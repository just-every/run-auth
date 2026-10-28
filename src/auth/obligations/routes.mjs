import {isDirectoryObligation,directoryBinding} from '../directory-sources/followup.mjs';
import {decisionKind} from './decision-sources.mjs';
import {releaseSource} from '../erasure/pair-erasure.mjs';
import {caseProjection} from './records.mjs';
import {followupAccess} from './access.mjs';
import {sendEarly} from './early.mjs';
import {holdsObligation,holdsCase} from './recipients.mjs';
import {requireRolePermission} from '../roles/policy.mjs';
import {obligationPage} from './pagination.mjs';
import {one,all,random,requireSession,auditDetail,json,fail} from '../core.mjs';
import {requireAuthority} from '../local-email.mjs';
import {policy,validatePolicy} from './policy.mjs';
import {businessDue} from './calendar.mjs';
import {syncObligations} from './sources.mjs';
export const FOLLOWUP_READ='/api/auth/followup';
export const isFollowupAction=path=>['/followup/settings','/followup/schedule','/followup/send'].includes(path);
export async function followupRead(ctx,request) {
 const s=await requireSession(ctx,request);
 await syncObligations(ctx);
 const access=await followupAccess(ctx,s),filter=access.filter;
 const [obligations,history]=await Promise.all([
  obligationPage(ctx,request,{table:'auth_obligations',columns:`id,kind,source_id,${caseProjection},owner_id,person_id,app_id,next_action,calendar,deadline_at,next_due_at,state,stop_rule,escalation_rule,last_error,delivery_error,created_at,stopped_at,reminders_stopped_at`,prefix:'obligation',defaultLimit:200,filter}),
  obligationPage(ctx,request,{table:'auth_obligation_history',prefix:'history',defaultLimit:100,filter:{clause:`obligation_id IN (SELECT id FROM auth_obligations WHERE ${filter.clause})`,args:filter.args}}),
 ]);
 for(const ob of obligations.items){if(isDirectoryObligation(ob)){const binding=await directoryBinding(ctx,ob);ob.kind='directory_source';ob.sourceLink=binding?(ctx.basePath??'')+'/app/move-in#directory-source-'+encodeURIComponent(binding.source_id):null;ob.canSend=false;continue;}ob.canSend=ob.state==='open'&&!ob.reminders_stopped_at&&await holdsObligation(ctx,s,ob);if(releaseSource(ob))ob.kind='identity_release';const kind=decisionKind(ob);if(kind)ob.kind=kind;if(await one(ctx,'SELECT obligation_id FROM auth_hr_feed_obligations WHERE obligation_id=?',ob.id)){ob.kind='hr_file_feed';ob.canSend=ob.canSend&&(await policy(ctx)).recipients.includes('source_owner');}}
 const live=await one(ctx,`SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1 WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?`,s.id,s.person_id,s.amr,ctx.now(),access.state.epoch);
 if(!live)fail('role_authority_changed',409);
 const saved=await policy(ctx),visiblePolicy=access.canManage?saved:{enabled:saved.enabled,calendar:saved.calendar,reminderBusinessDays:saved.reminderBusinessDays,deadlineBusinessDays:saved.deadlineBusinessDays,escalation:saved.escalation,recipients:[],escalationRecipients:[]};
 return json({canManage:access.canManage,eligibleAdmins:access.canManage?await all(ctx,"SELECT id,email,display_name AS name FROM oa_operators WHERE status='active' AND role IN ('owner','admin')"):[],policy:visiblePolicy,obligations:obligations.items,obligationsPage:obligations.page,history:history.items,historyPage:history.page,limitations:['Calendar changes apply to new obligations; existing records keep their calendar until explicitly rescheduled.','Email reminders only; Slack, Teams, Oncall and chat decisions are not implemented.','Requests and review items use their current decider. Stale HR feeds send only after explicit HR source-owner reminder consent; Generic SCIM pull freshness is visible only and never inherits reminder consent.','Interrupted dispatch stays recorded as dispatching and is not retried for the same recipient and scheduled occurrence; transport acknowledgment is not proof of access state.']});
}
export async function followupAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request);
 if(path==='/followup/send')return sendEarly(ctx,s,data);
 const guard=await requireRolePermission(ctx,s,'followup.manage',{write:true});
 if(path==='/followup/settings') {
  if(data.confirm!==true)fail('followup_explicit_consent_required');
  const p=await validatePolicy(ctx,data),changed=await ctx.db.prepare(`INSERT INTO auth_followup_settings(id,policy,updated_by,updated_at) SELECT 1,?,?,? WHERE ${guard.clause} ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,updated_by=excluded.updated_by,updated_at=excluded.updated_at`).bind(JSON.stringify(p),s.person_id,ctx.now(),...guard.args).run();
  if(!changed.meta.changes)await requireAuthority(ctx,s,guard);
  await auditDetail(ctx,s.person_id,'followup_settings_changed',null,{...p,consent:true});
  await syncObligations(ctx);
  return json({ok:true,policy:p});
 }
 await syncObligations(ctx);
 const ob=await one(ctx,`SELECT *,${caseProjection} FROM auth_obligations WHERE id=? AND state='open'`,String(data.id??''));if(!ob)fail('followup_unavailable',404);
 if(isDirectoryObligation(ob))fail('directory_source_schedule_owned_by_source',403);
 if(releaseSource(ob)&&s.role!=='owner')fail('owner_required',403);
 const owner=await one(ctx,"SELECT id,role FROM oa_operators WHERE id=? AND status='active'",String(data.ownerId??''));if(!owner||!['owner','admin'].includes(owner.role)&&!(ob.case_id&&await holdsCase(ctx,owner.id,ob.case_id)))fail('followup_owner_requires_admin');
 if(releaseSource(ob)&&owner.role!=='owner')fail('owner_required',403);
 for(const key of ['dueBusinessDays','deadlineBusinessDays'])if(!Number.isInteger(data[key])||data[key]<1||data[key]>90)fail('invalid_followup_schedule');
 if(data.deadlineBusinessDays<data.dueBusinessDays)fail('invalid_followup_schedule');
 const p=await policy(ctx),next=businessDue(ctx.now(),data.dueBusinessDays,p.calendar),deadline=businessDue(ctx.now(),data.deadlineBusinessDays,p.calendar),marker=random();
 const [changed]=await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_obligations SET owner_id=?,calendar=?,next_due_at=?,deadline_at=?,escalation_rule=?,reminders_stopped_at=NULL,claim_id=NULL,claimed_until=NULL WHERE id=? AND state='open' AND COALESCE(claimed_until,0)<=? AND ${guard.clause}`).bind(owner.id,JSON.stringify(p.calendar),next,deadline,p.escalation,ob.id,ctx.now(),...guard.args),
  ctx.db.prepare('INSERT INTO auth_obligation_history(id,obligation_id,event,actor_id,created_at) SELECT ?,?,?,?,? WHERE changes()>0').bind(marker,ob.id,'schedule_changed',s.person_id,ctx.now()),
 ]);
 if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('followup_changed',409);}
 await auditDetail(ctx,s.person_id,'followup_schedule_changed',ob.id,{ownerId:owner.id,calendar:p.calendar,nextDueAt:next,deadlineAt:deadline});
 return json({ok:true});
}
