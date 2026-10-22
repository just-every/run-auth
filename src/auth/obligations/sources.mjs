import {one,all,random} from '../core.mjs';
import {policy} from './policy.mjs';
import {businessDue} from './calendar.mjs';
// Source state is authoritative. Delivery or an administrator's follow-up action
// cannot manufacture successful enrollment or verified downstream revocation.
export async function sourceState(ctx,ob) {
 if(ob.kind==='enrollment') {
  const p=await one(ctx,'SELECT status FROM oa_operators WHERE id=?',ob.source_id);
  if(!p||p.status==='inactive')return {state:'cancelled'};
  if(p.status==='invited') {
   const invitation=await one(ctx,'SELECT expires_at,cancelled_at FROM auth_org_invitations WHERE person_id=?',ob.source_id);
   if(invitation?.cancelled_at)return {state:'cancelled'};
   if(invitation&&invitation.expires_at<=ctx.now())return {state:'expired'};
  }
  if(await one(ctx,'SELECT 1 FROM auth_passkeys WHERE person_id=? LIMIT 1',ob.source_id))return {state:'completed'};
  return {state:'open',action:p.status==='invited'?'accept_invitation':'enroll_passkey'};
 }
 if(ob.kind==='recovery') {
  const r=await one(ctx,'SELECT r.*,p.status FROM auth_recoveries r LEFT JOIN oa_operators p ON p.id=r.person_id WHERE r.id=?',ob.source_id);
  if(!r||r.cancelled_at)return {state:'cancelled'};
  if(r.completed_at)return {state:'completed'};
  if(r.status!=='active')return {state:'expired'};
  return {state:'open',action:r.approved_by||r.ready_at<=ctx.now()?'complete_recovery':'wait_or_request_distinct_admin_approval'};
 }
 const p=await one(ctx,'SELECT state,last_error FROM auth_provisioning WHERE id=?',ob.source_id);
 if(!p||p.state==='superseded')return {state:'cancelled'};
 if(p.state==='verified')return {state:'completed'};
 // Only fixed instruction codes leave the engine; vendor error bodies and
 // credentials never enter follow-up history or messages.
 return {state:'open',action:['failed','blocked'].includes(p.state)?'repair_connector_then_retry':'await_remote_verification',error:p.last_error?'remote_unverified_check_connector':null};
}
export async function syncObligations(ctx) {
 const now=ctx.now(),p=await policy(ctx),owner=await one(ctx,"SELECT id FROM oa_operators WHERE status='active' AND role='owner' ORDER BY created_at,id LIMIT 1");
 const candidates=await all(ctx,`SELECT 'enrollment' AS kind,id AS source_id,id AS person_id,NULL AS app_id,created_at FROM oa_operators WHERE status='invited'
  UNION ALL SELECT 'recovery',id,person_id,NULL,created_at FROM auth_recoveries WHERE cancelled_at IS NULL AND completed_at IS NULL
  UNION ALL SELECT 'provisioning',id,CASE WHEN subject_type='person' THEN subject_id ELSE NULL END,app_id,event_at FROM auth_provisioning WHERE state IN ('pending','failed','blocked')`);
 for(const c of candidates) {
  const existing=await one(ctx,'SELECT id,state FROM auth_obligations WHERE kind=? AND source_id=?',c.kind,c.source_id);
  if(existing) {
   // Reissuing an expired invitation restores only the follow-up record, using
   // the invitation's own renewed authority. The earlier history stays intact.
   if(c.kind==='enrollment'&&existing.state==='expired'&&(await sourceState(ctx,c)).state==='open')await ctx.db.batch([
    ctx.db.prepare("UPDATE auth_obligations SET state='open',stopped_at=NULL,reminders_stopped_at=NULL,next_due_at=?,deadline_at=?,calendar=? WHERE id=? AND state='expired'").bind(businessDue(now,p.reminderBusinessDays,p.calendar),businessDue(now,p.deadlineBusinessDays,p.calendar),JSON.stringify(p.calendar),existing.id),
    ctx.db.prepare("INSERT INTO auth_obligation_history(id,obligation_id,event,created_at) SELECT ?,?,'invitation_reissued',? WHERE changes()>0").bind(random(),existing.id,now),
   ]);
   continue;
  }
  // Deleted people may leave a provisioning residual. Keep the source id but
  // never create a dangling personal reference.
  const person=c.person_id&&await one(ctx,'SELECT id FROM oa_operators WHERE id=?',c.person_id),app=c.app_id&&await one(ctx,'SELECT id FROM auth_apps WHERE id=?',c.app_id);
  const id=random(),source=await sourceState(ctx,c),created=c.created_at;
  const inserted=await ctx.db.prepare(`INSERT OR IGNORE INTO auth_obligations(id,kind,source_id,owner_id,person_id,app_id,next_action,calendar,deadline_at,next_due_at,state,stop_rule,escalation_rule,last_error,created_at)
   VALUES(?,?,?,?,?,?,?,?,?,?,'open','source_satisfied_cancelled_or_authority_expired',?,?,?)`).bind(id,c.kind,c.source_id,c.kind==='recovery'?person?.id??owner?.id??null:owner?.id??null,person?.id??null,app?.id??null,source.action??'review_source',JSON.stringify(p.calendar),businessDue(created,p.deadlineBusinessDays,p.calendar),businessDue(created,p.reminderBusinessDays,p.calendar),p.escalation,source.error??null,created).run();
  if(inserted.meta.changes)await ctx.db.prepare("INSERT INTO auth_obligation_history(id,obligation_id,event,created_at) VALUES(?,?,'opened',?)").bind(random(),id,now).run();
 }
 for(const ob of await all(ctx,"SELECT * FROM auth_obligations WHERE state='open'")) {
  const source=await sourceState(ctx,ob);
  if(source.state==='open') {
   await ctx.db.prepare("UPDATE auth_obligations SET next_action=?,last_error=? WHERE id=? AND state='open'").bind(source.action,source.error??null,ob.id).run();continue;
  }
  await ctx.db.batch([
   ctx.db.prepare("UPDATE auth_obligations SET state=?,stopped_at=?,claim_id=NULL,claimed_until=NULL WHERE id=? AND state='open'").bind(source.state,now,ob.id),
   ctx.db.prepare('INSERT INTO auth_obligation_history(id,obligation_id,event,created_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_obligations WHERE id=? AND stopped_at=? AND state=?) AND NOT EXISTS(SELECT 1 FROM auth_obligation_history WHERE obligation_id=? AND event=?)').bind(random(),ob.id,source.state,now,ob.id,now,source.state,ob.id,source.state),
  ]);
 }
}
