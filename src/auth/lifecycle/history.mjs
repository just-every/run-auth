import {all,one,run,json,fail,requireSession} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {requireHardware,assertPermission,permitted} from '../roles/policy.mjs';

// Only correlate the exact work recorded at approval. Newer work must never
// complete an earlier episode. Missing queues or accepted logout are unknown.
export async function reconcileLeavers(ctx) {
 const rows=await all(ctx,"SELECT * FROM auth_lifecycle_steps WHERE kind IN ('scim','scim_group','logout','oidc_logout') AND state!='verified'");
 for(const step of rows) {
  let state='unknown',outcome='work_missing',dispatched=null,verified=null;
  if(step.kind==='logout'||step.kind==='oidc_logout') {
   const work=await one(ctx,step.kind==='logout'?'SELECT * FROM auth_logout_deliveries WHERE id=?':'SELECT * FROM auth_oidc_logouts WHERE id=?',step.work_id);
   if(work){dispatched=work.attempts?work.created_at:null;state=work.outcome==='delivered'?'unknown':work.outcome?'failed':'unstarted';outcome=work.outcome==='delivered'?'accepted_remote_unverified':work.outcome??'not_dispatched';}
  } else {
   const work=await one(ctx,'SELECT * FROM auth_provisioning WHERE id=?',step.work_id);
   if(work) {
    dispatched=work.dispatched_at;
    const valid=work.state==='verified'&&work.verified_at&&((step.kind==='scim'&&['deactivate','delete'].includes(work.operation))||(step.kind==='scim_group'&&['update','delete','create'].includes(work.operation)));
    state=valid?'verified':work.state==='superseded'?'unknown':work.last_error||['failed','blocked'].includes(work.state)?'failed':dispatched?'unknown':'unstarted';
    outcome=valid?'remote_readback_verified':work.state==='verified'?'remote_account_unobserved':work.last_error??work.state;
    verified=valid?work.verified_at:null;
   }
  }
  await run(ctx,"UPDATE auth_lifecycle_steps SET state=?,outcome=?,dispatched_at=COALESCE(?,dispatched_at),verified_at=? WHERE id=? AND state!='verified'",state,outcome,dispatched,verified,step.id);
 }
}

export async function leaverHistory(ctx,s,personId=null) {
 requireHardware(s);
 const state=await roleState(ctx,s);
 assertPermission(state,'people.view',personId?{personId,write:false}:{write:false});
 await reconcileLeavers(ctx);
 const rows=await all(ctx,`SELECT * FROM auth_lifecycle_plans${personId?' WHERE person_id=?':''} ORDER BY created_at DESC,rowid DESC LIMIT 100`,...(personId?[personId]:[])),plans=[];
 const canName=id=>state.dir.people.get(id)&&permitted(state,'people.view',{personId:id,write:false});
 for(const row of rows) {
  if(!canName(row.person_id))continue;
  const entry=JSON.parse(row.plan),steps=await all(ctx,'SELECT * FROM auth_lifecycle_steps WHERE plan_id=? ORDER BY rowid',row.id);
  const visible=step=>!step.app_id||state.legacy||permitted(state,'apps.view',{appId:step.app_id});
  const shown=steps.filter(visible),hidden=steps.length-shown.length,missing=Math.max(0,entry.lifecycle.steps.length-steps.length);
  const name=id=>canName(id)?state.dir.people.get(id).name||state.dir.people.get(id).email:'Restricted administrator';
  plans.push({id:row.id,personId:row.person_id,person:name(row.person_id),actor:name(row.actor_id),custodian:name(row.custodian_id),createdAt:row.created_at,denialAt:row.denial_at,digest:row.preview_digest,
   preview:{source:entry.source,state:entry.state,changes:entry.changes,groups:{added:entry.groups.added.filter(g=>state.legacy||permitted(state,'groups.view',{groupId:g.id})),removed:entry.groups.removed.filter(g=>state.legacy||permitted(state,'groups.view',{groupId:g.id}))},credentialActions:entry.lifecycle.credentialActions},
   state:hidden||missing||steps.some(s=>s.state!=='verified')?'unresolved':'verified',fullyOffboarded:false,hiddenSteps:hidden,missingSteps:missing,
   steps:shown.map(step=>({id:step.id,app:step.app_label,kind:step.kind,operation:step.operation,workId:step.work_id,state:step.state,outcome:step.outcome,deadlineAt:step.deadline_at,escalateAt:step.escalate_at,dispatchedAt:step.dispatched_at,verifiedAt:step.verified_at}))});
 }
 // Scope and proof are checked again after reading the complete projection.
 const current=await one(ctx,`SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1 WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?`,s.id,s.person_id,s.amr,ctx.now(),state.epoch);
 if(!current)fail('role_authority_changed',409);
 return {plans};
}
export async function leaverRead(ctx,request) {
 const s=await requireSession(ctx,request),personId=new URL(request.url).searchParams.get('personId');
 return json(await leaverHistory(ctx,s,personId));
}
