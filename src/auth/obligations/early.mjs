import {one,run,random,fail,json} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {roleState} from '../roles/state.mjs';
import {roleGuard} from '../roles/policy.mjs';
import {holdsObligation} from './recipients.mjs';
import {sourceState,syncObligations} from './sources.mjs';
import {policy} from './policy.mjs';
import {dispatchOccurrence} from './dispatch.mjs';

export async function sendEarly(ctx,s,data) {
 requireLocalEmail(ctx,s);
 await syncObligations(ctx);
 const ob=await one(ctx,"SELECT * FROM auth_obligations WHERE id=? AND state='open' AND reminders_stopped_at IS NULL",String(data.id??''));
 if(!ob)fail('followup_unavailable',404);
 if(!await holdsObligation(ctx,s,ob))fail('followup_holder_required',403);
 if(!(await policy(ctx)).enabled)fail('followup_policy_disabled',409);
 // This sends the already scheduled occurrence. It does not create another
 // occurrence, change the allowed recipients or advance the source's state.
 const state=await roleState(ctx,s),guard=roleGuard(ctx,s,state),claim=random();
 const changed=await run(ctx,`UPDATE auth_obligations SET claim_id=?,claimed_until=? WHERE id=? AND state='open' AND reminders_stopped_at IS NULL AND next_due_at=? AND owner_id IS ? AND COALESCE(claimed_until,0)<=? AND ${guard.clause}`,claim,ctx.now()+120000,ob.id,ob.next_due_at,ob.owner_id,ctx.now(),...guard.args);
 if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('followup_changed',409);}
 const current=async()=>{
  const live=await one(ctx,`SELECT 1 WHERE ${authority(ctx,s).clause}`,...authority(ctx,s).args);
  const latest=await one(ctx,'SELECT * FROM auth_obligations WHERE id=?',ob.id);
  return Boolean(live&&latest&&latest.next_due_at===ob.next_due_at&&await holdsObligation(ctx,s,latest));
 };
 try {
  if((await sourceState(ctx,ob)).state!=='open')fail('followup_unavailable',409);
  const {lastError}=await dispatchOccurrence(ctx,ob,claim,{deadline:ctx.now()>=ob.deadline_at,earlyCurrent:current});
  await run(ctx,"UPDATE auth_obligations SET delivery_error=? WHERE id=? AND claim_id=?",lastError,ob.id,claim);
  await run(ctx,"INSERT INTO auth_obligation_history(id,obligation_id,event,actor_id,created_at) SELECT ?,?,'early_send_requested',?,? WHERE EXISTS(SELECT 1 FROM auth_obligations WHERE id=? AND claim_id=?)",random(),ob.id,s.person_id,ctx.now(),ob.id,claim);
 }finally{await run(ctx,'UPDATE auth_obligations SET claim_id=NULL,claimed_until=NULL WHERE id=? AND claim_id=?',ob.id,claim);}
 return json({ok:true});
}
