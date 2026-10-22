import {caseProjection} from './records.mjs';
import {all,run,random} from '../core.mjs';
import {policy} from './policy.mjs';
import {businessDue,deliveryWindow} from './calendar.mjs';
import {syncObligations} from './sources.mjs';
import {dispatchOccurrence} from './dispatch.mjs';
import {dueTiming,claimTiming,finishTiming} from './timing.mjs';
const LEASE=120000;
export async function maintainObligations(ctx) {
 await syncObligations(ctx);
 const p=await policy(ctx);if(!p.enabled)return;
 for(const ob of await dueTiming(ctx)) {
  const claim=await claimTiming(ctx,ob);if(!claim)continue;
  const {lastError}=await dispatchOccurrence(ctx,ob,claim,{timing:true});
  await finishTiming(ctx,ob,claim,lastError);
 }
 for(const ob of await all(ctx,`SELECT *,${caseProjection} FROM auth_obligations WHERE state='open' AND reminders_stopped_at IS NULL AND next_due_at<=? AND COALESCE(claimed_until,0)<=? ORDER BY next_due_at,id LIMIT 50`,ctx.now(),ctx.now())) {
  const c=JSON.parse(ob.calendar);if(!deliveryWindow(ctx.now(),c))continue;
  const claim=random(),claimed=await run(ctx,"UPDATE auth_obligations SET claim_id=?,claimed_until=? WHERE id=? AND state='open' AND reminders_stopped_at IS NULL AND next_due_at<=? AND COALESCE(claimed_until,0)<=?",claim,ctx.now()+LEASE,ob.id,ctx.now(),ctx.now());
  if(!claimed.meta.changes)continue;
  const deadline=ctx.now()>=ob.deadline_at;
  const {lastError}=await dispatchOccurrence(ctx,ob,claim,{deadline});
  const stop=deadline&&ob.escalation_rule==='stop_at_deadline';
  const advanced=await run(ctx,"UPDATE auth_obligations SET next_due_at=?,delivery_error=?,reminders_stopped_at=?,claim_id=NULL,claimed_until=NULL WHERE id=? AND claim_id=? AND claimed_until>? AND state='open'",businessDue(ctx.now(),p.reminderBusinessDays,c),lastError,stop?ctx.now():null,ob.id,claim,ctx.now());
  if(stop&&advanced.meta.changes)await run(ctx,"INSERT INTO auth_obligation_history(id,obligation_id,event,created_at) VALUES(?,?,'reminders_stopped_at_deadline',?)",random(),ob.id,ctx.now());
 }
 await syncObligations(ctx);
}
