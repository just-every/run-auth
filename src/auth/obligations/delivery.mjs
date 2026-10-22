import {one,all,run,random} from '../core.mjs';
import {policy,eligibleRecipients} from './policy.mjs';
import {businessDue,deliveryWindow} from './calendar.mjs';
import {syncObligations,sourceState} from './sources.mjs';
const LEASE=120000;
export async function maintainObligations(ctx) {
 await syncObligations(ctx);
 const p=await policy(ctx);if(!p.enabled)return;
 for(const ob of await all(ctx,"SELECT * FROM auth_obligations WHERE state='open' AND reminders_stopped_at IS NULL AND next_due_at<=? AND COALESCE(claimed_until,0)<=? ORDER BY next_due_at,id LIMIT 50",ctx.now(),ctx.now())) {
  const c=JSON.parse(ob.calendar);if(!deliveryWindow(ctx.now(),c))continue;
  const claim=random(),claimed=await run(ctx,"UPDATE auth_obligations SET claim_id=?,claimed_until=? WHERE id=? AND state='open' AND reminders_stopped_at IS NULL AND next_due_at<=? AND COALESCE(claimed_until,0)<=?",claim,ctx.now()+LEASE,ob.id,ctx.now(),ctx.now());
  if(!claimed.meta.changes)continue;
  const escalation=ctx.now()>=ob.deadline_at;
  const recipients=await eligibleRecipients(ctx,escalation?p.escalationRecipients:p.recipients);
  let lastError=recipients.length?null:'approved_recipient_unavailable';
  for(const recipient of recipients) {
   // Recheck the persisted consent, live recipient authority and source before
   // every outbound call. A sent message does not change the source's state.
   const current=await policy(ctx),ids=escalation?current.escalationRecipients:current.recipients;
   if(!current.enabled||!ids.includes(recipient.id)||!(await eligibleRecipients(ctx,[recipient.id])).length||(await sourceState(ctx,ob)).state!=='open'||!await one(ctx,"SELECT 1 FROM auth_obligations WHERE id=? AND state='open' AND claim_id=?",ob.id,claim))break;
   const event=random(),now=ctx.now();
   await run(ctx,'INSERT INTO auth_obligation_history(id,obligation_id,event,recipient_id,created_at) VALUES(?,?,?,?,?)',event,ob.id,escalation?'escalation_dispatching':'reminder_dispatching',recipient.id,now);
   try {
    if(!ctx.mail)throw new Error('mail_not_configured');
    await ctx.mail({to:recipient.email,subject:escalation?'Auth follow-up deadline reached':'Auth follow-up is due',text:`An Auth ${ob.kind} action is unresolved. An administrator must ${ob.next_action.replaceAll('_',' ')}. Review it in Auth: ${ctx.origin}${ctx.basePath??''}/app/activity\nReference: ${ob.id}\nA reminder does not confirm enrollment or removal of access.`,html:'<p>An Auth action remains unresolved. Sign in to Auth and review Activity. A reminder does not confirm enrollment or removal of access.</p>'});
    await run(ctx,'UPDATE auth_obligation_history SET event=? WHERE id=?',escalation?'escalation_delivered':'reminder_delivered',event);
   } catch {
    lastError='mail_delivery_failed_check_transport';
    await run(ctx,"UPDATE auth_obligation_history SET event='delivery_failed',error=? WHERE id=?",lastError,event);
   }
  }
  const stop=escalation&&ob.escalation_rule==='stop_at_deadline';
  await run(ctx,"UPDATE auth_obligations SET next_due_at=?,delivery_error=?,reminders_stopped_at=?,claim_id=NULL,claimed_until=NULL WHERE id=? AND claim_id=? AND state='open'",businessDue(ctx.now(),p.reminderBusinessDays,c),lastError,stop?ctx.now():null,ob.id,claim);
  if(stop)await run(ctx,"INSERT INTO auth_obligation_history(id,obligation_id,event,created_at) VALUES(?,?,'reminders_stopped_at_deadline',?)",random(),ob.id,ctx.now());
 }
 await syncObligations(ctx);
}
