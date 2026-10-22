import {one,run,random,hash} from '../core.mjs';
import {policy,eligibleRecipients} from './policy.mjs';
import {sourceState} from './sources.mjs';
import {timingCurrent} from './timing.mjs';

export async function dispatchOccurrence(ctx,ob,claim,{deadline=false,timing=false}={}) {
 const p=await policy(ctx);
  let lastError=null,failedRecheck=false;
  const deliver=async(recipientId,escalation)=>{
   // Consent, source and the live claim are checked again before every call,
   // including fallback escalation. A failed recipient never receives mail.
   const current=await policy(ctx),ids=escalation?current.escalationRecipients:current.recipients;
   if(!current.enabled||(timing&&!await timingCurrent(ctx,ob,claim))||(await sourceState(ctx,ob)).state!=='open'||!await one(ctx,"SELECT 1 FROM auth_obligations WHERE id=? AND state='open' AND claim_id=? AND claimed_until>?",ob.id,claim,ctx.now()))return 'stopped';
   const [recipient]=ids.includes(recipientId)?await eligibleRecipients(ctx,[recipientId]):[];
   if(!recipient) {
    lastError=escalation?'approved_escalation_recipient_unavailable':'approved_recipient_unavailable';
    await run(ctx,'INSERT INTO auth_obligation_history(id,obligation_id,event,recipient_id,created_at,error) VALUES(?,?,?,(SELECT id FROM oa_operators WHERE id=?),?,?)',random(),ob.id,'recipient_recheck_failed',recipientId,ctx.now(),lastError);
    return 'unavailable';
   }
   // A durable attempt is keyed by the scheduled occurrence and recipient.
   // Commit it before transport: after a crash an unknown result stays unknown
   // and cannot be sent again merely because the worker claim expired.
   const event='dispatch:'+await hash(JSON.stringify([ob.id,timing?ob.timing_occurrence:ob.next_due_at,recipient.id])),now=ctx.now();
   const started=await run(ctx,"INSERT OR IGNORE INTO auth_obligation_history(id,obligation_id,event,recipient_id,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_obligations WHERE id=? AND state='open' AND claim_id=? AND claimed_until>?)",event,ob.id,escalation?'escalation_dispatching':'reminder_dispatching',recipient.id,now,ob.id,claim,now);
   if(!started.meta.changes) {
    const previous=await one(ctx,'SELECT event FROM auth_obligation_history WHERE id=?',event);
    if(!previous)return 'stopped';
    if(previous.event.endsWith('_dispatching'))lastError='dispatch_outcome_unknown_no_retry';
    return 'attempted';
   }
   try {
    if(!ctx.mail)throw new Error('mail_not_configured');
    await ctx.mail({to:recipient.email,subject:timing?'Auth downstream access unverified after 15 minutes':escalation?(deadline?'Auth follow-up deadline reached':'Auth follow-up recipient unavailable'):'Auth follow-up is due',text:`An Auth ${ob.kind} action is unresolved. An administrator must ${ob.next_action.replaceAll('_',' ')}. Review it in Auth: ${ctx.origin}${ctx.basePath??''}/app/activity\nReference: ${ob.id}\nA reminder does not confirm enrollment or removal of access.`,html:'<p>An Auth action remains unresolved. Sign in to Auth and review Activity. A reminder does not confirm enrollment or removal of access.</p>'});
    await run(ctx,'UPDATE auth_obligation_history SET event=? WHERE id=?',escalation?'escalation_accepted':'reminder_accepted',event);
   } catch {
    lastError='mail_delivery_failed_check_transport';
    await run(ctx,"UPDATE auth_obligation_history SET event='delivery_failed',error=? WHERE id=?",lastError,event);
   }
   return 'attempted';
  };
  if(!deadline&&!timing)for(const id of p.recipients) {
   const result=await deliver(id,false);
   if(result==='stopped')break;
   if(result==='unavailable'){failedRecheck=true;break;}
  }
  if(deadline||failedRecheck||timing) {
   const ids=(await policy(ctx)).escalationRecipients;
   if(!ids.length)lastError='approved_escalation_recipient_unavailable';
   for(const id of ids)if(await deliver(id,true)==='stopped')break;
  }

 return {lastError,failedRecheck};
}
