import {hash,random,one,run,limitState,AuthError} from '../core.mjs';

export const recipientHash=(ctx,address)=>hash(JSON.stringify([ctx.secret,String(address)]));
const unavailable=()=>new AuthError('mail_delivery_unavailable',503);

// Only identifiers and outcomes are durable. Message bodies, usable links,
// provider responses and addresses never enter the delivery journal.
export async function sendDelivery(ctx,message,transport) {
 const id=random(),recipient=await recipientHash(ctx,message.to),provider=ctx.mailProvider??'configured';
 await run(ctx,"INSERT INTO auth_mail_deliveries(id,person_id,recipient_hash,provider,state,created_at,updated_at) VALUES(?,(SELECT id FROM oa_operators WHERE email=?),?,?,'queued',?,?)",id,String(message.to).trim().toLowerCase(),recipient,provider,ctx.now(),ctx.now());
 const finish=async(state,error=null)=>run(ctx,"UPDATE auth_mail_deliveries SET state=?,error=?,updated_at=? WHERE id=? AND state IN ('queued','dispatching')",state,error,ctx.now(),id);
 if(await one(ctx,'SELECT 1 FROM auth_mail_suppressions WHERE recipient_hash=?',recipient)) {
  await finish('suppressed','recipient_suppressed');throw unavailable();
 }
 if(ctx.mailProvider&&provider!=='development') {
  const recipientLimit=await limitState(ctx,'delivery-recipient:'+recipient,20,60000),installationLimit=await limitState(ctx,'delivery-installation',200,60000);
  if(!recipientLimit.allowed||!installationLimit.allowed) {await finish('rate_limited','local_rate_limit');throw unavailable();}
 }
 const claimed=await run(ctx,"UPDATE auth_mail_deliveries SET state='dispatching',updated_at=? WHERE id=? AND state='queued' AND NOT EXISTS(SELECT 1 FROM auth_mail_suppressions WHERE recipient_hash=?)",ctx.now(),id,recipient);
 if(!claimed.meta.changes){await finish('suppressed','recipient_suppressed');throw unavailable();}
 try {
  const result=await transport({...message,deliveryId:id,...(provider==='sendgrid'?{customArgs:{rer_product:'auth',rer_seed:'auth',...(ctx.mailEventInstallationId?{rer_test_installation:ctx.mailEventInstallationId}:{})}}:{})});
  // A void result is the pre-existing custom transport's acceptance contract.
  const state=provider==='development'||result?.provider==='development'?'local_outbox':result?.status??'accepted';
  if(!['accepted','local_outbox','rejected','rate_limited','uncertain'].includes(state)) {
   await finish('uncertain','transport_outcome_unknown');throw unavailable();
  }
  await finish(state,['accepted','local_outbox'].includes(state)?null:'provider_'+state);
  if(!['accepted','local_outbox'].includes(state))throw unavailable();
  return result;
 }catch {
  // A thrown transport may have reached the provider. Never retry it here.
  await finish('uncertain','transport_outcome_unknown');throw unavailable();
 }
}
