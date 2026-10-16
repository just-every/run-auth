// Signed delivery to subscribers (the Standard Webhooks scheme: webhook-id,
// webhook-timestamp and an HMAC-SHA256 over "id.timestamp.body"), retried with
// backoff and Retry-After for three days. A 2xx proves receipt only.
import {one,all,run,utf8} from '../core.mjs';
import {unseal} from '../keys.mjs';
import {toBase64,fromBase64} from '../saml/der.mjs';

const BACKOFF=[30000,120000,600000,3600000,21600000,86400000],HORIZON=3*86400000,TIMEOUT=5000,CLAIM=60000;
export const secretsOf=async(ctx,sub)=>JSON.parse(await unseal(ctx,'events:'+sub.id,sub.sealed_secrets));

async function signatures(secrets,id,timestamp,body,now) {
 const live=secrets.filter(s=>!s.until||s.until>now),out=[];
 for(const {secret} of live) {
  const key=await crypto.subtle.importKey('raw',fromBase64(secret.slice('whsec_'.length)),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  out.push('v1,'+toBase64(new Uint8Array(await crypto.subtle.sign('HMAC',key,utf8.encode(`${id}.${timestamp}.${body}`)))));
 }
 return out.join(' ');
}

async function attempt(ctx,sub,event) {
 const body=JSON.stringify({id:event.id,type:event.type,version:event.version,seq:event.seq,occurredAt:new Date(event.occurred_at).toISOString(),subject:JSON.parse(event.subject),data:JSON.parse(event.data)});
 const timestamp=String(Math.floor(ctx.now()/1000));
 try {
  const response=await (ctx.connectorFetch||fetch)(sub.url,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(TIMEOUT),body,headers:{'content-type':'application/json','webhook-id':event.id,'webhook-timestamp':timestamp,'webhook-signature':await signatures(await secretsOf(ctx,sub),event.id,timestamp,body,ctx.now())}});
  await response.body?.cancel();
  return {status:response.status,retryAfter:Number(response.headers.get('retry-after'))};
 } catch {return {status:0};}
}

export async function deliverEvents(ctx,subscriptionId=null) {
 const now=ctx.now();
 const due=await all(ctx,`SELECT d.* FROM auth_event_deliveries d JOIN auth_event_subscriptions s ON s.id=d.subscription_id WHERE d.state='pending' AND d.next_attempt_at<=? AND (d.claimed_until IS NULL OR d.claimed_until<=?) AND s.disabled_at IS NULL${subscriptionId?' AND d.subscription_id=?':''} ORDER BY d.seq LIMIT 50`,now,now,...(subscriptionId?[subscriptionId]:[]));
 for(const row of due) {
  const d=await one(ctx,"UPDATE auth_event_deliveries SET claimed_until=? WHERE subscription_id=? AND seq=? AND state='pending' AND (claimed_until IS NULL OR claimed_until<=?) RETURNING *",ctx.now()+CLAIM,row.subscription_id,row.seq,ctx.now());
  if(!d)continue;
  const sub=await one(ctx,'SELECT * FROM auth_event_subscriptions WHERE id=?',d.subscription_id),event=await one(ctx,'SELECT * FROM auth_events WHERE seq=?',d.seq);
  const result=await attempt(ctx,sub,event),attempts=d.attempts+1,at=ctx.now();
  const permanent=result.status>=400&&result.status<500&&![408,429].includes(result.status);
  const delay=result.retryAfter>0?Math.min(result.retryAfter*1000,86400000):BACKOFF[Math.min(attempts-1,BACKOFF.length-1)];
  const state=result.status>=200&&result.status<300?'delivered':permanent?'failed':at+delay>event.occurred_at+HORIZON?'abandoned':'pending';
  await run(ctx,'UPDATE auth_event_deliveries SET attempts=?,state=?,last_status=?,delivered_at=?,next_attempt_at=?,claimed_until=NULL WHERE subscription_id=? AND seq=?',attempts,state,result.status,state==='delivered'?at:null,at+delay,d.subscription_id,d.seq);
 }
}
