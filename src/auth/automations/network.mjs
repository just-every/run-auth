import {fail,utf8,b64} from '../core.mjs';
import {outboundUrl} from '../outbound.mjs';
import {checkedDestination,withinTimeout,readBounded} from '../hooks/network.mjs';

export const automationUrl=(ctx,value)=>outboundUrl(ctx,value,'invalid_automation_destination').href;
export async function requestJson(ctx,url,init) {
 return withinTimeout(10000,async signal=>{
  // Local loopback is a deliberate local-install door. Hosted installs always
  // resolve every address, including both address families, before sending.
  const destination=ctx.local&&new URL(url).protocol==='http:'?automationUrl(ctx,url):await checkedDestination(ctx,url,signal);
  const response=await (ctx.connectorFetch??fetch)(destination,{...init,signal,redirect:'manual'});
  if(response.status>=300&&response.status<400||response.redirected||response.url&&response.url!==destination){await response.body?.cancel();fail('automation_redirect_refused',502);}
  if(!response.ok){await response.body?.cancel();fail('automation_remote_refused',502);}
  if(!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();fail('automation_response_invalid',502);}
  let value;try{value=JSON.parse(await readBounded(response,signal,16384));}catch{fail('automation_response_invalid',502);}
  return {value,status:response.status};
 });
}
export async function signedHeaders(secret,runId,ordinal,url,body,now) {
 const timestamp=String(Math.floor(now/1000)),id=runId+':'+ordinal;
 const key=await crypto.subtle.importKey('raw',utf8.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const signature=b64(await crypto.subtle.sign('HMAC',key,utf8.encode(`${id}.${timestamp}.POST.${url}.${body}`)));
 return {'content-type':'application/json','idempotency-key':id,'auth-automation-id':id,'auth-automation-timestamp':timestamp,'auth-automation-signature':signature};
}
