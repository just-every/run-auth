import {all,one,random,fail,AuthError,auditDetail} from '../core.mjs';
import {unseal} from '../keys.mjs';
import {POINTS,minimalPayload,validateOutput} from './policy.mjs';
import {checkedDestination,readBounded,withinTimeout} from './network.mjs';
import {signature} from './signing.mjs';

async function call(ctx,hook,id,point,payload,signal) {
 const url=await checkedDestination(ctx,hook.url,signal);
 const body=JSON.stringify({id,version:1,point,occurredAt:new Date(ctx.now()).toISOString(),data:minimalPayload(point,payload)});
 const timestamp=String(Math.floor(ctx.now()/1000)),secret=await unseal(ctx,'hooks:'+hook.id,hook.sealed_secret);
 const signed=await signature(secret,id,timestamp,body);
 let response;
 try {response=await (ctx.connectorFetch||fetch)(url,{method:'POST',redirect:'manual',signal,body,headers:{'content-type':'application/json',accept:'application/json','webhook-id':id,'webhook-timestamp':timestamp,'webhook-signature':signed}});}
 catch {fail('hook_unavailable',503);}
 if(response.status<200||response.status>=300) {
  await response.body?.cancel();
  if(response.status===403)fail('hook_refused',403);
  fail(response.status>=500||[408,429].includes(response.status)?'hook_unavailable':'hook_invalid_response',response.status>=500||[408,429].includes(response.status)?503:403);
 }
 if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')||'')){await response.body?.cancel();fail('hook_invalid_response',403);}
 let value;
 try {value=JSON.parse(await readBounded(response,signal));}
 catch(error){if(signal.aborted)throw error;fail('hook_invalid_response',403);}
 return validateOutput(point,value,JSON.parse(hook.allowed_fields));
}

export async function invokeHooks(ctx,point,payload={}) {
 if(!POINTS.includes(point))fail('invalid_hook_point');
 const appId=typeof payload.appId==='string'?payload.appId:null,clientId=typeof payload.clientId==='string'?payload.clientId:null;
 const hooks=await all(ctx,`SELECT * FROM auth_hooks WHERE point=? AND disabled_at IS NULL${['token','saml'].includes(point)?' AND ((app_id IS NOT NULL AND app_id=?) OR (client_id IS NOT NULL AND client_id=?))':''} ORDER BY created_at,id`,point,...(['token','saml'].includes(point)?[appId,clientId]:[]));
 const out=point==='token'?{claims:{}}:point==='saml'?{attributes:{}}:{allow:true};
 for(const hook of hooks) {
  // A hook disabled during an earlier call must not run from a stale list.
  if(!await one(ctx,'SELECT id FROM auth_hooks WHERE id=? AND disabled_at IS NULL',hook.id))continue;
  const id='hook_'+random(),start=Date.now();let result,error,outcome='allowed';
  try {result=await withinTimeout(hook.timeout_ms,signal=>call(ctx,hook,id,point,{...payload,...(out.profile??{})},signal));if(!await one(ctx,'SELECT id FROM auth_hooks WHERE id=? AND disabled_at IS NULL',hook.id))fail('hook_changed',409);}
  catch(caught) {
   error=caught.hookTimeout?new AuthError('hook_timeout',503):caught instanceof AuthError?caught:new AuthError('hook_invalid_response',403);
   outcome=error.message;
   if(!hook.fail_closed&&['hook_timeout','hook_unavailable','hook_dns_unavailable'].includes(outcome))outcome='ignored_'+outcome;
  }
  await auditDetail(ctx,payload.personId??null,'inline_hook_called',hook.id,{callId:id,point,latencyMs:Math.max(0,Date.now()-start),latency:`${Math.max(0,Date.now()-start)} ms`,outcome,failClosed:Boolean(hook.fail_closed)});
  if(error){if(outcome.startsWith('ignored_'))continue;throw error;}
  if(point==='token')Object.assign(out.claims,result.claims);
  else if(point==='saml')Object.assign(out.attributes,result.attributes);
  else if(result.profile)out.profile={...(out.profile??{}),...result.profile};
 }
 return out;
}
