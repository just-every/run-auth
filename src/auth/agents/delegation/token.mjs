import {decodeJwt} from 'jose';
import {AuthError,fail,json,run,random,auditDetail,limit} from '../../core.mjs';
import {ensureSigningKey,signToken} from '../../keys.mjs';
import {CLIENT_PREFIX,SCOPE,issuer,organization,target,id} from './common.mjs';
import {agentRow,taskTable,taskRow,taskGuard} from './state.mjs';
import {privateAssertion,verifyPrivateAssertion} from './assertions.mjs';
import {requireDpop,verifyDpop} from './dpop.mjs';
import {authorizationDetails,sameDetails} from './effect.mjs';
const TYPE='urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
function named(request,form) {
 const names=[form.get('client_id')],assertion=form.get('client_assertion');
 if(assertion&&assertion.length<=16384){try {const p=decodeJwt(assertion);names.push(p.iss,p.sub);}catch{}}
 const basic=/^Basic ([A-Za-z0-9+/=]+)$/i.exec(request.headers.get('authorization')??'');
 if(basic){try{const value=atob(basic[1]),colon=value.indexOf(':',CLIENT_PREFIX.length);names.push(decodeURIComponent(value.slice(0,colon<0?value.length:colon)));}catch{}}
 return names.find(v=>typeof v==='string'&&v.startsWith(CLIENT_PREFIX))??null;
}
export async function delegationToken(ctx,request) {
 const raw=await request.clone().text(),form=new URLSearchParams(raw),clientId=named(request,form);
 if(!clientId)return null;
 delete ctx.delegationActor;
 let agent=null,task=null;
 const claimedGrantId=form.get('grant_id'),attemptedGrantId=String(claimedGrantId??'').slice(0,200);
 const attribution=()=>({actorId:'delegated-agent:'+agent.id,agentId:agent.id,accountablePersonId:task.accountable_id,approvedBy:task.approved_by,grantId:task.id});
 try {
  agent=await agentRow(ctx,clientId);
  // Bound both proofs before refusal attribution, including invalid scope/resource.
  // The other delegated doors charge these same buckets before their proofs.
  if(agent) {
   if(!await limit(ctx,'delegated-assertion:'+agent.id,120,60000))fail('rate_limited',429);
   if(!await limit(ctx,'delegated-dpop:'+agent.id,120,60000))fail('rate_limited',429);
  }
  // Resolve only bounded, unambiguous claims. They are attempted identifiers,
  // never an actor/subject, until both registered-key proofs authenticate them.
  if(raw.length<=32768&&form.getAll('client_id').length===1&&form.getAll('grant_id').length===1&&form.get('client_id')===clientId) {
   if(agent&&typeof claimedGrantId==='string'&&/^[-A-Za-z0-9_:]{1,200}$/.test(claimedGrantId))task=await taskRow(ctx,claimedGrantId);
   if(task?.agent_id!==agent?.id)task=null;
   if(agent&&task&&!request.headers.has('authorization')&&form.getAll('client_assertion').length===1) {
    try {
     await verifyPrivateAssertion(ctx,agent,form.get('client_assertion'),issuer(ctx)+'/oidc/token',{delegation_use:'token',grant_id:task.id,effect_digest:task.effect_digest});
     await verifyDpop(ctx,request,agent,{htu:issuer(ctx)+'/oidc/token'});
     ctx.delegationActor=attribution();
    }catch(error){if(!(error instanceof AuthError))throw error;}
   }
  }
  // Keep the public error precedence. Authentication for refusal auditing above
  // is read-only: it consumes no assertion, nonce or replay identifier.
  if(raw.length>32768||!(request.headers.get('content-type')??'').startsWith('application/x-www-form-urlencoded')||[...form.keys()].some(k=>form.getAll(k).length!==1||!['client_id','grant_type','client_assertion_type','client_assertion','grant_id','scope','resource','authorization_details'].includes(k)))fail('invalid_request');
  if(request.headers.has('authorization')||form.has('client_secret')||form.get('client_assertion_type')!==TYPE||form.get('client_id')!==clientId)fail('invalid_client',401);
  if(form.get('grant_type')!=='client_credentials')fail('unsupported_grant_type');
  const selected=agent?await taskRow(ctx,claimedGrantId):null;
  const selectedEffect=selected&&agent&&selected.agent_id===agent.id?JSON.parse(selected.effect):null;
  const scope=selectedEffect?.scopes.join(' ')??SCOPE,audience=selectedEffect?.audience??target(ctx);
  if(form.get('scope')!==scope)fail('invalid_scope');
  if(form.get('resource')!==audience)fail('invalid_target');
  agent??=await agentRow(ctx,clientId);if(!agent)fail('invalid_client',401);
  task??=await taskRow(ctx,id(form.get('grant_id'),'invalid_grant'));
  if(!task||task.agent_id!==agent.id)fail('invalid_grant');
  const details=authorizationDetails(task);
  if(form.has('authorization_details')) {
   let requested;try{requested=JSON.parse(form.get('authorization_details'));}catch{fail('invalid_authorization_details');}
   if(!sameDetails(requested,details))fail('invalid_authorization_details');
  }
  // A nonce challenge must not consume the independent client assertion.
  const proof=await requireDpop(ctx,request,agent,{htu:issuer(ctx)+'/oidc/token',task:ctx.delegationActor?.grantId===task.id?task:null,tokenEndpoint:true});
  await privateAssertion(ctx,agent,form.get('client_assertion'),issuer(ctx)+'/oidc/token',{delegation_use:'token',grant_id:task.id,effect_digest:task.effect_digest},await taskGuard(ctx,agent,task));
  ctx.delegationActor=attribution();
  const now=Math.floor(ctx.now()/1000),expiresAt=Math.min(now+300,Math.floor(task.expires_at/1000),Math.floor(agent.expires_at/1000),Math.floor(agent.service.expires_at/1000));
  if(expiresAt<=now)fail('invalid_grant');
  const effect=JSON.parse(task.effect);
  await ensureSigningKey(ctx);
  const token=await signToken(ctx,{sub:task.accountable_id,act:{iss:issuer(ctx),sub:'agent:'+agent.id},cnf:{jkt:proof.jkt},authorization_details:details,aud:audience,client_id:agent.client_id,delegation_profile:task.resource_id?'auth-external-task-v1':'auth-assignment-task-v1',agent_id:agent.id,agent_revision:agent.revision,delegated_admin_service:agent.service.id,service_revision:agent.service.revision,grant_id:task.id,grant_revision:task.revision,effect_digest:task.effect_digest,organization_id:organization(ctx),accountable_person:task.accountable_id,person_version:task.accountable_version,scope,api_id:effect.apiId,resource:effect.resource,jti:random()},{typ:'at+jwt',expiresAt,published:true});
  const guard=await taskGuard(ctx,agent,task,['approved'],{expiresAt:expiresAt*1000});
  const stored=await run(ctx,`UPDATE ${taskTable(task)} SET last_issued_at=? WHERE id=? AND ${guard.clause}`,ctx.now(),task.id,...guard.args);
  if(!stored.meta.changes)fail('invalid_grant');
  await auditDetail(ctx,'delegated-agent:'+agent.id,'delegation_token_issued',task.id,{agentId:agent.id,serviceAppId:agent.service.id,accountablePersonId:task.accountable_id,approvedBy:task.approved_by,effectDigest:task.effect_digest,scope,expiresAt:expiresAt*1000});
  return json({access_token:token,token_type:'DPoP',expires_in:expiresAt-Math.floor(ctx.now()/1000),scope,authorization_details:details,grant_id:task.id,effect_digest:task.effect_digest});
 }catch(error) {
  await auditDetail(ctx,ctx.delegationActor?.actorId??null,'delegation_token_refused',ctx.delegationActor?.grantId??null,{...ctx.delegationActor,attemptedClientId:clientId.slice(0,256),attemptedGrantId,reason:error instanceof AuthError?error.message:'server_error'});
  if(!(error instanceof AuthError))throw error;
  return json({error:error.message},error.status,{...(error.status===429?{'retry-after':'60'}:{}),...(error.headers??{})});
 }
}
