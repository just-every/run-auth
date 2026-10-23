import {createLocalJWKSet,jwtVerify} from 'jose';
import {all,fail,random,json,auditDetail,AuthError,limit} from '../../core.mjs';
import {writeAdmin} from '../../admin-api/commands.mjs';
import {body,exact,id,SCOPE,issuer,organization,target,TARGET_PATH} from './common.mjs';
import {sameEffect,authorizationDetails,sameDetails} from './effect.mjs';
import {agentRow,taskRow,taskGuard,machinePrincipal,held} from './state.mjs';
import {requireDpop,DpopError} from './dpop.mjs';

const invalidToken=()=>{throw new DpopError('invalid_token',401);};

export async function authenticate(ctx,request,{external=false}={}) {
 const match=/^DPoP ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(request.headers.get('authorization')??'');
 if(!match||match[1].length>16384)invalidToken();
 const keys=(await all(ctx,'SELECT public_jwk FROM auth_signing_keys WHERE retire_at IS NULL OR retire_at>?',ctx.now())).map(r=>JSON.parse(r.public_jwk));
 let claims;
 try {
  ({payload:claims}=await jwtVerify(match[1],createLocalJWKSet({keys}),{issuer:issuer(ctx),typ:'at+jwt',algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['iss','exp','aud','iat','jti','sub','grant_id','effect_digest','scope','client_id','act','cnf','authorization_details']}));
 }catch{invalidToken();}
 const now=Math.floor(ctx.now()/1000);
 if(claims.delegation_profile!==(external?'auth-external-task-v1':'auth-assignment-task-v1')||!external&&(claims.aud!==target(ctx)||claims.scope!==SCOPE)||claims.organization_id!==organization(ctx)||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||claims.iat>now+30||claims.exp<=claims.iat||claims.exp-claims.iat>300||typeof claims.jti!=='string'||!claims.jti||claims.sid!==undefined||claims.amr!==undefined||claims.admin_service_app!==undefined||!claims.cnf||typeof claims.cnf.jkt!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(claims.cnf.jkt)||Object.keys(claims.cnf).length!==1)invalidToken();
 let agent,task;
 try {agent=await agentRow(ctx,id(claims.client_id));task=await taskRow(ctx,id(claims.grant_id));}catch(error){if(error instanceof AuthError)invalidToken();throw error;}
 const completed=task?.state==='completed'&&task.execution_id&&claims.grant_revision===task.revision-1;
 if(!agent||!task||task.agent_id!==agent.id||claims.sub!==task.accountable_id||!sameDetails(claims.act,{iss:issuer(ctx),sub:'agent:'+agent.id})||claims.agent_id!==agent.id||claims.agent_revision!==agent.revision||claims.delegated_admin_service!==agent.service.id||claims.service_revision!==agent.service.revision||claims.grant_revision!==task.revision&&!completed||claims.effect_digest!==task.effect_digest||claims.accountable_person!==task.accountable_id||claims.person_version!==task.accountable_version||!sameDetails(claims.authorization_details,authorizationDetails(task)))invalidToken();
 const effect=JSON.parse(task.effect);
 if(Boolean(task.resource_id)!==external||claims.aud!==effect.audience||claims.scope!==effect.scopes.join(' ')||claims.api_id!==effect.apiId||claims.resource!==effect.resource||claims.exp*1000>task.expires_at)invalidToken();
 return {agent,task,claims,raw:match[1]};
}
export async function executeDelegation(ctx,request,data) {
 if(request.method!=='POST')fail('method_not_allowed',405);
 const url=new URL(request.url);
 if(url.origin!==ctx.origin||url.search||![TARGET_PATH,(ctx.basePath??'')+TARGET_PATH].includes(url.pathname))fail('delegation_target_refused',403);
 const {agent,task,claims,raw}=await authenticate(ctx,request);
 if(!await limit(ctx,'delegated-dpop:'+agent.id,120,60000))fail('rate_limited',429);
 await requireDpop(ctx,request,agent,{htu:target(ctx),accessToken:raw,jkt:claims.cnf.jkt,task});
 data??=await body(ctx,request);
 try {exact(data,['grantId','effectDigest','task']);}catch(error){if(error instanceof AuthError)fail('delegation_effect_changed',403);throw error;}
 if(data.grantId!==task.id||data.effectDigest!==task.effect_digest)fail('delegation_effect_changed',403);
 const effect=await sameEffect(ctx,task,data.task);
 if(task.state==='completed')fail('delegation_already_consumed',409);
 const machine=await machinePrincipal(ctx,agent,claims.exp*1000);
 const live=()=>taskGuard(ctx,agent,task,['approved'],{expiresAt:claims.exp*1000,principal:machine});
 // Native writeAdmin checks assignments.manage plus the actual app/person
 // resources. Its command receives only this exact, digest-checked effect.
 const execution=random(),marker={clause:'EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)',args:[execution]};
 let committed=false;
 const actor={...machine,grantId:task.id,accountablePersonId:task.accountable_id,
  get ownerState(){return machine.ownerState;},
  get guard(){return marker;},
  assertAuthority:async()=>{if(!committed){await machine.assertAuthority();await held(ctx,await live());}},
  commit:async statements=>{
   if(committed)fail('delegation_already_consumed',409);
   await machine.prepareAuthority();
   const guard=await live(),detail=JSON.stringify({agentId:agent.id,grantId:task.id,accountablePersonId:task.accountable_id,agentCustodian:agent.registered_by,approvedBy:task.approved_by,effectDigest:task.effect_digest,effect,executionId:execution});
   const results=await ctx.db.batch([
    ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause}`).bind(execution,...guard.args),
    ctx.db.prepare(`UPDATE auth_delegated_tasks SET state='completed',completed_at=?,execution_id=?,revision=revision+1 WHERE id=? AND ${marker.clause}`).bind(ctx.now(),execution,task.id,...marker.args),
    ...statements,
    ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'delegation_executed',?,? WHERE ${marker.clause}`).bind(machine.actorId,task.id,ctx.now(),...marker.args),
    ctx.db.prepare(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${marker.clause}`).bind(detail,...marker.args),
    ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(execution),
   ]);
   if(!results[0].meta.changes){if((await taskRow(ctx,task.id))?.state==='completed')fail('delegation_already_consumed',409);await held(ctx,await live());fail('delegation_authority_changed',403);}
   committed=true;return results.slice(2,2+statements.length);
  },
 };
 try {
  const response=await writeAdmin(ctx,actor,`/assignments/${effect.appId}/person/${effect.personId}`,'PUT',{role:effect.role});
  if(!committed)fail('delegation_not_executed',409);
  return json({grantId:task.id,state:'completed',executionId:execution,effectDigest:task.effect_digest,result:await response.json()});
 }catch(error) {
  // Native assignment application is atomic with task completion. Later native
  // audit/event/provisioning work can still fail; preserve that distinction.
  if(committed)await auditDetail(ctx,machine.actorId,'delegation_followup_failed',task.id,{executionId:execution,assignmentApplied:true,reason:String(error?.message??'failed').slice(0,160)});
  throw error;
 }
}
