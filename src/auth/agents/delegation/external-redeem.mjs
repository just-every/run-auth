import {one,run,hash,random,json,fail,limit,AuthError} from '../../core.mjs';
import {body,exact,issuer,both} from './common.mjs';
import {authenticate} from './execute.mjs';
import {sameEffect} from './effect.mjs';
import {taskGuard,taskRow,held} from './state.mjs';
import {resourceRow,resourceGuard} from './external-state.mjs';
import {verifyPrivateAssertion} from './assertions.mjs';
import {requireDpop} from './dpop.mjs';

// A resource calls this door itself before a side effect. Auth never calls an
// arbitrary destination, and a self-contained JWT alone never licenses a call.
export async function redeemExternalTask(ctx,request,data) {
 data??=await body(ctx,request);exact(data,['resourceId','resourceAssertion','grantId','effectDigest','task']);
 const {agent,task,claims,raw}=await authenticate(ctx,request,{external:true});
 const resource=await resourceRow(ctx,task.resource_id)||fail('resource_not_registered',403);
 if(data.resourceId!==resource.id||data.grantId!==task.id||data.effectDigest!==task.effect_digest)fail('delegation_effect_changed',403);
 if(!await limit(ctx,'external-resource:'+resource.id,120,60000)||!await limit(ctx,'delegated-dpop:'+agent.id,120,60000))fail('rate_limited',429);
 const resourceIdentity={client_id:resource.client_id,service:{jwks:resource.jwks}};
 const assertion=await verifyPrivateAssertion(ctx,resourceIdentity,data.resourceAssertion,issuer(ctx)+'/api/auth/delegations/resources/redeem',{
  delegation_use:'redeem',grant_id:task.id,effect_digest:task.effect_digest,token_hash:await hash(raw),proof_hash:await hash(request.headers.get('dpop')??''),
 });
 const effect=await sameEffect(ctx,task,data.task);
 await held(ctx,resourceGuard(ctx,resource));
 await requireDpop(ctx,request,agent,{htu:resource.audience,accessToken:raw,jkt:claims.cnf.jkt,task});
 if(task.state==='completed')fail('delegation_already_consumed',409);
 const guard=both(await taskGuard(ctx,agent,task,['approved'],{expiresAt:claims.exp*1000}),resourceGuard(ctx,resource));
 const execution=random(),marker={clause:'EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)',args:[execution]};
 const detail=JSON.stringify({agentId:agent.id,accountablePersonId:task.accountable_id,approvedBy:task.approved_by,resourceId:resource.id,effectDigest:task.effect_digest,executionId:execution,remoteOutcome:'unknown'});
 let results;
 try {
  results=await ctx.db.batch([
   ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause}`).bind(execution,...guard.args),
   ctx.db.prepare(`INSERT INTO auth_delegation_resource_assertions(resource_id,jti,expires_at) SELECT ?,?,? WHERE ${marker.clause}`).bind(resource.id,assertion.jti,assertion.exp*1000,...marker.args),
   ctx.db.prepare(`UPDATE auth_external_tasks SET state='completed',completed_at=?,execution_id=?,revision=revision+1 WHERE id=? AND ${marker.clause}`).bind(ctx.now(),execution,task.id,...marker.args),
   ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'delegation_resource_released',?,? WHERE ${marker.clause}`).bind('delegated-agent:'+agent.id,task.id,ctx.now(),...marker.args),
   ctx.db.prepare(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${marker.clause}`).bind(detail,...marker.args),
   ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(execution),
  ]);
 }catch(error){if(/UNIQUE constraint failed|PRIMARY KEY constraint failed/.test(String(error?.message)))fail('invalid_client',401);throw error;}
 if(!results[0].meta.changes){if((await taskRow(ctx,task.id))?.state==='completed')fail('delegation_already_consumed',409);await held(ctx,guard);fail('delegation_authority_changed',403);}
 return json({authorized:true,grantId:task.id,executionId:execution,personId:task.accountable_id,organizationId:task.organization_id,agentId:agent.id,approvedBy:task.approved_by,effectDigest:task.effect_digest,task:effect,remoteOutcome:'unknown'});
}
