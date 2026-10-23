import {one,run,random,hash,fail,json,auditDetail,limit} from '../../core.mjs';
import {issuer,publicPath,both} from './common.mjs';
import {canonicalEffect,effectDigest} from './effect.mjs';
import {agentGuard,machinePrincipal,held} from './state.mjs';
import {resourceRow,resourceGuard} from './external-state.mjs';
import {privateAssertion} from './assertions.mjs';

export async function requestExternalTask(ctx,request,data,agent) {
 const effect=canonicalEffect(ctx,data.task,{creating:true});
 const resource=await resourceRow(ctx,effect.resourceId)||fail('resource_not_registered',403);
 if(effect.audience!==resource.audience||effect.detailType!==resource.detail_type||!JSON.parse(resource.scopes).includes(effect.scopes[0])||!JSON.parse(resource.operations).includes(effect.operation))fail('delegation_target_refused',403);
 if(!await one(ctx,'SELECT 1 FROM auth_delegation_agent_resources WHERE agent_id=? AND resource_id=?',agent.id,resource.id))fail('delegation_resource_refused',403);
 if(effect.expiresAt>agent.expires_at||effect.expiresAt>agent.service.expires_at)fail('invalid_delegation_expiry');
 const principal=await machinePrincipal(ctx,agent,effect.expiresAt);
 if(!principal.permits('people',effect.personId))fail('admin_service_resource_refused',403);
 if(!await limit(ctx,'delegated-assertion:'+agent.id,120,60000)||!await limit(ctx,'delegated-request:'+agent.id,30,3600000))fail('rate_limited',429);
 await privateAssertion(ctx,agent,data.clientAssertion,issuer(ctx)+'/api/auth/delegations/request',{delegation_use:'request',request_hash:await effectDigest(effect)});
 const person=await one(ctx,"SELECT version FROM oa_operators p WHERE id=? AND status='active' AND role='member' AND NOT EXISTS(SELECT 1 FROM auth_role_grants r WHERE r.person_id=p.id AND r.revoked_at IS NULL)",effect.personId)||fail('delegation_target_unavailable',403);
 const grantId=random(),digest=await hash(JSON.stringify({grantId,task:effect,agentRevision:agent.revision,serviceRevision:agent.service.revision,personVersion:person.version,resourceVersion:resource.revision}));
 const guard=both(await agentGuard(ctx,agent,effect.expiresAt,principal),resourceGuard(ctx,resource),{
  clause:"EXISTS(SELECT 1 FROM oa_operators p WHERE id=? AND version=? AND status='active' AND role='member' AND NOT EXISTS(SELECT 1 FROM auth_role_grants r WHERE r.person_id=p.id AND r.revoked_at IS NULL)) AND EXISTS(SELECT 1 FROM auth_delegation_agent_resources WHERE agent_id=? AND resource_id=?)",args:[effect.personId,person.version,agent.id,resource.id],
 });
 const result=await run(ctx,`INSERT INTO auth_external_tasks(id,agent_id,agent_revision,service_revision,organization_id,accountable_id,accountable_version,app_id,resource_id,resource_version,app_version,native_epoch,role_epoch,effect,effect_digest,before_role,before_created_by,before_created_at,created_at,expires_at) SELECT ?,?,?,?,?,?,?,NULL,?,?,0,0,0,?,?,NULL,?,?,?,? WHERE ${guard.clause}`,
 grantId,agent.id,agent.revision,agent.service.revision,effect.organizationId,effect.personId,person.version,resource.id,resource.revision,JSON.stringify(effect),digest,agent.registered_by,ctx.now(),ctx.now(),effect.expiresAt,...guard.args);
 if(!result.meta.changes){await held(ctx,guard);fail('delegation_target_changed',409);}
 await auditDetail(ctx,'delegated-agent:'+agent.id,'delegation_requested',grantId,{resourceId:resource.id,accountablePersonId:effect.personId,effectDigest:digest});
 return json({grantId,effectDigest:digest,consentPath:publicPath(ctx,'/app/account?delegation='+encodeURIComponent(grantId)),state:'requested',expiresAt:effect.expiresAt},201);
}
