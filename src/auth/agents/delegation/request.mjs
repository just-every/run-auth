import {one,run,random,hash,fail,json,auditDetail,limit} from '../../core.mjs';
import {body,exact,id,issuer,publicPath,both} from './common.mjs';
import {canonicalEffect,effectDigest} from './effect.mjs';
import {agentRow,agentGuard,machinePrincipal,held} from './state.mjs';
import {privateAssertion} from './assertions.mjs';
import {requestExternalTask} from './external-request.mjs';

export async function requestDelegation(ctx,request,data) {
 data??=await body(ctx,request);
 exact(data,['clientId','clientAssertion','task']);
 if(request.headers.has('authorization'))fail('invalid_client',401);
 const agent=await agentRow(ctx,id(data.clientId))||fail('invalid_client',401);
 if(data.task?.resourceId)return requestExternalTask(ctx,request,data,agent);
 const effect=canonicalEffect(ctx,data.task,{creating:true}),requestHash=await effectDigest(effect);
 if(effect.expiresAt>agent.expires_at||effect.expiresAt>agent.service.expires_at)fail('invalid_delegation_expiry');
 const principal=await machinePrincipal(ctx,agent,effect.expiresAt);
 if(!principal.permits('apps',effect.appId)||!principal.permits('people',effect.personId)||!principal.ownerAllows('apps.assign',{appId:effect.appId,personId:effect.personId,write:true}))fail('admin_service_resource_refused',403);
 if(!await limit(ctx,'delegated-assertion:'+agent.id,120,60000))fail('rate_limited',429);
 await privateAssertion(ctx,agent,data.clientAssertion,issuer(ctx)+'/api/auth/delegations/request',{delegation_use:'request',request_hash:requestHash});
 if(!await limit(ctx,'delegated-request:'+agent.id,30,3600000))fail('rate_limited',429);
 // Exactly one existing direct employee assignment; no group or administrator
 // custody changes are included in this first task profile.
 const before=await one(ctx,`SELECT p.version AS person_version,app.version AS app_version,a.role,a.created_by,a.created_at,ne.version AS native_epoch,re.epoch AS role_epoch FROM oa_operators p JOIN auth_apps app ON app.id=? JOIN auth_app_assignments a ON a.app_id=app.id AND a.principal_type='person' AND a.principal_id=p.id JOIN auth_admin_api_epoch ne ON ne.id=1 JOIN auth_role_epoch re ON re.id=1 WHERE p.id=? AND p.status='active' AND p.role='member' AND app.disabled_at IS NULL AND NOT EXISTS(SELECT 1 FROM auth_role_grants r WHERE r.person_id=p.id AND r.revoked_at IS NULL)`,effect.appId,effect.personId);
 if(!before)fail('delegation_target_unavailable',403);
 if(before.role===effect.role)fail('assignment_already_matches',409);
 await principal.prepareAuthority();
 if(!principal.ownerAllows('apps.assign',{appId:effect.appId,personId:effect.personId,write:true}))fail('delegation_owner_permission_required',403);
 const grantId=random(),digest=await hash(JSON.stringify({grantId,task:effect,preconditions:{agentRevision:agent.revision,serviceRevision:agent.service.revision,...before}})),guard=both(await agentGuard(ctx,agent,effect.expiresAt,principal),{
  clause:`EXISTS(SELECT 1 FROM oa_operators p JOIN auth_apps app ON app.id=? JOIN auth_app_assignments a ON a.app_id=app.id AND a.principal_type='person' AND a.principal_id=p.id JOIN auth_admin_api_epoch ne ON ne.id=1 JOIN auth_role_epoch re ON re.id=1 WHERE p.id=? AND p.status='active' AND p.role='member' AND p.version=? AND app.disabled_at IS NULL AND app.version=? AND a.role IS ? AND a.created_by=? AND a.created_at=? AND ne.version=? AND re.epoch=?)`,
  args:[effect.appId,effect.personId,before.person_version,before.app_version,before.role,before.created_by,before.created_at,before.native_epoch,before.role_epoch],
 });
 const result=await run(ctx,`INSERT INTO auth_delegated_tasks(id,agent_id,agent_revision,service_revision,organization_id,accountable_id,accountable_version,app_id,app_version,native_epoch,role_epoch,effect,effect_digest,before_role,before_created_by,before_created_at,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`,grantId,agent.id,agent.revision,agent.service.revision,effect.organizationId,effect.personId,before.person_version,effect.appId,before.app_version,before.native_epoch,before.role_epoch,JSON.stringify(effect),digest,before.role,before.created_by,before.created_at,ctx.now(),effect.expiresAt,...guard.args);
 if(!result.meta.changes){await held(ctx,await agentGuard(ctx,agent));fail('delegation_target_changed',409);}
 await auditDetail(ctx,'delegated-agent:'+agent.id,'delegation_requested',grantId,{accountablePersonId:effect.personId,effectDigest:digest,task:effect});
 return json({grantId,effectDigest:digest,consentPath:publicPath(ctx,'/app/account?delegation='+encodeURIComponent(grantId)),state:'requested',expiresAt:effect.expiresAt},201);
}
