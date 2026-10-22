import {one,fail,AuthError} from '../../core.mjs';
import {principalFor} from '../../admin-api/credentials/authority.mjs';
import {both,organization,CLIENT_PREFIX,SCOPE} from './common.mjs';

export const taskRow=(ctx,id)=>one(ctx,'SELECT * FROM auth_delegated_tasks WHERE id=?',id);
export async function agentRow(ctx,clientId) {
 const row=await one(ctx,`SELECT a.*,json_object('id',s.id,'client_id',s.client_id,'owner_id',s.owner_id,'revision',s.revision,'expires_at',s.expires_at,'revoked_at',s.revoked_at,'suspended_at',s.suspended_at,'jwks',s.jwks,'scopes',s.scopes,'resources',s.resources) AS service_json FROM auth_delegated_agents a JOIN auth_admin_service_apps s ON s.id=a.service_app_id WHERE a.client_id=?`,clientId);
 return row?{...row,service:JSON.parse(row.service_json)}:null;
}
export function employerGuard(ctx) {
 return organization(ctx)==='root'?{clause:'1',args:[]}:{clause:"EXISTS(SELECT 1 FROM auth_organizations employer WHERE employer.id=? AND employer.status='active')",args:[organization(ctx)]};
}
export async function agentGuard(ctx,agent,expiresAt=agent.expires_at,principal=null) {
 principal??=await machinePrincipal(ctx,agent,expiresAt);
 return both(employerGuard(ctx),principal.guard,{
  clause:"EXISTS(SELECT 1 FROM auth_delegated_agents da JOIN oa_operators custodian ON custodian.id=da.registered_by WHERE da.id=? AND da.client_id=? AND da.revision=? AND da.state='active' AND da.expires_at>? AND da.service_app_id=? AND da.registered_by=? AND custodian.status='active' AND custodian.role='owner' AND custodian.version=da.registered_owner_version AND custodian.version=?)",
  args:[agent.id,agent.client_id,agent.revision,ctx.now(),agent.service.id,agent.service.owner_id,agent.registered_owner_version],
 });
}
export async function taskGuard(ctx,agent,task,states=['approved'],{consent=true,approval=true,expiresAt=task.expires_at,principal=null}={}) {
 const now=ctx.now();
 principal??=await machinePrincipal(ctx,agent,expiresAt);
 if(!principal.permits('apps',task.app_id)||!principal.permits('people',task.accountable_id)||!principal.ownerAllows('apps.assign',{appId:task.app_id,personId:task.accountable_id,write:true}))fail('delegation_owner_permission_required',403);
 return both(await agentGuard(ctx,agent,expiresAt,principal),{
  clause:`EXISTS(SELECT 1 FROM auth_delegated_tasks dt
   JOIN oa_operators person ON person.id=dt.accountable_id
   JOIN auth_apps app ON app.id=dt.app_id
   JOIN auth_app_assignments aa ON aa.app_id=app.id AND aa.principal_type='person' AND aa.principal_id=person.id
   JOIN auth_admin_api_epoch ne ON ne.id=1
   WHERE dt.id=? AND dt.revision=? AND dt.effect_digest=? AND dt.organization_id=?
   AND dt.agent_id=? AND dt.agent_revision=? AND dt.service_revision=?
   AND dt.state IN (${states.map(()=>'?').join(',')}) AND dt.expires_at>?
   AND person.status='active' AND person.role='member' AND person.version=dt.accountable_version
   AND NOT EXISTS(SELECT 1 FROM auth_role_grants privileged WHERE privileged.person_id=person.id AND privileged.revoked_at IS NULL)
   AND app.disabled_at IS NULL AND app.version=dt.app_version
   AND aa.role IS dt.before_role AND aa.created_by=dt.before_created_by AND aa.created_at=dt.before_created_at
   AND ne.version=dt.native_epoch
   ${consent?'AND dt.consented_by=dt.accountable_id AND dt.consented_at IS NOT NULL AND dt.consented_at<=?':''}
   ${approval?"AND EXISTS(SELECT 1 FROM oa_operators approver WHERE approver.id=dt.approved_by AND approver.status='active' AND approver.role IN ('owner','admin') AND approver.version=dt.approver_version AND approver.id!=dt.accountable_id AND approver.id!=? AND dt.approved_at IS NOT NULL AND dt.approved_at<=?)":''})`,
  args:[task.id,task.revision,task.effect_digest,organization(ctx),agent.id,agent.revision,agent.service.revision,...states,now,...(consent?[now]:[]),...(approval?[agent.registered_by,now]:[])],
 });
}
export async function held(ctx,guard,code='delegation_authority_changed') {
 if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail(code,403);
}
export async function machinePrincipal(ctx,agent,expiresAt) {
 if(agent.service.client_id!==agent.client_id||!agent.client_id.startsWith(CLIENT_PREFIX)||!JSON.parse(agent.service.scopes).includes(SCOPE))fail('admin_service_scope_required',403);
 const principal=await principalFor(ctx,agent.service,[SCOPE],expiresAt);
 // Retain the principal's live accessors when its owner snapshot is refreshed.
 return {...principal,get ownerState(){return principal.ownerState;},get guard(){return principal.guard;},kind:'delegated-agent',actorId:CLIENT_PREFIX+agent.id,agentId:agent.id};
}
export async function agentForTask(ctx,task) {
 const row=await one(ctx,'SELECT client_id FROM auth_delegated_agents WHERE id=?',task.agent_id);
 return row?agentRow(ctx,row.client_id):null;
}
export async function taskCurrent(ctx,agent,task) {
 if(!agent||!['requested','consented','approved'].includes(task.state))return false;
 try {
  const guard=await taskGuard(ctx,agent,task,[task.state],{consent:task.state!=='requested',approval:task.state==='approved'});
  return Boolean(await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args));
 }catch(error) {
  // Ended authority remains visible as ended; unexpected storage failures surface.
  if(error instanceof AuthError)return false;
  throw error;
 }
}
