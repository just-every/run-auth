import {one} from '../../core.mjs';
import {both,organization} from './common.mjs';
import {agentGuard,machinePrincipal} from './state.mjs';

export const resourceRow=(ctx,id)=>one(ctx,'SELECT * FROM auth_delegation_resources WHERE id=?',id);
export const resourceGuard=(ctx,resource)=>({
 clause:"EXISTS(SELECT 1 FROM auth_delegation_resources dr JOIN oa_operators custodian ON custodian.id=dr.registered_by WHERE dr.id=? AND dr.revision=? AND dr.disabled_at IS NULL AND custodian.status='active' AND custodian.role='owner' AND custodian.version=dr.owner_version)",
 args:[resource.id,resource.revision],
});
export async function externalTaskGuard(ctx,agent,task,states,{consent=true,approval=true,expiresAt=task.expires_at,principal=null}={}) {
 principal??=await machinePrincipal(ctx,agent,expiresAt);
 const now=ctx.now();
 return both(await agentGuard(ctx,agent,expiresAt,principal),{
 clause:`EXISTS(SELECT 1 FROM auth_external_tasks dt
 JOIN oa_operators person ON person.id=dt.accountable_id
 JOIN auth_delegation_resources dr ON dr.id=dt.resource_id
 JOIN oa_operators custodian ON custodian.id=dr.registered_by
 JOIN auth_delegation_agent_resources ar ON ar.resource_id=dr.id AND ar.agent_id=dt.agent_id
 WHERE dt.id=? AND dt.revision=? AND dt.effect_digest=? AND dt.organization_id=?
 AND dt.agent_id=? AND dt.agent_revision=? AND dt.service_revision=?
 AND dt.state IN (${states.map(()=>'?').join(',')}) AND dt.expires_at>?
 AND person.status='active' AND person.role='member' AND person.version=dt.accountable_version
 AND NOT EXISTS(SELECT 1 FROM auth_role_grants privileged WHERE privileged.person_id=person.id AND privileged.revoked_at IS NULL)
 AND dr.revision=dt.resource_version AND dr.disabled_at IS NULL
 AND custodian.status='active' AND custodian.role='owner' AND custodian.version=dr.owner_version
 ${consent?'AND dt.consented_by=dt.accountable_id AND dt.consented_at IS NOT NULL AND dt.consented_at<=?':''}
 ${approval?"AND EXISTS(SELECT 1 FROM oa_operators approver WHERE approver.id=dt.approved_by AND approver.status='active' AND approver.role IN ('owner','admin') AND approver.version=dt.approver_version AND approver.id!=dt.accountable_id AND approver.id!=? AND dt.approved_at IS NOT NULL AND dt.approved_at<=?)":''})`,
 args:[task.id,task.revision,task.effect_digest,organization(ctx),agent.id,agent.revision,agent.service.revision,...states,now,...(consent?[now]:[]),...(approval?[agent.registered_by,now]:[])],
 },{clause:"EXISTS(SELECT 1 FROM auth_admin_service_apps s,json_each(s.resources,'$.people') p WHERE s.id=? AND p.value=?)",args:[agent.service.id,task.accountable_id]});
}
