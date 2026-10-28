import {REVISION_ACTIONS,revisionCommand} from '../catalog/revisions.mjs';
import {requireVerifiedDomain} from '../domains/ownership.mjs';
// Human-only adapter over the existing native command implementations. Each
// action is named here with explicit permission and compound resource checks;
// no generic path forwarding or machine credential is accepted.
import {one,random,json,fail} from '../core.mjs';
import {authority,requireAuthority,requireLocalEmail} from '../local-email.mjs';
import {workforceCommand} from '../workforce/routes.mjs';
import {setAuthorizedRule,ruleDelta} from '../workforce/people/rules.mjs';
import {normalizeRule} from '../workforce/people/groups.mjs';
import {planEdits} from '../workforce/people/plan.mjs';
import {applyAuthorizedPlan} from '../workforce/people/apply.mjs';
import {clientSettings} from '../oidc-apps/clients.mjs';
import {writeProvider} from '../admin-api/providers.mjs';
import {configuredProvider} from '../domain-policy.mjs';
import {roleState} from './state.mjs';
import {requireHardware,assertPermission,roleGuard,permitted} from './policy.mjs';
import {contains} from './permissions.mjs';
import {commit} from './commit.mjs';

const APP_COMMANDS=[...REVISION_ACTIONS,'/company-apps/create','/company-apps/update','/company-apps/remove','/oidc-apps/create','/oidc-apps/update','/oidc-apps/rotate-secret','/catalog/add','/provisioning/connect','/provisioning/rotate','/provisioning/disconnect'];
const ASSIGN_COMMANDS=['/company-apps/assign','/company-apps/unassign'];
const GROUP_COMMANDS=['/groups/create','/groups/delete','/groups/rule'];
export const ROLE_COMMANDS=Object.freeze([...APP_COMMANDS,...ASSIGN_COMMANDS,...GROUP_COMMANDS,'/people/suspend','/people/restore','/policy/domain-rule','/identity-providers/availability']);
const wildcard=(state,permission,kind)=>{
 if(!state.entries.some(e=>e.role.permissions.includes(permission)&&contains(e.resources.edit[kind],'*')))fail('unrestricted_role_resource_required',403);
};
function targetPeople(state,permission,ids) {
 for(const personId of ids)assertPermission(state,permission,{personId,write:true});
}
function groupPeople(state,id) {return [...state.memberships].filter(([,groups])=>groups.has(id)).map(([personId])=>personId);}
function commandAuthority(state,action,data) {
 if(APP_COMMANDS.includes(action)) {
  const create=['/company-apps/create','/oidc-apps/create','/catalog/add'].includes(action);
  if(create){assertPermission(state,'apps.edit');wildcard(state,'apps.edit','apps');}
  else assertPermission(state,'apps.edit',{appId:String(data.appId??data.id??''),write:true});
  return 'apps.edit';
 }
 if(ASSIGN_COMMANDS.includes(action)) {
  const appId=String(data.appId??'');assertPermission(state,'apps.assign',{appId,write:true});
  if(data.principal!==undefined)fail('explicit_assignment_target_required');
  if(data.principalType==='group') {
   const groupId=String(data.principalId??'');assertPermission(state,'apps.assign',{appId,groupId,write:true});
   targetPeople(state,'apps.assign',groupPeople(state,groupId));
  } else if(data.principalType==='person')assertPermission(state,'apps.assign',{appId,personId:String(data.principalId??''),write:true});
  else fail('invalid_assignment_target');
  return 'apps.assign';
 }
 if(GROUP_COMMANDS.includes(action)) {
  const permission=action==='/groups/rule'?'groups.rules.edit':'groups.edit';
  if(action==='/groups/create'){assertPermission(state,permission);wildcard(state,permission,'groups');}
  else {
   const groupId=String(data.groupId??data.id??'');assertPermission(state,permission,{groupId,write:true});
   targetPeople(state,permission,groupPeople(state,groupId));
  }
  return permission;
 }
 if(action==='/people/suspend'||action==='/people/restore') {
  const permission=action==='/people/suspend'?'people.suspend':'people.restore';
  assertPermission(state,permission,{personId:String(data.personId??''),write:true});return permission;
 }
 const permission=action==='/policy/domain-rule'?'policy.manage':'identity-providers.manage';
 assertPermission(state,permission);wildcard(state,permission,'people');wildcard(state,permission,'groups');wildcard(state,permission,'apps');return permission;
}
function actorFor(ctx,s,state,action,data,permission) {
 const id=random(),live=roleGuard(ctx,s,state);let used=false;
 const guard={clause:'EXISTS(SELECT 1 FROM auth_role_operations WHERE id=?)',args:[id]};
 return {kind:'human-scoped',actorId:s.person_id,ownerId:s.person_id,scopes:['idps.manage'],guard,
  assertAuthority:()=>requireAuthority(ctx,s,authority(ctx,s,[state.person.role])),
  commit:async statements=>{
   // These native actions have one mutation transaction. A second commit would
   // require a new authorization decision against its newly affected resources.
   if(used)fail('role_command_multiple_transactions',409);
   const {results}=await commit(ctx,s,live,'roles.command',String(data.appId??data.id??data.groupId??data.personId??data.providerId??''),{action,permission},()=>statements,id);
   used=true;return results.slice(1,1+statements.length);
  },
 };
}
async function updateOidc(ctx,actor,data) {
 const appId=String(data.appId??data.id??''),row=await one(ctx,'SELECT c.*,a.name,a.attributes,a.launch_url,a.version FROM auth_oidc_clients c JOIN auth_apps a ON a.id=c.app_id WHERE c.app_id=? AND a.disabled_at IS NULL',appId)??fail('app_not_found',404);
 if(data.version!==undefined&&Number(data.version)!==row.version)fail('app_changed',409);
 const settings=clientSettings(ctx,{authMethod:row.auth_method,jwks:row.jwks,redirectUris:JSON.parse(row.redirect_uris),postLogoutRedirectUris:JSON.parse(row.post_logout_redirect_uris),requirePkce:Boolean(row.require_pkce),subjectType:row.subject_type,legacyFlows:Boolean(row.legacy_flows),frontchannelLogoutUri:row.frontchannel_logout_uri,backchannelLogoutUri:row.backchannel_logout_uri,idTokenAlg:row.id_token_alg,...data});
 // Changing secret-based authentication to/from a different method needs a
 // credential ceremony; creation/rotation are the existing one-time doors.
 if(settings.authMethod!==row.auth_method)fail('oidc_auth_method_fixed',409);
 const name=data.name===undefined?row.name:String(data.name).trim();if(!name||name.length>120)fail('invalid_name');
 const g=actor.guard;
 await actor.commit([
  ctx.db.prepare(`UPDATE auth_apps SET name=?,version=version+1,updated_at=? WHERE id=? AND ${g.clause}`).bind(name,ctx.now(),appId,...g.args),
  ctx.db.prepare(`UPDATE auth_oidc_clients SET jwks=?,redirect_uris=?,post_logout_redirect_uris=?,require_pkce=?,subject_type=?,legacy_flows=?,frontchannel_logout_uri=?,backchannel_logout_uri=?,id_token_alg=? WHERE app_id=? AND ${g.clause}`).bind(settings.jwks?JSON.stringify(settings.jwks):null,JSON.stringify(settings.redirectUris),JSON.stringify(settings.postLogout),settings.requirePkce?1:0,settings.subjectType,settings.legacyFlows?1:0,settings.frontchannel,settings.backchannel,settings.alg,appId,...g.args),
 ]);
 return json({ok:true,id:appId});
}
export async function roleCommand(ctx,s,data) {
 requireHardware(s);requireLocalEmail(ctx,s);
 const action=String(data.action??'');if(!ROLE_COMMANDS.includes(action))fail('role_command_excluded',403);
 const params=data.params??{};if(!params||typeof params!=='object'||Array.isArray(params))fail('invalid_role_command');
 if(params.id!==undefined&&params.appId!==undefined&&params.id!==params.appId)fail('conflicting_resource_ids');
 if(params.id!==undefined&&params.groupId!==undefined&&params.id!==params.groupId)fail('conflicting_resource_ids');
 const state=await roleState(ctx,s),permission=commandAuthority(state,action,params);
 if(REVISION_ACTIONS.includes(action))return revisionCommand(ctx,s,action,params);
 const actor=actorFor(ctx,s,state,action,params,permission);
 if(action==='/oidc-apps/update')return updateOidc(ctx,actor,params);
 if(action==='/provisioning/disconnect') {
  const appId=String(params.appId??''),g=actor.guard;
  await actor.commit([ctx.db.prepare(`DELETE FROM auth_scim_connectors WHERE app_id=? AND ${g.clause}`).bind(appId,...g.args),ctx.db.prepare(`UPDATE auth_provisioning SET state='failed',last_error='connector_removed' WHERE app_id=? AND state='pending' AND ${g.clause}`).bind(appId,...g.args)]);
  return json({ok:true});
 }
 if(action==='/groups/rule') {
  const group=state.dir.groups.find(g=>g.id===params.groupId)??fail('group_not_found',404),rule=params.rule?normalizeRule(state.dir.defs,params.rule):null;
  const delta=ruleDelta(state.dir,group,rule);
  targetPeople(state,permission,[...delta.added,...delta.removed].map(p=>p.id));
  return json(await setAuthorizedRule(ctx,actor,actor.guard,state.dir,{groupId:group.id,rule}));
 }
 if(action==='/people/suspend'||action==='/people/restore') {
  const personId=String(params.personId??''),plan=await planEdits(ctx,state.dir,[{personId,state:action==='/people/suspend'?'suspended':'active'}],s.person_id);
  if(!plan.ok)return json({error:'edit_refused',refusals:plan.entries.flatMap(e=>e.refusals)},409);
  await applyAuthorizedPlan(ctx,actor,actor.guard,state.dir,plan);return json({ok:true});
 }
 if(action==='/identity-providers/availability')return writeProvider(ctx,actor,String(params.providerId??''),{enabled:params.enabled});
 if(action==='/policy/domain-rule') {
  const domain=String(params.domain??'').toLowerCase(),providerId=String(params.providerId??'');
  if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||domain.length>253)fail('invalid_domain');
  if(providerId&&!configuredProvider(ctx,providerId))fail('unknown_provider');
  if(providerId)await requireVerifiedDomain(ctx,domain);
  const g=actor.guard;
  await actor.commit([providerId?ctx.db.prepare(`INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) SELECT ?,?,?,? WHERE ${g.clause} ON CONFLICT(domain) DO UPDATE SET provider_id=excluded.provider_id,created_by=excluded.created_by,created_at=excluded.created_at`).bind(domain,providerId,s.person_id,ctx.now(),...g.args):ctx.db.prepare(`DELETE FROM oa_domain_rules WHERE domain=? AND ${g.clause}`).bind(domain,...g.args)]);
  return json({ok:true});
 }
 return workforceCommand(ctx,actor,action,params);
}
