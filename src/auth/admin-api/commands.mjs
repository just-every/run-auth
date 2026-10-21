import {writeProvider} from './providers.mjs';
import {json,fail,one,all} from '../core.mjs';
import {workforceCommand} from '../workforce/routes.mjs';
import {loadDirectory} from '../workforce/people/load.mjs';
import {planEdits} from '../workforce/people/plan.mjs';
import {applyAuthorizedPlan,onboardAuthorizedPerson} from '../workforce/people/apply.mjs';
import {setAuthorizedRule,ruleDelta} from '../workforce/people/rules.mjs';
import {normalizeRule} from '../workforce/people/groups.mjs';
import {configuredProvider} from '../domain-policy.mjs';
import {emit} from '../events/store.mjs';
import {requireScope,requireResource,only,groupEffects,personEffects,planResources} from './resources.mjs';

export async function writeAdmin(ctx,actor,path,method,data) {
 let m;
 if((m=/^\/idps\/([^/]+)$/.exec(path))&&method==='PUT'){requireScope(actor,'idps.manage');only(data,['enabled']);return writeProvider(ctx,actor,m[1],data);}
 if(path==='/groups'&&method==='POST') {
  requireScope(actor,'groups.manage');only(data,['name']);
  if(!actor.permits('groups','*'))fail('admin_service_resource_refused',403);
  return workforceCommand(ctx,actor,'/groups/create',data);
 }
 if((m=/^\/groups\/([^/]+)$/.exec(path))&&method==='DELETE') {
  requireScope(actor,'groups.manage');only(data,[]);await groupEffects(ctx,actor,m[1]);
  return workforceCommand(ctx,actor,'/groups/delete',{id:m[1]});
 }
 if((m=/^\/groups\/([^/]+)\/members\/([^/]+)$/.exec(path))&&['PUT','DELETE'].includes(method)) {
  requireScope(actor,'groups.manage');only(data,['reason']);await groupEffects(ctx,actor,m[1]);requireResource(actor,'people',m[2]);
  return workforceCommand(ctx,actor,method==='PUT'?'/groups/add':'/groups/remove',{groupId:m[1],personId:m[2],reason:data.reason});
 }
 if((m=/^\/groups\/([^/]+)\/rule$/.exec(path))&&method==='PUT') {
  requireScope(actor,'groups.manage');only(data,['rule']);await groupEffects(ctx,actor,m[1]);
  const dir=await loadDirectory(ctx),group=dir.groups.find(g=>g.id===m[1])||fail('group_not_found',404);
  const rule=data.rule?normalizeRule(dir.defs,data.rule):null;
  for(const p of [...ruleDelta(dir,group,rule).added,...ruleDelta(dir,group,rule).removed])requireResource(actor,'people',p.id);
  return json(await setAuthorizedRule(ctx,actor,actor.guard,dir,{groupId:m[1],rule}));
 }
 if(path==='/apps'&&method==='POST') {
  requireScope(actor,'apps.manage');if(!actor.permits('apps','*'))fail('admin_service_resource_refused',403);
  const protocol=data.protocol??'saml';
  only(data,protocol==='saml'?['protocol','name','metadata','entityId','acsUrl','acsBinding','sloUrl','sloBinding','nameIdFormat','nameIdSource','sign','digest','sha1Exception','attributes','launchUrl','signingCertificate','encryptionCertificate','encryption','wantRequestsSigned','idpInitiated','relayState']:['protocol','name','authMethod','jwks','redirectUris','postLogoutRedirectUris','requirePkce','subjectType','legacyFlows','frontchannelLogoutUri','backchannelLogoutUri','idTokenAlg','attributes','launchUrl']);
  if(!['saml','oidc'].includes(protocol))fail('invalid_app_protocol');
  return workforceCommand(ctx,actor,protocol==='saml'?'/company-apps/create':'/oidc-apps/create',data);
 }
 if((m=/^\/apps\/([^/]+)$/.exec(path))&&['PATCH','DELETE'].includes(method)) {
  requireScope(actor,'apps.manage');requireResource(actor,'apps',m[1]);
  if(method==='PATCH')only(data,['name','metadata','entityId','acsUrl','acsBinding','sloUrl','sloBinding','nameIdFormat','nameIdSource','sign','digest','sha1Exception','attributes','launchUrl','signingCertificate','encryptionCertificate','encryption','wantRequestsSigned','idpInitiated','relayState']);else only(data,[]);
  // Removing an app changes all its assignments, so the credential must own each target.
  if(method==='DELETE')for(const a of await all(ctx,'SELECT principal_type,principal_id FROM auth_app_assignments WHERE app_id=?',m[1]))requireResource(actor,a.principal_type==='group'?'groups':'people',a.principal_id);
  return workforceCommand(ctx,actor,method==='PATCH'?'/company-apps/update':'/company-apps/remove',{...data,id:m[1]});
 }
 if((m=/^\/assignments\/([^/]+)\/(person|group)\/([^/]+)$/.exec(path))&&['PUT','DELETE'].includes(method)) {
  requireScope(actor,'assignments.manage');only(data,['role']);requireResource(actor,'apps',m[1]);requireResource(actor,m[2]==='group'?'groups':'people',m[3]);
  return workforceCommand(ctx,actor,method==='PUT'?'/company-apps/assign':'/company-apps/unassign',{...data,appId:m[1],principalType:m[2],principalId:m[3]});
 }
 if(path==='/people'&&method==='POST') {
  requireScope(actor,'people.manage');only(data,['email','name','kind','set','source','sourceId']);
  if(!actor.permits('people','*'))fail('admin_service_resource_refused',403);
  // Creation is an invited member record, with no automatic outbound invitation.
  const dir=await loadDirectory(ctx);
  if(dir.ruleGroups.some(g=>!actor.permits('groups',g.id))||dir.assignments.some(a=>!actor.permits('apps',a.app_id)))fail('admin_service_resource_refused',403);
  const result=await onboardAuthorizedPerson(ctx,actor,actor.guard,dir,{...data,invite:false},()=>{});
  if(result.refused)return json({error:'onboard_refused',refusals:result.refused},409);
  return json({id:result.personId},201);
 }
 if((m=/^\/people\/([^/]+)$/.exec(path))&&method==='PATCH') {
  requireScope(actor,'people.manage');only(data,['set','source','email','state']);await personEffects(ctx,actor,m[1]);
  const dir=await loadDirectory(ctx),plan=await planEdits(ctx,dir,[{...data,personId:m[1]}],actor.actorId);
  if(!plan.ok)return json({error:'edit_refused',refusals:plan.entries.flatMap(e=>e.refusals)},409);
  planResources(actor,plan);await applyAuthorizedPlan(ctx,actor,actor.guard,dir,plan);return json({ok:true});
 }
 if((m=/^\/policies\/([^/]+)$/.exec(path))&&['PUT','DELETE'].includes(method)) {
  requireScope(actor,'policies.manage');only(data,method==='PUT'?['providerId']:[]);
  const domain=m[1].toLowerCase(),providerId=method==='DELETE'?'':String(data.providerId||'');
  if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||domain.length>253)fail('invalid_domain');
  if(method==='PUT'&&(!providerId||!configuredProvider(ctx,providerId)))fail('unknown_provider');
  const guard=actor.guard;
  const statement=providerId?ctx.db.prepare(`INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) SELECT ?,?,?,? WHERE ${guard.clause} ON CONFLICT(domain) DO UPDATE SET provider_id=excluded.provider_id,created_by=excluded.created_by,created_at=excluded.created_at`).bind(domain,providerId,actor.actorId,ctx.now(),...guard.args):ctx.db.prepare(`DELETE FROM oa_domain_rules WHERE domain=? AND ${guard.clause}`).bind(domain,...guard.args);
  await actor.commit([statement]);await emit(ctx,'policy.domain_rule_changed',{type:'domain',id:domain},{requiredProvider:providerId||null});return json({ok:true});
 }
 // No scope opens identity, custody, recovery, role/resource-set or credential
 // management doors. New domain capabilities need explicit commands here.
 fail('admin_service_action_excluded',403);
}
