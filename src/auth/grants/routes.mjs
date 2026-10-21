import {configuration,configurationView} from './configuration.mjs';
import {all,auditDetail,fail,input,json,one,random,requireSession,run} from '../core.mjs';
import {authority,requireAuthority,requireLocalEmail} from '../local-email.mjs';
import {workforceCommand} from '../workforce/routes.mjs';
import {CLIENT_PREFIX,identifier,label,policySettings,serviceSettings} from './config.mjs';
import {apiRow,organization,serviceGuard} from './authority.mjs';
import {publicKeys} from './public-keys.mjs';
import {decisionSnapshot,evaluate} from './decision.mjs';
import {resourcePrincipal} from './token.mjs';

const prefix='/resource-apis';
const actionPath=path=>path.startsWith('/api/auth/')?path.slice('/api/auth'.length):path;
const ACTIONS=['register','assign','service-create','service-revoke','check'].map(s=>prefix+'/'+s);
export const isGrantAction=path=>ACTIONS.includes(actionPath(path));
const origin=(ctx,request)=>{if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);};

export async function grantCheck(ctx,request,data) {
 if(data===undefined) {
  if(!request.headers.has('authorization'))data=await input(ctx,request);
  else {
   if(!(request.headers.get('content-type')||'').startsWith('application/json'))fail('unsupported_content_type',415);
   if(Number(request.headers.get('content-length')||0)>65536)fail('request_too_large',413);
   const text=await request.text();
   if(text.length>65536)fail('request_too_large',413);
   try{data=JSON.parse(text);}catch{fail('invalid_json');}
  }
 }
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_request');
 const apiId=identifier(data.apiId,'invalid_api_id');
 const machine=request.headers.has('authorization');
 let personId,principal=null,guard;
 if(machine) {
  principal=await resourcePrincipal(ctx,request,apiId);
  // A service is always itself; its owner is accountability, never a substituted subject.
  if(data.subject!==undefined)fail('subject_substitution_refused',403);
  personId=principal.ownerId;
  guard=serviceGuard(ctx,principal.service,principal.expiresAt,principal.api.revision);
 } else {
  origin(ctx,request);
  const s=await requireSession(ctx,request);
  if(data.subject!==undefined&&data.subject!==s.person_id)fail('subject_substitution_refused',403);
  personId=s.person_id;
  guard={clause:"EXISTS(SELECT 1 FROM auth_sessions live_session JOIN oa_operators live_person ON live_person.id=live_session.person_id WHERE live_session.id=? AND live_session.person_id=? AND live_session.revoked_at IS NULL AND live_session.expires_at>? AND live_session.person_version=live_person.version AND live_session.person_version=? AND live_person.status='active')",args:[s.id,s.person_id,ctx.now(),s.person_version]};
 }
 const snapshot=await decisionSnapshot(ctx,apiId,personId,guard);
 const result=evaluate(ctx,snapshot,data,principal);
 await auditDetail(ctx,principal?.clientId??personId,'resource_permission_check',apiId,{principal:principal?.id??personId,kind:machine?'service':'person',owner:principal?.ownerId??null,action:typeof data.action==='string'?data.action.slice(0,256):null,resource:typeof data.resource==='string'?data.resource.slice(0,256):typeof data.resource?.id==='string'?data.resource.id.slice(0,256):null,allowed:result.allowed,reason:result.reason??null});
 return json(result);
}

export async function grantAction(ctx,request,path,data) {
 path=actionPath(path);
 if(!ACTIONS.includes(path))fail('not_found',404);
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_request');
 if(path===prefix+'/check')return grantCheck(ctx,request,data);
 origin(ctx,request);
 const {s,guard}=await configuration(ctx,request,path,data);
 const log=(event,id,detail)=>auditDetail(ctx,s.person_id,event,id,detail);
 const committed=async(sql,...args)=>{
  const result=await run(ctx,sql,...args);
  if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('resource_config_changed',409);}
  return result;
 };
 if(path===prefix+'/register') {
  const appId=identifier(data.appId,'invalid_app_id'),name=label(data.name,120,'invalid_api_name'),audience=identifier(data.audience,'invalid_api_audience');
  // The namespace must be distinct from Auth administration and identity endpoints.
  if(audience===ctx.origin||audience===(ctx.issuer??ctx.origin)||audience.includes('/api/auth/admin')||audience===CLIENT_PREFIX)fail('invalid_api_audience');
  const policy=policySettings(data,organization(ctx)),id=data.apiId===undefined?random():identifier(data.apiId,'invalid_api_id');
  const current=await apiRow(ctx,id);
  if(data.apiId!==undefined&&!current)fail('api_not_found',404);
  if(current&&current.app_id!==appId)fail('api_app_binding_immutable',409);
  const appGuard='EXISTS(SELECT 1 FROM auth_apps target_app WHERE target_app.id=? AND target_app.disabled_at IS NULL)';
  const unique='NOT EXISTS(SELECT 1 FROM auth_resource_apis conflict_api WHERE conflict_api.audience=? AND conflict_api.id!=?)';
  if(current) {
   await committed(`UPDATE auth_resource_apis SET name=?,audience=?,policy=?,revision=revision+1,updated_at=? WHERE id=? AND revision=? AND ${guard.clause} AND ${appGuard} AND ${unique}`,name,audience,JSON.stringify(policy),ctx.now(),id,current.revision,...guard.args,appId,audience,id);
  } else {
   await committed(`INSERT INTO auth_resource_apis(id,app_id,name,audience,policy,created_by,created_at,updated_at) SELECT ?,?,?,?,?,?,?,? WHERE ${guard.clause} AND ${appGuard} AND ${unique}`,id,appId,name,audience,JSON.stringify(policy),s.person_id,ctx.now(),ctx.now(),...guard.args,appId,audience,id);
  }
  await log('resource_api_registered',id,{appId,audience,revision:(current?.revision??0)+1});
  return json({id,apiId:id,appId,audience,revision:(current?.revision??0)+1},current?200:201);
 }
 if(path===prefix+'/assign') {
  const api=await apiRow(ctx,identifier(data.apiId,'invalid_api_id'))||fail('api_not_found',404);
  if(data.remove!==undefined&&typeof data.remove!=='boolean')fail('invalid_assignment_removal');
  const principalType=data.principalType??data.type,principalId=data.principalId??data.personId??data.groupId;
  if(!['person','group'].includes(principalType))fail('invalid_principal_type');
  identifier(principalId,'invalid_principal_id');
  if(!data.remove&&!JSON.parse(api.policy).roles.some(r=>r.role===data.role))fail('unknown_api_role');
  const apiGuard={clause:`${guard.clause} AND EXISTS(SELECT 1 FROM auth_resource_apis current_api JOIN auth_apps current_app ON current_app.id=current_api.app_id WHERE current_api.id=? AND current_api.revision=? AND current_app.disabled_at IS NULL)`,args:[...guard.args,api.id,api.revision]};
  // Reuse the native workforce command, including audit/events and SCIM queue.
  return workforceCommand(ctx,{kind:'human',actorId:s.person_id,guard:apiGuard,assertAuthority:()=>requireAuthority(ctx,s,apiGuard)},data.remove?'/company-apps/unassign':'/company-apps/assign',{appId:api.app_id,principalType,principalId,role:data.role});
 }
 if(path===prefix+'/service-create') {
  const api=await apiRow(ctx,identifier(data.apiId,'invalid_api_id'))||fail('api_not_found',404),settings=serviceSettings(ctx,data,JSON.parse(api.policy)),keys=await publicKeys(data.jwks);
  const owner=await one(ctx,"SELECT id,version FROM oa_operators WHERE id=? AND status='active'",settings.ownerId)||fail('invalid_service_owner');
  const id=random(),clientId=CLIENT_PREFIX+id;
  const liveApi="EXISTS(SELECT 1 FROM auth_resource_apis target_api JOIN auth_apps target_app ON target_app.id=target_api.app_id WHERE target_api.id=? AND target_api.revision=? AND target_app.disabled_at IS NULL)";
  await committed(`INSERT INTO auth_resource_services(id,client_id,api_id,name,purpose,owner_id,owner_version,jwks,scopes,resources,created_by,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause} AND ${liveApi} AND EXISTS(SELECT 1 FROM oa_operators target_owner WHERE target_owner.id=? AND target_owner.version=? AND target_owner.status='active')`,id,clientId,api.id,settings.name,settings.purpose,owner.id,owner.version,JSON.stringify(keys),JSON.stringify(settings.scopes),JSON.stringify(settings.resources),s.person_id,ctx.now(),settings.expiresAt,...guard.args,api.id,api.revision,owner.id,owner.version);
  await log('resource_service_created',id,{clientId,apiId:api.id,owner:owner.id,scopes:settings.scopes,resources:settings.resources,expiresAt:settings.expiresAt,purpose:settings.purpose});
  return json({id,clientId,apiId:api.id,audience:api.audience,ownerId:owner.id,expiresAt:settings.expiresAt,tokenEndpoint:(ctx.issuer??ctx.origin)+'/oidc/token',tokenEndpointAuthMethod:'private_key_jwt'},201);
 }
 const clientId=identifier(data.clientId,'invalid_service_client');
 await committed(`UPDATE auth_resource_services SET revoked_at=?,revoked_by=?,revision=revision+1 WHERE client_id=? AND revoked_at IS NULL AND ${guard.clause}`,ctx.now(),s.person_id,clientId,...guard.args);
 await log('resource_service_revoked',clientId,{});
 return json({ok:true});
}

export async function grantModel(ctx) {
 const [apis,services]=await Promise.all([
  all(ctx,'SELECT * FROM auth_resource_apis ORDER BY name'),
  all(ctx,'SELECT id,client_id,api_id,name,purpose,owner_id,owner_version,scopes,resources,revision,created_at,expires_at,revoked_at,last_used_at FROM auth_resource_services ORDER BY created_at DESC'),
 ]);
 return {organizationId:organization(ctx),configurationAuthority:'scoped-hardware-administration',apis:apis.map(a=>({id:a.id,appId:a.app_id,name:a.name,audience:a.audience,...JSON.parse(a.policy),revision:a.revision})),services:services.map(a=>({id:a.id,clientId:a.client_id,apiId:a.api_id,name:a.name,purpose:a.purpose,ownerId:a.owner_id,ownerVersion:a.owner_version,scopes:JSON.parse(a.scopes),resources:JSON.parse(a.resources),revision:a.revision,createdAt:a.created_at,expiresAt:a.expires_at,revokedAt:a.revoked_at,lastUsedAt:a.last_used_at}))};
}
export async function grantRead(ctx,request,path) {
 if(actionPath(path)!==prefix)fail('not_found',404);
 return json(await configurationView(ctx,request,await grantModel(ctx)));
}
