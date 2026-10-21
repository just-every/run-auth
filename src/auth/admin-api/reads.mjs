// Machine reads use explicit projections; interactive administration models also
// contain authority and credential state and must never be serialized here.
import {all,json,fail} from '../core.mjs';
import {definitions,valuesByPerson,effective} from '../workforce/people/fields.mjs';
import {configuredProvider} from '../domain-policy.mjs';
import {SCOPES} from './credentials/config.mjs';

const families=new Set(['people','groups','apps','assignments','policies','idps','domains','logs']);
const scopeFor=(p,family)=>{
 const read=p.scopes.includes(family+'.read'),manage=!['domains','logs'].includes(family)&&p.scopes.includes(family+'.manage');
 if(!read&&!manage)fail('admin_service_scope_required',403);
};
const integer=(params,key,initial,min,max)=>{
 const raw=params.get(key);if(raw===null)return initial;
 if(!/^(0|[1-9]\d*)$/.test(raw))fail('invalid_pagination');
 const value=Number(raw);if(!Number.isSafeInteger(value)||value<min||value>max)fail('invalid_pagination');return value;
};
function page(items,url) {
 const limit=integer(url.searchParams,'limit',25,1,100),offset=integer(url.searchParams,'offset',0,0,Number.MAX_SAFE_INTEGER);
 return {items:items.slice(offset,offset+limit),total:items.length,nextOffset:offset+limit<items.length?offset+limit:null};
}
const found=row=>row??fail('not_found',404);
const permitted=(p,kind,id)=>{if(!p.permits(kind,id))fail('not_found',404);};
const parse=value=>value===null?null:JSON.parse(value);

async function people(ctx,p,id,groupId) {
 if(id)permitted(p,'people',id);
 const [rows,defs,fields]=await Promise.all([
  all(ctx,`SELECT p.id,p.email,p.display_name AS name,p.status,d.terminated_at FROM oa_operators p LEFT JOIN auth_people d ON d.person_id=p.id ${groupId?'JOIN auth_group_members m ON m.person_id=p.id WHERE m.group_id=?':''} ORDER BY p.email,p.id`,...(groupId?[groupId]:[])),
  definitions(ctx),valuesByPerson(ctx),
 ]);
 const items=rows.filter(r=>p.permits('people',r.id)&&(!id||id===r.id)).map(r=>{
  const values=effective(fields.get(r.id),defs),profile={};
  for(const [key,spec] of defs)if(Object.hasOwn(values,key)&&(spec.type!=='person'||p.permits('people',values[key])))profile[key]=values[key];
  return {id:r.id,email:r.email,name:profile.name??r.name,state:r.status==='invited'?'invited':r.status==='active'?'active':r.terminated_at?'terminated':'suspended',profile};
 });
 return id?found(items[0]):items;
}

async function groups(ctx,p,id) {
 if(id)permitted(p,'groups',id);
 const rows=await all(ctx,'SELECT id,name,rule FROM auth_groups ORDER BY name,id');
 const items=rows.filter(r=>p.permits('groups',r.id)).map(r=>({id:r.id,name:r.name,rule:parse(r.rule)}));
 return id?found(items.find(r=>r.id===id)):items;
}

async function apps(ctx,p,id) {
 if(id)permitted(p,'apps',id);
 // Neither secret digests nor public/private signing key material are read.
 const rows=await all(ctx,`SELECT a.id,a.name,a.protocol,a.recipe,a.launch_url,a.entity_id,a.acs,a.slo,a.name_id_format,a.name_id_source,a.sign,a.digest,a.sha1_exception,a.encryption,a.want_requests_signed,a.idp_initiated,a.relay_state,a.attributes,
  c.client_id,c.auth_method,c.redirect_uris,c.post_logout_redirect_uris,c.require_pkce,c.subject_type,c.legacy_flows,c.frontchannel_logout_uri,c.backchannel_logout_uri,c.id_token_alg
  FROM auth_apps a LEFT JOIN auth_oidc_clients c ON c.app_id=a.id WHERE a.disabled_at IS NULL ORDER BY a.name,a.id`);
 const items=rows.filter(r=>p.permits('apps',r.id)).map(r=>({id:r.id,name:r.name,protocol:r.protocol,recipe:r.recipe,launchUrl:r.launch_url,attributes:parse(r.attributes),
  ...(r.protocol==='oidc'?{clientId:r.client_id,authMethod:r.auth_method,redirectUris:parse(r.redirect_uris),postLogoutRedirectUris:parse(r.post_logout_redirect_uris),requirePkce:Boolean(r.require_pkce),subjectType:r.subject_type,legacyFlows:Boolean(r.legacy_flows),frontchannelLogoutUri:r.frontchannel_logout_uri,backchannelLogoutUri:r.backchannel_logout_uri,idTokenAlg:r.id_token_alg}
   :{entityId:r.entity_id,acs:parse(r.acs),slo:parse(r.slo),nameIdFormat:r.name_id_format,nameIdSource:r.name_id_source,sign:r.sign,digest:r.digest,sha1Exception:Boolean(r.sha1_exception),encryption:r.encryption,wantRequestsSigned:Boolean(r.want_requests_signed),idpInitiated:Boolean(r.idp_initiated),relayState:r.relay_state})}));
 return id?found(items.find(r=>r.id===id)):items;
}

// Business events only: credential, factor, recovery, role, key and service-app
// lifecycle records are deliberately absent, even if their detail looks safe.
const auditKinds={
 people:['person_invited','person_onboarded','person_suspended','person_restored','person_terminated','person_rehired','directory_person_updated','directory_conflict_resolved'],
 groups:['group_created','group_deleted','group_member_added','group_member_removed','group_rule_set','group_rule_cleared'],
 apps:['company_app_created','company_app_updated','company_app_removed','catalog_app_added','oidc_app_created','app_assigned','app_unassigned'],
 policies:['domain_provider_required','domain_provider_removed'],domains:['domain_allowed'],
};
const eventKinds=new Map(Object.entries(auditKinds).flatMap(([kind,events])=>events.map(event=>[event,kind])));
const requestEvents=['admin_api_call'];
function requestAudit(row,p) {
 let detail;try{detail=JSON.parse(row.detail);}catch{return null;}
 // Request subjects are relative REST paths. Refuse unknown/excluded surfaces
 // and require all resource kinds to be unrestricted for collection requests.
 const path=String(detail?.path??'').split('?')[0],parts=path.split('/').filter(Boolean),family=parts[0];
 if(!families.has(family)||family==='logs')return null;
 if(['people','groups','apps'].includes(family)) {
  if(parts[1]?!p.permits(family,parts[1]):!p.resources[family]?.includes('*'))return null;
  if(parts.length>2&&!(family==='groups'&&parts[2]==='rule'&&parts.length===3)&&!(family==='groups'&&parts[2]==='members'&&parts.length<=4&&(!parts[3]||p.permits('people',parts[3]))))return null;
 }else if(family==='assignments') {
  if(parts.length===1&&!['people','groups','apps'].every(k=>p.resources[k]?.includes('*')))return null;
  if(parts.length>1&&(parts.length!==4||!['person','group'].includes(parts[2])||!p.permits('apps',parts[1])||!p.permits(parts[2]==='person'?'people':'groups',parts[3])))return null;
 }else if(family==='policies'?parts.length>2:parts.length>1)return null;
 const safe={};
 for(const key of ['serviceApp','owner'])if(typeof detail?.[key]==='string'&&detail[key].length<=256)safe[key]=detail[key];
 if(typeof detail?.scope==='string')safe.scope=detail.scope.split(/\s+/).filter(s=>SCOPES.includes(s)).join(' ');
 if(typeof detail?.result==='number'&&Number.isInteger(detail.result)&&detail.result>=100&&detail.result<600)safe.result=detail.result;
 else if(typeof detail?.result==='string'&&/^[a-z][a-z0-9_]{0,79}$/.test(detail.result))safe.result=detail.result;
 return {subject:row.subject_id,detail:safe};
}
async function logs(ctx,p) {
 const events=[...eventKinds.keys(),...requestEvents];
 const rows=await all(ctx,`SELECT a.id,a.event,a.subject_id,a.created_at,d.detail FROM auth_activity a LEFT JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event IN (${events.map(()=>'?').join(',')}) ORDER BY a.id DESC`,...events);
 return rows.flatMap(row=>{
  const kind=eventKinds.get(row.event);let request;
  if(kind&&['people','groups','apps'].includes(kind)&&!p.permits(kind,row.subject_id))return [];
  if(!kind){request=requestAudit(row,p);if(!request)return [];}
  return [{id:row.id,event:row.event,subject:request?.subject??row.subject_id,time:row.created_at,...(request?{detail:request.detail}:{})}];
 });
}

// Called only for GET by the REST router. Unknown routes remain the router's 404.
export async function readAdmin(ctx,principal,path,url) {
 const parts=path.split('/').filter(Boolean),family=parts[0];
 if(!families.has(family)||!/^\/(people|groups|apps|assignments|policies|idps|domains|logs)(?:\/[^/]+)?(?:\/members)?$/.test(path))return null;
 if(parts.length>1&&!['people','groups','apps'].includes(family)||parts.length===3&&(family!=='groups'||parts[2]!=='members'))return null;
 scopeFor(principal,family);
 const id=parts[1];let value;
 if(family==='people')value=await people(ctx,principal,id);
 if(family==='groups') {
  value=await groups(ctx,principal,id);
  if(parts[2]==='members')value=await people(ctx,principal,null,id);
 }
 if(family==='apps')value=await apps(ctx,principal,id);
 if(family==='assignments') {
  const rows=await all(ctx,'SELECT app_id,principal_type,principal_id,role FROM auth_app_assignments ORDER BY app_id,principal_type,principal_id');
  value=rows.filter(r=>principal.permits('apps',r.app_id)&&principal.permits(r.principal_type==='person'?'people':'groups',r.principal_id)).map(r=>({appId:r.app_id,principalType:r.principal_type,principalId:r.principal_id,role:r.role}));
 }
 if(family==='policies')value=(await all(ctx,'SELECT domain,provider_id FROM oa_domain_rules ORDER BY domain')).map(r=>({domain:r.domain,providerId:r.provider_id,available:Boolean(configuredProvider(ctx,r.provider_id))}));
 if(family==='idps')value=(ctx.configuredUpstreamProviders??ctx.upstreamProviders??[]).map(r=>({id:r.id,label:r.label||r.preset,preset:r.preset,available:Boolean(configuredProvider(ctx,r.id))})).sort((a,b)=>a.id.localeCompare(b.id));
 if(family==='domains')value=(await all(ctx,'SELECT domain,created_at FROM auth_domains ORDER BY domain')).map(r=>({domain:r.domain,createdAt:r.created_at}));
 if(family==='logs')value=await logs(ctx,principal);
 await principal.assertAuthority();
 return json(Array.isArray(value)?page(value,url):value);
}
