import {DAY,fail} from '../core.mjs';

export const CLIENT_PREFIX='resource-service:';
export const identifier=(value,code='invalid_identifier')=>{
 if(typeof value!=='string'||!value||value.length>256||/[\s\x00-\x1f]/.test(value))fail(code);
 return value;
};
export const label=(value,max,code)=>{
 if(typeof value!=='string'||!value.trim()||value.length>max)fail(code);
 return value.trim();
};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export function list(value,code,max=100) {
 if(!Array.isArray(value)||!value.length||value.length>max)fail(code);
 return [...new Set(value.map(v=>identifier(v,code)))];
}
function attributes(value,code) {
 if(value===undefined)return {};
 if(!object(value)||Object.keys(value).length>30)fail(code);
 const result={};
 for(const [key,v] of Object.entries(value)) {
  identifier(key,code);
  if(!['string','number','boolean'].includes(typeof v)||String(v).length>256||typeof v==='number'&&!Number.isFinite(v))fail(code);
  Object.defineProperty(result,key,{value:String(v),enumerable:true});
 }
 return result;
}
export function policySettings(data,organizationId) {
 const scopes=list(data.scopes,'invalid_api_scopes');
 if(!Array.isArray(data.roles)||!data.roles.length||data.roles.length>100)fail('invalid_api_roles');
 const roles=data.roles.map(r=>{
  if(!object(r))fail('invalid_api_roles');
  const role=identifier(r.role,'invalid_api_roles'),allowed=list(r.scopes,'invalid_api_roles');
  if(role.length>80)fail('invalid_api_roles');
  if(allowed.some(s=>!scopes.includes(s)))fail('invalid_api_roles');
  const relations=attributes(r.relations,'invalid_api_relations');
  if(Object.values(relations).some(v=>v!=='$person'&&!/^\$attribute:[a-z][a-z0-9_.]{0,63}$/.test(v)))fail('invalid_api_relations');
  return {role,scopes:allowed,resources:list(r.resources??['*'],'invalid_api_resources',500),attributes:attributes(r.attributes,'invalid_api_attributes'),relations};
 });
 if(new Set(roles.map(r=>r.role)).size!==roles.length)fail('duplicate_api_role');
 if(!Array.isArray(data.resources)||data.resources.length>500)fail('invalid_api_resources');
 const resources=data.resources.map(r=>{
  if(!object(r)||r.organizationId!==undefined&&r.organizationId!==organizationId)fail('invalid_api_resources');
  return {id:identifier(r.id,'invalid_api_resources'),attributes:attributes(r.attributes,'invalid_api_attributes')};
 });
 if(new Set(resources.map(r=>r.id)).size!==resources.length)fail('duplicate_api_resource');
 return {scopes,roles,resources};
}
export function serviceSettings(ctx,data,policy) {
 const scopes=list(data.scopes,'invalid_service_scopes');
 if(scopes.some(s=>!policy.scopes.includes(s)))fail('invalid_scope');
 const expiresAt=typeof data.expiresAt==='string'?Date.parse(data.expiresAt):data.expiresAt;
 if(!Number.isSafeInteger(expiresAt)||expiresAt<=ctx.now()||expiresAt>ctx.now()+365*DAY)fail('invalid_service_expiry');
 const resources=list(data.resources,'invalid_service_resources',500);
 if(resources.some(pattern=>!policy.resources.some(r=>matchesResource(pattern,r.id))))fail('invalid_service_resources');
 return {name:label(data.name,120,'invalid_service_name'),purpose:label(data.purpose,1000,'invalid_service_purpose'),ownerId:identifier(data.ownerId,'invalid_service_owner'),scopes,resources,expiresAt};
}
export const matchesResource=(pattern,id)=>pattern==='*'||pattern.endsWith('*')?id.startsWith(pattern.slice(0,-1)):pattern===id;
