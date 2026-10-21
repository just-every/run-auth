import {fail,one,hash} from '../core.mjs';
import {validateExpression,evaluateExpression} from './language.mjs';
import {mappingDirectory} from './context.mjs';
export const RESERVED=new Set(['sub','iss','aud','exp','iat','nbf','jti','nonce','sid','auth_time','amr','acr','at_hash','c_hash','email_verified','email_verified_at']);
const SCIM=new Set(['userName','displayName','title','department','costCenter','employeeNumber','name.givenName','name.familyName','name.formatted']);
const parse=value=>{try{return typeof value==='string'?JSON.parse(value):value;}catch{fail('mapping_invalid_program');}};
export function validateProgram(raw,schema) {
 const p=parse(raw);
 if(!p||p.language!==1||Object.keys(p).some(k=>!['language','nameId','username','saml','oidc','scim'].includes(k)))fail('mapping_invalid_program');
 for(const key of ['nameId','username'])if(p[key]!==undefined){const spec=p[key];if(!spec||Object.keys(spec).some(k=>!['expression','unique'].includes(k))||spec.unique!==undefined&&typeof spec.unique!=='boolean')fail('mapping_invalid_program');if(!['text','null','person','choice','date'].includes(validateExpression(spec.expression,schema)))fail('mapping_type');}
 for(const key of ['saml','oidc','scim'])if(p[key]!==undefined){
  if(!p[key]||Array.isArray(p[key])||typeof p[key]!=='object'||Object.keys(p[key]).length>32)fail('mapping_invalid_program');
  for(const [name,expr] of Object.entries(p[key])){
   if(!/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/.test(name)||['__proto__','constructor','prototype'].includes(name)||key==='oidc'&&RESERVED.has(name)||key==='scim'&&!SCIM.has(name))fail('mapping_forbidden_target');
   const type=validateExpression(expr,schema);if(key==='scim'&&!['text','date','person','choice','null'].includes(type))fail('mapping_type');
  }
 }
 if(JSON.stringify(p).length>16384)fail('mapping_budget');return p;
}
export async function activeProgram(ctx,appId) {
 const row=await one(ctx,'SELECT v.program FROM auth_mapping_versions v JOIN auth_apps a ON a.id=v.app_id AND a.mapping_version=v.version WHERE a.id=? AND a.disabled_at IS NULL',appId);
 return row?JSON.parse(row.program):null;
}
const empty=v=>v===null||v===undefined||v===''||Array.isArray(v)&&!v.length;
// Allocate against the entire directory, never only the preview selection.
function uniqueValues(rows,key,spec) {
 if(!spec)return;
 const groups=new Map();for(const row of rows){const value=row.values[key];if(empty(value)){row.warnings.push(key+':empty');continue;}const list=groups.get(value)??[];list.push(row);groups.set(value,list);}
 const used=new Set(groups.keys());
 for(const [value,group] of groups)if(group.length>1)for(const row of group){row.warnings.push(key+':duplicate');if(spec.unique){let n=1,next;do{next=value+'-'+n++;}while(used.has(next));used.add(next);row.values[key]=next;}}
}
export function evaluateProgram(p,directory) {
 const rows=[...directory.dir.people.values()].sort((a,b)=>a.id.localeCompare(b.id)).map(person=>{
  const context=directory.context(person),values={saml:{},oidc:{},scim:{}};
  for(const key of ['nameId','username'])if(p[key])values[key]=evaluateExpression(p[key].expression,context);
  for(const key of ['saml','oidc','scim'])for(const [name,expr] of Object.entries(p[key]??{}))values[key][name]=evaluateExpression(expr,context);
  const warnings=[];for(const key of ['saml','oidc','scim'])for(const [name,value] of Object.entries(values[key]))if(empty(value))warnings.push(key+'.'+name+':empty');
  return {personId:person.id,email:person.email,values,warnings};
 });
 for(const kind of ['saml','oidc','scim'])for(const key of Object.keys(p[kind]??{})){
  const seen=new Map();for(const row of rows){const v=row.values[kind][key];if(empty(v))continue;const fingerprint=JSON.stringify(v),previous=seen.get(fingerprint);if(previous){const warning=kind+'.'+key+':duplicate';if(!previous.warnings.includes(warning))previous.warnings.push(warning);row.warnings.push(warning);}else seen.set(fingerprint,row);}
 }
 uniqueValues(rows,'nameId',p.nameId);uniqueValues(rows,'username',p.username);return rows;
}
export async function computedValues(ctx,appId,personId) {
 const p=await activeProgram(ctx,appId);if(!p)return null;
 const d=await mappingDirectory(ctx);validateProgram(p,d.schema);
 const row=evaluateProgram(p,d).find(r=>r.personId===personId);if(!row)fail('mapping_person_not_found');
 for(const key of ['nameId','username'])if(p[key]&&(empty(row.values[key])||!p[key].unique&&row.warnings.includes(key+':duplicate')))fail('mapping_empty_or_duplicate');
 return row.values;
}
export const previewDigest=(version,program,rows)=>hash(JSON.stringify({version,program,rows}));
export const scimValues=values=>{
 const out={};for(const [key,value] of Object.entries(values??{})){if(value===null||value===undefined)continue;const parts=key.split('.');if(parts.length===2)(out[parts[0]]??={})[parts[1]]=value;else out[key]=value;}return out;
};
