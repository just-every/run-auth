import {fail} from '../core.mjs';

export const POINTS=['token','saml','registration','user_import','password_import'];
const RESERVED=new Set(['iss','sub','subject','subject_id','personid','person_id','nameid','name_id','aud','exp','iat','nbf','jti','nonce','sid','amr','acr','auth_time','at_hash','c_hash','email','email_verified','email_verified_at','name','role','roles','groups','permissions','scope','scopes','admin','administrator','isadmin','is_admin','install_owner','mfa','required_mfa','policy','allow','deny','__proto__','prototype','constructor']);
export const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const only=(value,keys)=>object(value)&&Object.keys(value).every(k=>keys.includes(k));
export function allowedFields(value=[]) {
 if(!Array.isArray(value)||value.length>32||value.some(k=>typeof k!=='string'||! /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(k)||RESERVED.has(k.toLowerCase())))fail('invalid_hook_fields');
 return [...new Set(value)];
}
const text=(value,max)=>typeof value==='string'&&value.length<=max;
const scalar=value=>typeof value==='boolean'||(typeof value==='number'&&Number.isFinite(value))||text(value,2048);
function fields(value,allowed,saml) {
 if(!object(value)||Object.keys(value).length>32)fail('hook_invalid_response',403);
 for(const [key,item] of Object.entries(value)) {
  if(!allowed.includes(key)||RESERVED.has(key.toLowerCase()))fail('hook_invalid_response',403);
  const valid=saml?text(item,2048)||(Array.isArray(item)&&item.length<=32&&item.every(v=>text(v,2048))):scalar(item)||(Array.isArray(item)&&item.length<=32&&item.every(scalar));
  if(!valid)fail('hook_invalid_response',403);
 }
 return value;
}
export function validateOutput(point,value,allowed) {
 if(point==='token'||point==='saml') {
  const key=point==='token'?'claims':'attributes';
  if(!only(value,[key])||!Object.hasOwn(value,key))fail('hook_invalid_response',403);
  return {[key]:fields(value[key],allowed,point==='saml')};
 }
 if(!only(value,['allow','profile'])||typeof value.allow!=='boolean')fail('hook_invalid_response',403);
 if(Object.hasOwn(value,'profile')&&(!only(value.profile,['name'])||!allowed.includes('name')||!text(value.profile.name,160)||!value.profile.name.trim()))fail('hook_invalid_response',403);
 if(!value.allow)fail('hook_refused',403);
 return {allow:true,...(value.profile?{profile:{name:value.profile.name.trim()}}:{})};
}
// Construct a new object instead of forwarding caller objects, claims or secrets.
export function minimalPayload(point,payload) {
 const keys=point==='token'?['personId','appId','clientId']:point==='saml'?['personId','appId']:point==='registration'?['email','name']:point==='user_import'?['sourceId','email','name']:['personId','sourceId'];
 return Object.fromEntries(keys.filter(k=>text(payload[k],k==='name'?160:320)).map(k=>[k,payload[k]]));
}
export function registrationFields(point,value=[]) {
 if(['registration','user_import'].includes(point)) {
  if(!Array.isArray(value)||value.some(k=>k!=='name'))fail('invalid_hook_fields');
  return [...new Set(value)];
 }
 if(point==='password_import') {
  if(!Array.isArray(value)||value.length)fail('invalid_hook_fields');
  return [];
 }
 return allowedFields(value);
}
