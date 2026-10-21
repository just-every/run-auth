import {importJWK} from 'jose';
import {DAY,fail,unb64} from '../../core.mjs';
import {allowedIps} from './ip.mjs';

export const CLIENT_PREFIX='auth-admin-service:';
export const SCOPES=Object.freeze(['people.read','people.manage','groups.read','groups.manage','apps.read','apps.manage','assignments.read','assignments.manage','policies.read','policies.manage','idps.read','idps.manage','domains.read','logs.read']);
export const RESOURCE_KINDS=Object.freeze(['people','groups','apps']);
const text=(value,max,code)=>{if(typeof value!=='string')fail(code);const result=value.replace(/\s+/g,' ').trim();if(!result||result.length>max)fail(code);return result;};
export function resourceSettings(value) {
 if(value===undefined)return Object.fromEntries(RESOURCE_KINDS.map(k=>[k,['*']]));
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!RESOURCE_KINDS.includes(k)))fail('invalid_admin_service_resources');
 return Object.fromEntries(RESOURCE_KINDS.map(kind=>{
  const ids=Object.hasOwn(value,kind)?value[kind]:['*'];
  if(!Array.isArray(ids)||ids.length>500||ids.some(id=>typeof id!=='string'||!id||id.length>256||/[\s\x00-\x1f]/.test(id)))fail('invalid_admin_service_resources');
  const unique=[...new Set(ids)];if(unique.includes('*')&&unique.length!==1)fail('invalid_admin_service_resources');
  return [kind,unique];
 }));
}
async function publicKeys(value) {
 let parsed=value;
 if(typeof value==='string'){try{parsed=JSON.parse(value);}catch{fail('invalid_admin_service_jwks');}}
 if(!parsed||!Array.isArray(parsed.keys)||parsed.keys.length<1||parsed.keys.length>5)fail('invalid_admin_service_jwks');
 const keys=[],kids=new Set();
 for(const key of parsed.keys) {
  if(!key||typeof key!=='object'||Array.isArray(key)||['d','p','q','dp','dq','qi','oth','k'].some(k=>Object.hasOwn(key,k)))fail('invalid_admin_service_jwks');
  const alg=key.alg??(key.kty==='RSA'?'RS256':key.kty==='EC'?'ES256':null);
  if(!['RS256','ES256'].includes(alg)||alg==='RS256'&&key.kty!=='RSA'||alg==='ES256'&&(key.kty!=='EC'||key.crv!=='P-256')||key.use&&key.use!=='sig'||key.key_ops&&(!Array.isArray(key.key_ops)||key.key_ops.some(op=>op!=='verify')))fail('invalid_admin_service_jwks');
  if(key.kid!==undefined&&(typeof key.kid!=='string'||!key.kid||key.kid.length>128))fail('invalid_admin_service_jwks');
  if(parsed.keys.length>1&&!key.kid||key.kid&&kids.has(key.kid))fail('invalid_admin_service_jwks');
  if(key.kid)kids.add(key.kid);
  const fields=key.kty==='RSA'?['n','e']:['crv','x','y'];
  if(fields.some(k=>typeof key[k]!=='string'||!key[k]||key[k].length>2048))fail('invalid_admin_service_jwks');
  if(fields.filter(k=>k!=='crv').some(k=>!/^[A-Za-z0-9_-]+$/.test(key[k])))fail('invalid_admin_service_jwks');
  const safe={kty:key.kty,alg,use:'sig',...(key.kid?{kid:key.kid}:{}),...Object.fromEntries(fields.map(k=>[k,key[k]]))};
  try {
   if(alg==='RS256') {const n=unb64(safe.n);if(n.length<256||n.length>1024||n.length===256&&n[0]<128)fail('invalid_admin_service_jwks');}
   else if(unb64(safe.x).length!==32||unb64(safe.y).length!==32)fail('invalid_admin_service_jwks');
   await importJWK(safe,alg);
  }catch{fail('invalid_admin_service_jwks');}
  keys.push(safe);
 }
 return {keys};
}
export async function serviceSettings(ctx,data) {
 const name=text(data.name,80,'invalid_admin_service_name'),purpose=text(data.purpose,1000,'invalid_admin_service_purpose');
 const ownerId=text(data.ownerId,256,'invalid_admin_service_owner');
 if(!Array.isArray(data.scopes)||!data.scopes.length||data.scopes.some(s=>!SCOPES.includes(s)))fail('invalid_admin_service_scopes');
 const expiresAt=typeof data.expiresAt==='number'?data.expiresAt:typeof data.expiresAt==='string'?Date.parse(data.expiresAt):NaN;
 if(!Number.isSafeInteger(expiresAt)||expiresAt<=ctx.now()||expiresAt>ctx.now()+365*DAY)fail('invalid_admin_service_expiry');
 return {name,purpose,ownerId,jwks:await publicKeys(data.jwks),scopes:[...new Set(data.scopes)],resources:resourceSettings(data.resources),allowedIps:allowedIps(data.allowedIps),expiresAt};
}
export const permitsResource=(principal,kind,id)=>RESOURCE_KINDS.includes(kind)&&typeof id==='string'&&Boolean(principal.resources[kind]?.includes('*')||principal.resources[kind]?.includes(id));
