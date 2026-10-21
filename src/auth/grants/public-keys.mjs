import {importJWK} from 'jose';
import {fail,unb64} from '../core.mjs';

export async function publicKeys(value) {
 if(!value||!Array.isArray(value.keys)||!value.keys.length||value.keys.length>5)fail('invalid_service_jwks');
 const kids=new Set(),keys=[];
 for(const key of value.keys) {
  if(!key||typeof key!=='object'||['d','p','q','dp','dq','qi','oth','k'].some(k=>Object.hasOwn(key,k)))fail('invalid_service_jwks');
  const alg=key.alg??(key.kty==='RSA'?'RS256':'ES256');
  if(!['ES256','RS256'].includes(alg)||key.use&&key.use!=='sig'||key.key_ops&&(!Array.isArray(key.key_ops)||key.key_ops.some(v=>v!=='verify')))fail('invalid_service_jwks');
  if(alg==='ES256'&&(key.kty!=='EC'||key.crv!=='P-256')||alg==='RS256'&&key.kty!=='RSA')fail('invalid_service_jwks');
  if(typeof key.kid!=='string'||!key.kid||key.kid.length>128||kids.has(key.kid))fail('invalid_service_jwks');
  kids.add(key.kid);
  const fields=alg==='ES256'?['crv','x','y']:['n','e'];
  if(fields.some(f=>typeof key[f]!=='string'||!key[f]||key[f].length>2048))fail('invalid_service_jwks');
  const safe={kty:key.kty,alg,kid:key.kid,use:'sig',...Object.fromEntries(fields.map(f=>[f,key[f]]))};
  try {
   if(alg==='RS256'){const n=unb64(safe.n);if(n.length<256||n.length>1024||n.length===256&&n[0]<128)fail('invalid_service_jwks');}
   else if(unb64(safe.x).length!==32||unb64(safe.y).length!==32)fail('invalid_service_jwks');
   await importJWK(safe,alg);
  }catch{fail('invalid_service_jwks');}
  keys.push(safe);
 }
 return {keys};
}
