// RER Managed trust: which RER account keys may sign link approvals for this
// install. Provisioned keys arrive in the RER_LINK_APPROVAL_KEYS binding (set by
// RER when it installed Auth); an owner can add one on Sign-in methods with a
// passkey and fresh email proof (adoption). Withdrawal ends a key for good: by
// an administrator here, or by RER itself when the account leaves Managed.
import {createLocalJWKSet,jwtVerify} from 'jose';
import {all,run,fail,json,requireSession,auditDetail} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {readBody} from './app.mjs';

export const WITHDRAW='/oidc/link/rer-trust/withdraw';
const KID=/^[A-Za-z0-9_-]{8,128}$/;
function publicKey(value) {
 const k=value&&typeof value==='object'?value:null;
 if(!k||k.kty!=='EC'||k.crv!=='P-256'||typeof k.x!=='string'||typeof k.y!=='string'||'d' in k||!KID.test(k.kid||''))fail('invalid_rer_key');
 return {kty:'EC',crv:'P-256',x:k.x,y:k.y,kid:k.kid,alg:'ES256',use:'sig'};
}
function provisioned(ctx) {
 if(!ctx.rerTrustKeys)return [];
 let keys;try{keys=JSON.parse(ctx.rerTrustKeys);}catch{return [];}
 return keys&&typeof keys==='object'&&!Array.isArray(keys)?Object.entries(keys).flatMap(([kid,key])=>{try{return [publicKey({...key,kid})];}catch{return [];}}):[];
}
// Every key with its state, for the Sign-in methods page and for verification.
// A withdrawal restored from an archive may name a key this install never held.
export async function rerTrust(ctx) {
 const [rows,withdrawals]=await Promise.all([all(ctx,'SELECT kid,public_jwk,added_at FROM auth_rer_trust'),all(ctx,'SELECT kid,source,withdrawn_at FROM auth_rer_withdrawals')]);
 const withdrawn=new Map(withdrawals.map(w=>[w.kid,w.withdrawn_at]));
 const keys=[...provisioned(ctx).map(key=>({kid:key.kid,key,source:'provisioned',added_at:null})),...rows.map(r=>({kid:r.kid,key:JSON.parse(r.public_jwk),source:'owner',added_at:r.added_at}))].map(k=>({...k,withdrawn_at:withdrawn.get(k.kid)??null}));
 for(const w of withdrawals)if(!keys.some(k=>k.kid===w.kid))keys.push({kid:w.kid,key:null,source:w.source,added_at:null,withdrawn_at:w.withdrawn_at});
 return keys;
}
export const activeKeys=async ctx=>(await rerTrust(ctx)).filter(k=>!k.withdrawn_at).map(k=>k.key);

const ACTIONS=['/rer-trust/add','/rer-trust/withdraw'];
export const isTrustAction=path=>ACTIONS.includes(path);
export async function trustAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const guard=authority(ctx,s,['owner','admin']);
 if(path==='/rer-trust/add') {
  let parsed;try{parsed=typeof data.key==='string'?JSON.parse(data.key):data.key;}catch{fail('invalid_rer_key');}
  const key=publicKey(parsed);
  if((await rerTrust(ctx)).some(k=>k.kid===key.kid))fail('rer_key_known',409);
  const added=await run(ctx,`INSERT INTO auth_rer_trust(kid,public_jwk,source,added_by,added_at) SELECT ?,?,'owner',?,? WHERE NOT EXISTS(SELECT 1 FROM auth_rer_withdrawals WHERE kid=?) AND ${guard.clause}`,key.kid,JSON.stringify(key),s.person_id,ctx.now(),key.kid,...guard.args);
  if(!added.meta.changes){await requireAuthority(ctx,s,guard);fail('rer_key_known',409);}
  await auditDetail(ctx,s.person_id,'rer_trust_added',null,{kid:key.kid});
  return json({trusted:true,kid:key.kid},201);
 }
 const kid=String(data.kid||''),known=(await rerTrust(ctx)).find(k=>k.kid===kid&&!k.withdrawn_at)||fail('rer_key_not_found',404);
 const withdrawn=await run(ctx,`INSERT INTO auth_rer_withdrawals(kid,source,withdrawn_by,withdrawn_at) SELECT ?,?,?,? WHERE ${guard.clause} ON CONFLICT(kid) DO NOTHING`,kid,known.source,s.person_id,ctx.now(),...guard.args);
 if(!withdrawn.meta.changes){await requireAuthority(ctx,s,guard);fail('rer_key_not_found',404);}
 await auditDetail(ctx,s.person_id,'rer_trust_withdrawn',null,{kid});
 return json({withdrawn:true,kid});
}

// RER leaving Managed: it signs the withdrawal with the key itself (aud = this URL).
export async function withdrawBySignature(ctx,request) {
 const data=await readBody(request),kid=String(data.kid||'');
 const known=(await rerTrust(ctx)).find(k=>k.kid===kid&&!k.withdrawn_at)||fail('rer_key_not_found',404);
 let claims;try{({payload:claims}=await jwtVerify(String(data.assertion||''),createLocalJWKSet({keys:[known.key]}),{audience:ctx.origin+WITHDRAW,algorithms:['ES256'],currentDate:new Date(ctx.now()),requiredClaims:['iat','exp','jti']}));}catch{fail('invalid_rer_assertion',401);}
 if(claims.exp-claims.iat>300)fail('invalid_rer_assertion',401);
 try{await run(ctx,'INSERT INTO auth_rer_approvals(jti,kid,expires_at) VALUES(?,?,?)',claims.jti,kid,claims.exp*1000);}catch{fail('invalid_rer_assertion',401);}
 await run(ctx,"INSERT INTO auth_rer_withdrawals(kid,source,withdrawn_by,withdrawn_at) VALUES(?,?,'rer',?) ON CONFLICT(kid) DO NOTHING",kid,known.source,ctx.now());
 await auditDetail(ctx,null,'rer_trust_withdrawn_by_rer',null,{kid});
 return json({withdrawn:true,kid});
}
export const rerTrustModel=async ctx=>(await rerTrust(ctx)).map(({kid,source,added_at,withdrawn_at})=>({kid,source,added_at,withdrawn_at}));
