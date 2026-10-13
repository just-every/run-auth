// A link approval signed by RER Managed with a key this install trusts. It names
// this issuer (aud), lasts at most five minutes, is used once (jti), and binds the
// app's admitted origin and link public key. `claim` is honoured only for this
// install's owner. Auth still pulls the app and links only what was approved.
import {decodeProtectedHeader,createLocalJWKSet,jwtVerify} from 'jose';
import {one,run,fail} from '../core.mjs';
import {INTERFACE,pullApp,sameKey,linkKey} from './app.mjs';
import {link} from './handshake.mjs';
import {activeKeys} from './rer-trust.mjs';

export const APPROVAL_TYPE='rer-link-approval+jwt';
export async function rerApproval(ctx,origin,approval) {
 let header;try{header=decodeProtectedHeader(approval);}catch{fail('invalid_rer_approval',401);}
 const key=(await activeKeys(ctx)).find(k=>k.kid===header.kid);
 if(!key||header.alg!=='ES256'||header.typ!==APPROVAL_TYPE)fail('untrusted_rer_approval',403);
 let claims;
 try{({payload:claims}=await jwtVerify(approval,createLocalJWKSet({keys:[key]}),{audience:ctx.origin,algorithms:['ES256'],typ:APPROVAL_TYPE,currentDate:new Date(ctx.now()),requiredClaims:['iat','exp','jti']}));}
 catch{fail('invalid_rer_approval',401);}
 const sec=Math.floor(ctx.now()/1000);
 if(claims.exp-claims.iat>300||claims.iat>sec+30||typeof claims.jti!=='string'||!claims.jti||claims.jti.length>200)fail('invalid_rer_approval',401);
 // One use, whatever happens next.
 try{await run(ctx,'INSERT INTO auth_rer_approvals(jti,kid,expires_at) VALUES(?,?,?)',claims.jti,key.kid,claims.exp*1000);}catch{fail('rer_approval_used',409);}
 if(claims.origin!==origin||claims.interface!==INTERFACE)fail('rer_approval_origin_mismatch',403);
 let approvedKey;try{approvedKey=linkKey({keys:[claims.link_key]});}catch{fail('invalid_rer_approval',401);}
 let claimPerson=null;
 if(claims.claim!==undefined) {
  const owner=await one(ctx,"SELECT id,email FROM oa_operators WHERE role='owner' AND status='active' ORDER BY created_at LIMIT 1");
  if(!owner||typeof claims.claim?.email!=='string'||claims.claim.email.toLowerCase()!==owner.email)fail('rer_claim_not_auth_owner',403);
  claimPerson=owner.id;
 }
 const app=await pullApp(ctx,origin);
 if(!sameKey(app.key,approvedKey))fail('rer_approval_key_mismatch',403);
 return link(ctx,{app,source:'rer',approvedBy:`rer:${key.kid}`,claimPerson});
}
