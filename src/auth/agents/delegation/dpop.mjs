import {decodeProtectedHeader,importJWK,jwtVerify,calculateJwkThumbprint} from 'jose';
import {AuthError,hash,random,one,run,limit,fail} from '../../core.mjs';
import {agentGuard} from './state.mjs';

export class DpopError extends AuthError {
 constructor(code,status,headers={}) {
  super(code,status);
  this.headers={'cache-control':'no-store','www-authenticate':`DPoP error="${code}", algs="ES256 RS256"`,...headers};
 }
}
const refused=()=>{throw new DpopError('invalid_dpop_proof',401);};
function normalized(value) {
 const url=new URL(value);
 if(!['https:','http:'].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw new Error('invalid_dpop_uri');
 return url.href.replace(/%([0-9a-f]{2})/gi,(encoded,hex)=>{
  const character=String.fromCharCode(parseInt(hex,16));
  return /^[A-Za-z0-9._~-]$/.test(character)?character:encoded.toUpperCase();
 });
}
async function nonceChallenge(ctx,agent,jkt,htu,tokenEndpoint) {
 const nonce=random(),guard=await agentGuard(ctx,agent);
 const result=await run(ctx,`INSERT INTO auth_delegation_dpop_nonces(nonce_hash,agent_id,jkt,htu,expires_at) SELECT ?,?,?,?,? WHERE ${guard.clause}`,await hash(nonce),agent.id,jkt,htu,ctx.now()+300000,...guard.args);
 if(!result.meta.changes)refused();
 throw new DpopError('use_dpop_nonce',tokenEndpoint?400:401,{'dpop-nonce':nonce});
}
// RFC 9449 proof: a public registered key, HTTP method/URI, fresh issuance,
// endpoint-specific server nonce, access-token hash and key-bound replay ID.
export async function requireDpop(ctx,request,agent,{htu,accessToken=null,jkt=null,task=null,tokenEndpoint=false}) {
 const raw=request.headers.get('dpop');
 if(!raw||raw.length>16384||!/^[-A-Za-z0-9_]+\.[-A-Za-z0-9_]+\.[-A-Za-z0-9_]+$/.test(raw))refused();
 if(!await limit(ctx,'delegated-dpop:'+agent.id,120,60000))fail('rate_limited',429);
 let payload,thumbprint;
 try {
  const header=decodeProtectedHeader(raw),key=header.jwk;
  if(header.typ!=='dpop+jwt'||!['ES256','RS256'].includes(header.alg)||!key||typeof key!=='object'||Array.isArray(key)||['d','p','q','dp','dq','qi','oth','k'].some(field=>Object.hasOwn(key,field)))refused();
  thumbprint=await calculateJwkThumbprint(key,'sha256');
  const registered=JSON.parse(agent.service.jwks).keys;
  const matches=await Promise.all(registered.map(async candidate=>candidate.alg===header.alg&&await calculateJwkThumbprint(candidate,'sha256')===thumbprint));
  if(!matches.some(Boolean)||jkt!==null&&jkt!==thumbprint)refused();
  ({payload}=await jwtVerify(raw,await importJWK(key,header.alg),{typ:'dpop+jwt',algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['jti','iat','htm','htu']}));
  const now=Math.floor(ctx.now()/1000);
  if(typeof payload.jti!=='string'||!payload.jti||payload.jti.length>200||!Number.isSafeInteger(payload.iat)||payload.iat>now+30||payload.iat<now-300||payload.htm!==request.method||typeof payload.htu!=='string'||normalized(payload.htu)!==normalized(htu)||accessToken!==null&&payload.ath!==await hash(accessToken))refused();
 }catch(error) {
  if(error instanceof DpopError)throw error;
  refused();
 }
 // Attribution follows verified key possession, never the unverified header.
 ctx.delegationActor={actorId:'delegated-agent:'+agent.id,agentId:agent.id,accountablePersonId:task?.accountable_id??null,approvedBy:task?.approved_by??null,grantId:task?.id??null};
 if(await one(ctx,'SELECT 1 FROM auth_delegation_dpop_proofs WHERE jkt=? AND jti=?',thumbprint,payload.jti))refused();
 const nonce=typeof payload.nonce==='string'&&payload.nonce.length<=256?await one(ctx,'SELECT nonce_hash FROM auth_delegation_dpop_nonces WHERE nonce_hash=? AND agent_id=? AND jkt=? AND htu=? AND expires_at>?',await hash(payload.nonce),agent.id,thumbprint,htu,ctx.now()):null;
 if(!nonce)await nonceChallenge(ctx,agent,thumbprint,htu,tokenEndpoint);
 const guard=await agentGuard(ctx,agent),expiresAt=Math.max(ctx.now()+301000,(payload.iat+301)*1000);
 let consumed;
 try {
  consumed=await run(ctx,`INSERT INTO auth_delegation_dpop_proofs(jkt,jti,agent_id,expires_at) SELECT ?,?,?,? WHERE ${guard.clause}`,thumbprint,payload.jti,agent.id,expiresAt,...guard.args);
 }catch(error) {
  if(/UNIQUE constraint failed|PRIMARY KEY constraint failed/.test(String(error?.message)))refused();
  throw error;
 }
 if(!consumed.meta.changes)refused();
 return {jkt:thumbprint};
}
