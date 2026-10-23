import {calculateJwkThumbprint,decodeProtectedHeader,importJWK,jwtVerify} from 'jose';
import {fail,hash,run} from '../core.mjs';

// RFC 9449: asymmetric key possession, exact endpoint/method, token hash and
// single-use proof IDs. The authorization code binds the key before redemption.
export async function deviceProof(ctx,request,jkt,accessToken=null) {
 const raw=request.headers.get('dpop');
 if(!raw||raw.length>16384)fail('invalid_dpop_proof',401);
 let payload,thumbprint;
 try {
  const header=decodeProtectedHeader(raw),key=header.jwk;
  if(header.typ!=='dpop+jwt'||header.alg!=='ES256'||key?.kty!=='EC'||key.crv!=='P-256'||['d','p','q','dp','dq','qi','oth','k'].some(k=>Object.hasOwn(key,k)))throw Error();
  thumbprint=await calculateJwkThumbprint(key,'sha256');
  if(thumbprint!==jkt)throw Error();
  ({payload}=await jwtVerify(raw,await importJWK(key,'ES256'),{algorithms:['ES256'],typ:'dpop+jwt',currentDate:new Date(ctx.now()),requiredClaims:['jti','iat','htm','htu']}));
  const now=Math.floor(ctx.now()/1000),endpoint=new URL(request.url);endpoint.search='';endpoint.hash='';
  if(typeof payload.jti!=='string'||!payload.jti||payload.jti.length>200||!Number.isSafeInteger(payload.iat)||payload.iat>now+30||payload.iat<now-60||payload.htm!==request.method||payload.htu!==endpoint.href||accessToken!==null&&payload.ath!==await hash(accessToken))throw Error();
 }catch{fail('invalid_dpop_proof',401);}
 try {await run(ctx,'INSERT INTO auth_refresh_proofs(jkt,jti,expires_at) VALUES(?,?,?)',thumbprint,payload.jti,Math.max(ctx.now()+61000,(payload.iat+61)*1000));}
 catch(error){if(/UNIQUE constraint|PRIMARY KEY/.test(String(error?.message)))fail('invalid_dpop_proof',401);throw error;}
 return thumbprint;
}
