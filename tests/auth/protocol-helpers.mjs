import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {openRuntime,emailSession} from './runtime.mjs';
const digest=v=>createHash('sha256').update(v).digest('base64url');
export async function fixture(t,{local=false,algorithm='ES256'}={}) {
 const r=await openRuntime(),close=r.close.bind(r);let closed=false;
 r.close=async()=>{if(!closed){closed=true;await close();}};
 t.after(()=>r.close());if(local){r.origin='http://127.0.0.1:8000';r.local=true;}
 await r.person('owner','owner@example.com','owner');r.cookie=await emailSession(r,'owner@example.com');
 const key=await generateKeyPair('ES256');r.privateKey=key.privateKey;
 const jwk={...await exportJWK(key.publicKey),kid:'client-signing',alg:'ES256',use:'sig'};
 r.clientOrigin=local?'http://127.0.0.1:9000':'https://app.example.com';
 await r.db.prepare('INSERT INTO auth_clients(id,name,origin,sector_id,redirect_uris,jwks,owner_person_id,source,created_at) VALUES(?,?,?,?,?,?,?,?,?)').bind('app','App',r.clientOrigin,'install-A',JSON.stringify([r.clientOrigin+'/callback']),JSON.stringify({keys:[jwk]}),'owner','owner',r.now).run();
 assert.equal((await r.call('/.well-known/openid-configuration')).status,200);r.stage=await r.db.prepare('SELECT kid,use_after AS useAfter FROM auth_signing_keys LIMIT 1').first();r.now=(await r.db.prepare('SELECT MAX(use_after) AS ready FROM auth_signing_keys').first()).ready+1;
 await r.db.prepare('UPDATE auth_clients SET id_token_signed_response_alg=? WHERE id=?').bind(algorithm,'app').run();
 r.authorize=async({client='app',redirect=r.clientOrigin+'/callback',scope='openid email profile claim',verifier=randomBytes(32).toString('base64url'),extra={}}={})=>{
  const q=new URLSearchParams({client_id:client,redirect_uri:redirect,response_type:'code',scope,state:'state-to-bind',nonce:'nonce-to-bind',code_challenge:digest(verifier),code_challenge_method:'S256',...extra});
  const response=await r.call('/oidc/authorize?'+q,{cookie:r.cookie});return {response,verifier,code:response.headers.get('location')?new URL(response.headers.get('location'),r.origin).searchParams.get('code'):null};
 };
 r.assertion=async(jti=randomBytes(16).toString('hex'))=>new SignJWT({jti}).setProtectedHeader({alg:'ES256',kid:'client-signing'}).setIssuer('app').setSubject('app').setAudience(r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(r.privateKey);
 r.redeem=async(grant,extra={})=>r.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',client_id:'app',redirect_uri:r.clientOrigin+'/callback',code:grant.code,code_verifier:grant.verifier,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await r.assertion(),...extra}});
 return r;
}
