import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {cookieOf} from './runtime.mjs';
export const browserCookie=response=>response.headers.getSetCookie().find(c=>c.startsWith('__Host-auth_browser=')||c.startsWith('auth_browser='))?.split(';')[0];
export const sessionCookie=response=>response.headers.getSetCookie().find(c=>c.startsWith('__Host-auth_session=')||c.startsWith('auth_session='))?.split(';')[0];
export async function requestProof(r,address,cookie) {
 const requested=await r.call('/auth/identity/email/request',{method:'POST',data:{email:address},cookie});assert.equal(requested.status,202);
 const token=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 return {binding:cookieOf(requested),token};
}
export const finishProof=(r,{binding,token})=>r.call('/auth/identity/email/confirm',{method:'POST',data:{token},cookie:binding});
export async function beginPasskey(r,key,cookie) {
 const options=await r.call('/auth/passkeys/authenticate/options',{method:'POST',data:{},cookie});assert.equal(options.status,200);const tx=await options.json();
 return {binding:cookieOf(options),data:{transaction:tx.transaction,response:key.authenticate(tx.options)}};
}
export const finishPasskey=(r,{binding,data})=>r.call('/auth/passkeys/authenticate/verify',{method:'POST',cookie:binding,data});
export async function issueClient(r) {
 const key=await generateKeyPair('ES256'),jwk={...await exportJWK(key.publicKey),kid:'client-key',alg:'ES256',use:'sig'},origin='https://app.example.com';
 await r.db.prepare('INSERT INTO auth_clients(id,name,origin,sector_id,redirect_uris,jwks,source,created_at) VALUES(?,?,?,?,?,?,?,?)').bind('policy-app','Policy app',origin,'policy-install',JSON.stringify([origin+'/callback']),JSON.stringify({keys:[jwk]}),'owner',r.now).run();
 await r.call('/.well-known/openid-configuration');r.now=(await r.db.prepare('SELECT use_after FROM auth_signing_keys LIMIT 1').first()).use_after+1;
 return {async authorize(cookie) {
  const verifier=randomBytes(32).toString('base64url'),q=new URLSearchParams({client_id:'policy-app',redirect_uri:origin+'/callback',response_type:'code',scope:'openid email',state:'bound-state',nonce:'bound-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',prompt:'none'});
  const response=await r.call('/oidc/authorize?'+q,{cookie});assert.equal(response.status,302);
  return {verifier,code:new URL(response.headers.get('location')).searchParams.get('code')};
 },async redeem(grant) {
  const assertion=await new SignJWT({jti:randomBytes(16).toString('hex')}).setProtectedHeader({alg:'ES256',kid:'client-key'}).setIssuer('policy-app').setSubject('policy-app').setAudience(r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(key.privateKey);
  return r.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',client_id:'policy-app',redirect_uri:origin+'/callback',code:grant.code,code_verifier:grant.verifier,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion}});
 }};
}
