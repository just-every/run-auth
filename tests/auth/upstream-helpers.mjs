import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {openRuntime,cookieOf} from './runtime.mjs';
// Google trusts a verified address only at gmail.com (or with a matching hd claim),
// so the owner's address is a fresh gmail.com mailbox name generated per run.
export const ownerGmail=`owner-${randomBytes(6).toString('hex')}@gmail.com`;
export async function upstreamFixture(t,preset='google',subjectEmails={}) {
 const r=await openRuntime();t.after(()=>r.close());await r.person('owner',ownerGmail,'owner');await r.person('member','member@company.example');
 const keys=await generateKeyPair('RS256'),jwk={...await exportJWK(keys.publicKey),kid:'upstream',alg:'RS256',use:'sig'};
 const issuer=preset==='google'?'https://accounts.google.com':preset==='microsoft'?'https://login.microsoftonline.com/tenant-id/v2.0':'https://company.okta.com/oauth2/default';
 r.upstreamProviders=[{id:'company',preset,...(preset==='microsoft'?{tenant:'tenant-id'}:preset==='okta'?{issuer}:{}),clientId:'auth-upstream',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only',subjectEmails}];
 r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[jwk]}};
 r.login=async(claims,provider='company')=>{
  const started=await r.call(`/auth/oidc/${provider}/start`,{method:'POST',data:{returnTo:'/app/account'}});assert.equal(started.status,303,await started.clone().text());
  const location=new URL(started.headers.get('location'));
  r.upstream.tokens={id_token:await new SignJWT({...claims,nonce:location.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:'upstream'}).setIssuer(issuer).setAudience('auth-upstream').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
  return r.call(`/auth/oidc/${provider}/callback?`+new URLSearchParams({code:'upstream-code',state:location.searchParams.get('state'),iss:issuer}),{cookie:cookieOf(started)});
 };
 r.keys=keys;r.issuer=issuer;
 return r;
}
