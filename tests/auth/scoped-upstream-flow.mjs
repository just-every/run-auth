import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {cookieOf} from './runtime.mjs';

export async function scopedUpstreamFlow({r,a,b,adminA,adminB,owner,personA,personB}) {
 const json=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
 const post=(data,cookie)=>({method:'POST',data,cookie});
 assert.equal((await a.call('/api/auth/federation/create',post({domain:'example.com',provider:{id:'foreign',preset:'google',clientId:'synthetic-auth-79',clientSecret:'synthetic-auth-80',subjectEmails:{foreign:'contractor@example.com'}},confirm:true},adminB.cookie))).status,401,'a different employer cannot prepare provider trust');
 assert.equal((await a.call('/api/auth/federation',{cookie:owner.cookie})).status,401,'installation ownership supplies no employer setup session');
 const secret='synthetic-auth-72',provider={id:'company',label:'Employer Google',preset:'google',clientId:'synthetic-auth-71',tokenAuthMethod:'client_secret_basic',clientSecret:secret};
 r.upstreamProviders=[{...provider,id:'installation',clientId:'synthetic-auth-73'}];
 assert.equal((await a.call('/auth/oidc/installation/start',post({returnTo:'/app/account'}))).status,404,'root provider trust is never inherited');
 assert.equal((await a.call('/api/auth/organizations/providers',post(provider,owner.cookie))).status,401,'root owner cannot configure an employer');
 for(const [client,admin] of [[a,adminA],[b,adminB]]) {
  const registered=await json(await client.call('/api/auth/organizations/providers',post(provider,admin.cookie)),201);assert.ok(registered.callback.includes('/org/'));
  assert.ok(!JSON.stringify(registered).includes(secret));
  const me=await json(await client.call('/api/auth/me',{cookie:admin.cookie}));assert.ok(!JSON.stringify(me).includes(secret));
 }
 const keys=await generateKeyPair('RS256'),jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-74',alg:'RS256',use:'sig'},issuer='https://accounts.google.com';
 r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[jwk]}};
 const start=async client=>{const response=await client.call('/auth/oidc/company/start',post({returnTo:'/app/account'}));assert.equal(response.status,303,await response.clone().text());return {response,location:new URL(response.headers.get('location'))};};
 const callback=async(client,started)=>{
  r.upstream.tokens={id_token:await new SignJWT({sub:'synthetic-auth-same-subject',email:'contractor@example.com',email_verified:true,hd:'example.com',nonce:started.location.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(issuer).setAudience(provider.clientId).setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
  return client.call('/auth/oidc/company/callback?'+new URLSearchParams({code:'synthetic-auth-75',state:started.location.searchParams.get('state'),iss:issuer}),{cookie:cookieOf(started.response)});
 };
 const first=await start(a),redirectA=first.location.searchParams.get('redirect_uri');
 assert.ok(redirectA.includes('/org/'));assert.ok(redirectA.endsWith('/auth/oidc/company/callback'));
 const completedA=await callback(a,first);assert.equal(completedA.status,303,await completedA.clone().text());
 const cookieA=completedA.headers.getSetCookie().find(value=>/^__Host-auth_session_/.test(value)).split(';')[0];
 const meA=await json(await a.call('/api/auth/me',{cookie:cookieA}));assert.equal(meA.user.id,personA.id);assert.ok(meA.user.amr.includes('oidc'));
 assert.equal((await b.call('/api/auth/me',{cookie:cookieA})).status,401,'A provider session supplies no B proof');
 assert.ok(!(await json(await a.call('/api/auth/organizations',{cookie:cookieA}))).memberships.some(org=>redirectA.includes('/org/'+org.id+'/')===false),'a single provider session discloses only its own membership');
 assert.equal((await callback(b,first)).status,400,'A state and browser correlation cannot be transferred to B');
 const second=await start(b);assert.notEqual(second.location.searchParams.get('redirect_uri'),redirectA);
 const completedB=await callback(b,second);assert.equal(completedB.status,303,await completedB.clone().text());
 const cookieB=completedB.headers.getSetCookie().find(value=>/^__Host-auth_session_/.test(value)).split(';')[0];
 const meB=await json(await b.call('/api/auth/me',{cookie:cookieB}));assert.equal(meB.user.id,personB.id);assert.notEqual(meA.user.id,meB.user.id);assert.ok(meB.user.amr.includes('oidc'));
 assert.equal((await a.call('/api/auth/me',{cookie:cookieB})).status,401,'the identical upstream subject supplies no A proof from B');
 assert.equal((await r.call('/api/auth/me',{cookie:cookieA+'; '+cookieB})).status,401,'neither membership provider session supplies installation proof');
 assert.equal((await a.call('/api/auth/identity-pairs',{cookie:cookieA})).status,403,'upstream equality creates no voluntary cross-identity link');
}
