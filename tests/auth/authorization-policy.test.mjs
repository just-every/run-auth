import {test} from 'node:test';
import assert from 'node:assert/strict';
import {jwtVerify,createLocalJWKSet,generateKeyPair,exportJWK,SignJWT} from 'jose';
import {fixture} from './protocol-helpers.mjs';
import {cookieOf} from './runtime.mjs';
import {register} from './webauthn.mjs';
import {sessionCookie,browserCookie} from './policy-helpers.mjs';

const location=(r,response)=>new URL(response.headers.get('location'),r.origin);
const returnPath=(r,response)=>{
 assert.equal(response.status,303,'interactive authorization must ask for authentication');
 const page=location(r,response);assert.equal(page.pathname,'/signin');
 return page.searchParams.get('returnTo');
};
async function passkey(r,key,returnTo,cookie) {
 const offered=await r.call('/auth/passkeys/authenticate/options',{method:'POST',data:{returnTo},cookie});
 assert.equal(offered.status,200);const tx=await offered.json();
 const response=await r.call('/auth/passkeys/authenticate/verify',{method:'POST',data:{transaction:tx.transaction,response:key.authenticate(tx.options)},cookie:cookieOf(offered)});
 return {response,binding:cookieOf(offered)};
}
async function confirm(r,binding) {
 const token=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 return r.call('/auth/identity/email/confirm',{method:'POST',form:{token},cookie:binding});
}

async function upstream(r,returnTo,flowCookie) {
 const issuer='https://accounts.google.com',keys=await generateKeyPair('RS256');
 r.upstreamProviders=[{id:'company',preset:'google',clientId:'auth-upstream',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only'}];
 r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[{...await exportJWK(keys.publicKey),kid:'upstream',alg:'RS256',use:'sig'}]}};
 const offered=await r.call('/auth/oidc/company/start',{method:'POST',data:{returnTo},cookie:flowCookie});assert.equal(offered.status,303);
 const authorization=location(r,offered);
 // A genuine signed SSO response, without evidence of fresh user presence.
 r.upstream.tokens={id_token:await new SignJWT({sub:'owner-subject',email:'owner@example.com',email_verified:true,hd:'example.com',nonce:authorization.searchParams.get('nonce'),auth_time:Math.floor(r.now/1000)-420}).setProtectedHeader({alg:'RS256',kid:'upstream'}).setIssuer(issuer).setAudience('auth-upstream').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
 return r.call('/auth/oidc/company/callback?'+new URLSearchParams({code:'upstream-code',state:authorization.searchParams.get('state'),iss:issuer}),{cookie:`${cookieOf(offered)}; ${flowCookie}`});
}

test('sessions end with email proof and interactive app sign-in returns through bound email re-proof',async t=>{
 const r=await fixture(t),owner=await register(r,r.cookie);
 const proof=await r.db.prepare("SELECT verified_at FROM auth_emails WHERE person_id='owner'").first();
 r.now=proof.verified_at+29*86400000+23*3600000;
 const signed=await passkey(r,owner.key,'/app/account');assert.equal(signed.response.status,200);
 r.cookie=sessionCookie(signed.response);
 const horizon=proof.verified_at+30*86400000;
 r.now=horizon;
 assert.equal((await r.call('/api/auth/me',{cookie:r.cookie})).status,401,'the session must end at the proof horizon');
 r.now+=3600000;
 const silent=await r.authorize({extra:{prompt:'none'}});
 assert.equal(location(r,silent.response).searchParams.get('error'),'login_required');
 const grant=await r.authorize(),returnTo=returnPath(r,grant.response);
 const attempt=await passkey(r,owner.key,returnTo,r.cookie);
 assert.equal(attempt.response.status,202);assert.equal((await attempt.response.json()).reproof,true);
 assert.equal((await confirm(r,'__Host-auth_browser=wrong-browser')).status,400);
 const proven=await confirm(r,attempt.binding);assert.equal(proven.status,303);
 assert.equal(proven.headers.get('location'),returnTo);
 const continued=await r.call(returnTo,{cookie:[sessionCookie(proven),cookieOf(grant.response)].filter(Boolean).join('; ')});
 assert.equal(continued.status,302);
 assert.equal(location(r,continued).searchParams.get('state'),'state-to-bind');
 assert.equal((await r.redeem({...grant,code:location(r,continued).searchParams.get('code')})).status,200);
 assert.equal((await confirm(r,attempt.binding)).status,400,'email proof cannot replay');
});

test('prompt and maximum authentication age require a new proof once, with silent refusal and fresh auth_time',async t=>{
 const r=await fixture(t),owner=await register(r,r.cookie);r.cookie=owner.cookie;r.now+=7*60000;
 for(const extra of [{prompt:'login'},{max_age:'0'},{max_age:'1'},{prompt:'select_account login'}]) {
  const grant=await r.authorize({extra}),returnTo=returnPath(r,grant.response),flowCookie=cookieOf(grant.response);
  // Knowing the return path or retaining the old Auth session is not a new proof.
  assert.equal((await r.call(returnTo,{cookie:r.cookie})).status,400);
  const unchanged=await r.call(returnTo,{cookie:`${r.cookie}; ${flowCookie}`});
  assert.equal(unchanged.status,303);assert.equal(location(r,unchanged).searchParams.get('code'),null);
  const newPath=returnPath(r,unchanged),newFlowCookie=cookieOf(unchanged),authAt=Math.floor(r.now/1000);
  const signed=await passkey(r,owner.key,newPath,r.cookie);assert.equal(signed.response.status,200);
  assert.equal((await signed.response.json()).returnTo,newPath);r.cookie=sessionCookie(signed.response);
  const continued=await r.call(newPath,{cookie:`${r.cookie}; ${newFlowCookie}`});assert.equal(continued.status,302);
  const target=location(r,continued);assert.equal(target.searchParams.get('state'),'state-to-bind');assert.equal(target.searchParams.get('iss'),r.origin);
  const token=await r.redeem({...grant,code:target.searchParams.get('code')});assert.equal(token.status,200);
  const claims=(await jwtVerify((await token.json()).id_token,createLocalJWKSet(await(await r.call('/oidc/jwks')).json()),{currentDate:new Date(r.now)})).payload;
  assert.equal(claims.auth_time,authAt);
  assert.equal((await r.call(newPath,{cookie:`${r.cookie}; ${newFlowCookie}`})).status,400,'continuation is one use');
  r.now+=7*60000;
 }
 const allowed=await r.authorize({extra:{max_age:'600',prompt:'none'}});assert.equal(allowed.response.status,302);assert.ok(allowed.code);
 for(const max_age of ['0','1']) {
  const silent=location(r,(await r.authorize({extra:{max_age,prompt:'none'}})).response);
  assert.equal(silent.searchParams.get('error'),'login_required');assert.equal(silent.searchParams.get('code'),null);
  assert.equal(silent.searchParams.get('state'),'state-to-bind');assert.equal(silent.searchParams.get('iss'),r.origin);
 }
 for(const extra of [{prompt:'none login'},{max_age:'-1'},{max_age:'1.5'},{max_age:'not-a-number'},{max_age:''}]) {
  const error=location(r,(await r.authorize({extra})).response);assert.equal(error.searchParams.get('error'),'invalid_request');assert.equal(error.searchParams.get('code'),null);
 }
 // Zero is an active-authentication request even in the same second as sign-in.
 const fresh=await passkey(r,owner.key,'/app/account');r.cookie=sessionCookie(fresh.response);
 returnPath(r,(await r.authorize({extra:{max_age:'0'}})).response);
 // Expired continuations cannot exempt a later request from active proof.
 const expired=await r.authorize({extra:{prompt:'login'}}),expiredPath=returnPath(r,expired.response);
 r.now+=16*60000;
 assert.equal((await r.call(expiredPath,{cookie:`${r.cookie}; ${cookieOf(expired.response)}`})).status,400);
 // A provider callback must complete an Auth proof for forced reauthentication.
 const grant=await r.authorize({extra:{prompt:'login'}}),returnTo=returnPath(r,grant.response),flowCookie=cookieOf(grant.response),mailCount=(await r.mails()).length;
 const sso=await upstream(r,returnTo,flowCookie);assert.equal(sso.status,303);
 assert.equal(location(r,sso).searchParams.get('returnTo'),returnTo);
 assert.equal(sessionCookie(sso),undefined);assert.equal((await r.mails()).length,mailCount+1);
 const proven=await confirm(r,browserCookie(sso));assert.equal(proven.status,303);assert.equal(proven.headers.get('location'),returnTo);
 const continued=await r.call(returnTo,{cookie:`${sessionCookie(proven)}; ${flowCookie}`});assert.equal(continued.status,302);
 assert.equal((await r.redeem({...grant,code:location(r,continued).searchParams.get('code')})).status,200);
});

test('unsupported request objects match discovery and never bypass callback validation or issue codes',async t=>{
 const r=await fixture(t),metadata=await(await r.call('/.well-known/openid-configuration')).json();
 assert.equal(metadata.request_parameter_supported,false);assert.equal(metadata.request_uri_parameter_supported,false);
 for(const [parameter,error]of [['request','request_not_supported'],['request_uri','request_uri_not_supported']]) {
  for(const value of ['',parameter==='request'?'opaque.jwt.object':'https://app.example.com/request']) {
   const response=(await r.authorize({extra:{[parameter]:value}})).response;assert.equal(response.status,302);
   const target=location(r,response);assert.equal(target.origin,r.clientOrigin);assert.equal(target.searchParams.get('error'),error);
   assert.equal(target.searchParams.get('code'),null);assert.equal(target.searchParams.get('state'),'state-to-bind');assert.equal(target.searchParams.get('iss'),r.origin);
  }
  // Object parameters may have carried nonce and PKCE. Refuse the mechanism itself.
  const q=new URLSearchParams({client_id:'app',redirect_uri:r.clientOrigin+'/callback',response_type:'code',scope:'openid',state:'bound',[parameter]:'unsupported'});
  assert.equal(location(r,await r.call('/oidc/authorize?'+q)).searchParams.get('error'),error);
  for(const input of [{client:'unknown'},{redirect:'https://foreign.example/callback'}]) {
   const refused=(await r.authorize({...input,extra:{[parameter]:'unsupported'}})).response;
   assert.equal(refused.status,400);assert.equal(refused.headers.get('location'),null);
  }
 }
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_codes').first()).n,0);
});
