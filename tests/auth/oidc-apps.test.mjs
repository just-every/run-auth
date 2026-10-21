import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import * as oidc from 'openid-client';
import {generateKeyPair,exportJWK,jwtVerify,createLocalJWKSet,decodeJwt} from 'jose';
import {samlInstall,browse} from './saml-helpers.mjs';

const RP='https://rp.example.com';
// The relying party's own back-channel endpoint, at the network edge.
async function logoutReceiver(t,r) {
 const received=[];
 const server=createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;received.push({path:req.url,token:new URLSearchParams(body).get('logout_token')});res.writeHead(200);res.end();});
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>server.close(done)));
 r.edges={[RP]:`http://127.0.0.1:${server.address().port}`};
 return received;
}
async function ready(r) {
 assert.equal((await r.call('/.well-known/openid-configuration')).status,200);
 // Signing keys publish a cache lifetime before use; this run does not wait it out.
 await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
}
async function register(r,data) {
 const response=await r.admin('oidc-apps/create',{attributes:'department=role',...data});assert.equal(response.status,201,await response.clone().text());
 const app=await response.json();
 for(const id of data.assign??['ada'])assert.equal((await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:id,role:'finance'})).status,200);
 return app;
}
// openid-client, a certified relying party library, talking to Auth's real doors.
async function relyingParty(r,clientId,auth,metadata={}) {
 const fetcher=async(url,options={})=>{const u=new URL(url),body=options.body?String(options.body):null;r.tick();return r.call(u.pathname+u.search,{method:options.method||'GET',headers:Object.fromEntries(new Headers(options.headers)),form:body?Object.fromEntries(new URLSearchParams(body)):undefined});};
 const config=await oidc.discovery(new URL(r.origin),clientId,metadata,auth,{[oidc.customFetch]:fetcher});
 config[oidc.customFetch]=fetcher;
 return config;
}
async function signIn(r,config,{redirect,cookie=r.ada,extra={}}) {
 const verifier=oidc.randomPKCECodeVerifier(),state=oidc.randomState(),nonce=oidc.randomNonce();
 const url=oidc.buildAuthorizationUrl(config,{redirect_uri:redirect,scope:'openid email profile groups',code_challenge:await oidc.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256',state,nonce,...extra});
 const response=await browse(r,url.pathname+url.search,{cookie});assert.equal(response.status,302,await response.clone().text());
 const location=new URL(response.headers.get('location'));
 return {location,verifier,state,nonce,grant:()=>oidc.authorizationCodeGrant(config,location,{pkceCodeVerifier:verifier,expectedState:state,expectedNonce:nonce})};
}
const tokenRequest=(r,form,headers={})=>{r.tick();return r.call('/oidc/token',{method:'POST',form,headers});};
const basicAuth=(id,secret)=>({authorization:'Basic '+Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')});

test('SaaS clients sign in with client_secret_basic, client_secret_post and private_key_jwt, and a native app with none and PKCE; RP-initiated logout reaches front- and back-channel apps',async t=>{
 const r=await samlInstall(t),received=await logoutReceiver(t,r);await ready(r);
 const discovery=await (await r.call('/.well-known/openid-configuration')).json();
 for(const method of ['client_secret_basic','client_secret_post','private_key_jwt','none'])assert.ok(discovery.token_endpoint_auth_methods_supported.includes(method));
 assert.deepEqual(discovery.subject_types_supported,['pairwise','public']);assert.equal(discovery.frontchannel_logout_supported,true);
 const basic=await register(r,{name:'Expenses',authMethod:'client_secret_basic',redirectUris:`${RP}/cb`,postLogoutRedirectUris:`${RP}/bye`,frontchannelLogoutUri:`${RP}/fc`,backchannelLogoutUri:`${RP}/bc`});
 assert.equal(basic.clientSecret.length,43);
 const mapped={appId:basic.id,personIds:['ada'],program:{language:1,oidc:{mapped_name:{op:'upper',args:[{field:'name'}]}}}};
 const preview=await (await r.admin('mapping/preview',mapped)).json();
 assert.equal((await r.admin('mapping/save',{...mapped,version:0,digest:preview.digest})).status,200);
 const post=await register(r,{name:'Travel',authMethod:'client_secret_post',redirectUris:`${RP}/travel/cb`,backchannelLogoutUri:`${RP}/travel/bc`,subjectType:'public'});
 const key=await generateKeyPair('RS256',{extractable:true}),jwk={...await exportJWK(key.publicKey),kid:'rp-key',alg:'RS256',use:'sig'};
 const jwt=await register(r,{name:'Payroll',authMethod:'private_key_jwt',jwks:JSON.stringify({keys:[jwk]}),redirectUris:`${RP}/payroll/cb`,requirePkce:true});
 const native=await register(r,{name:'Field app',authMethod:'none',redirectUris:'com.example.field:/oauth'});
 assert.equal(native.clientSecret,null);
 const clients=[
  [basic,oidc.ClientSecretBasic(basic.clientSecret),`${RP}/cb`],
  [post,oidc.ClientSecretPost(post.clientSecret),`${RP}/travel/cb`],
  [jwt,oidc.PrivateKeyJwt({key:key.privateKey,kid:'rp-key'}),`${RP}/payroll/cb`],
  [native,oidc.None(),'com.example.field:/oauth'],
 ];
 const subjects=new Set();let session;
 for(const [app,auth,redirect] of clients) {
  const config=await relyingParty(r,app.clientId,auth);
  const flow=await signIn(r,config,{redirect});assert.equal(flow.location.searchParams.get('iss'),r.origin);
  const tokens=await flow.grant(),claims=tokens.claims();
  assert.equal(claims.email,'ada@example.com');if(app.id===basic.id)assert.equal(claims.mapped_name,'ADA');assert.equal(claims.department,'finance');assert.equal(tokens.refresh_token,undefined);
  subjects.add(claims.sub);session??=claims.sid;
  const info=await oidc.fetchUserInfo(config,tokens.access_token,claims.sub);assert.equal(info.email,'ada@example.com');assert.deepEqual(info.groups,[]);
  app.tokens=tokens;app.config=config;
 }
 assert.equal(subjects.size,4);assert.ok(subjects.has('ada'),'the public-subject app sees the stable person ID');
 // A public client must use PKCE.
 const noPkce=await browse(r,`/oidc/authorize?${new URLSearchParams({client_id:native.clientId,redirect_uri:'com.example.field:/oauth',response_type:'code',scope:'openid',state:'s1'})}`,{cookie:r.ada});
 assert.equal(new URL(noPkce.headers.get('location')).searchParams.get('error'),'invalid_request');
 // RP-initiated logout: front-channel frame and back-channel tokens, then back to the app.
 const end=oidc.buildEndSessionUrl(basic.config,{id_token_hint:basic.tokens.id_token,post_logout_redirect_uri:`${RP}/bye`,state:'after'});
 const page=await browse(r,end.pathname+end.search,{cookie:r.ada});assert.equal(page.status,200);
 const html=await page.text();
 assert.match(html,new RegExp(`<iframe src="${RP}/fc\\?iss=${encodeURIComponent(r.origin).replace(/\./g,'\\.')}&amp;sid=${session}"`));
 assert.match(html,new RegExp(`url=${RP}/bye\\?state=after`));assert.match(page.headers.get('content-security-policy'),new RegExp(`frame-src ${RP}`));
 const keys=createLocalJWKSet(await (await r.call('/oidc/jwks')).json());
 assert.deepEqual(received.map(x=>x.path).sort(),['/bc','/travel/bc']);
 for(const {token,path} of received) {
  const {payload,protectedHeader}=await jwtVerify(token,keys,{issuer:r.origin,currentDate:new Date(r.now)});
  assert.equal(protectedHeader.typ,'logout+jwt');assert.equal(payload.sid,session);assert.ok(payload.events['http://schemas.openid.net/event/backchannel-logout']);
  assert.equal(payload.aud,path==='/bc'?basic.clientId:post.clientId);assert.equal(payload.nonce,undefined);
 }
 await assert.rejects(oidc.fetchUserInfo(basic.config,basic.tokens.access_token,decodeJwt(basic.tokens.id_token).sub));
});

test('wrong, mismatched and rotated-out secrets, substituted redirects and codes, replays and unsupported grants are refused; legacy flows only where opted in; unassigned people get no tokens',async t=>{
 const r=await samlInstall(t);await ready(r);
 const a=await register(r,{name:'Ledger',authMethod:'client_secret_basic',redirectUris:`${RP}/a`});
 const b=await register(r,{name:'Board',authMethod:'client_secret_post',redirectUris:`${RP}/b`});
 const code=async(app,redirect,cookie=r.ada)=>{const res=await browse(r,`/oidc/authorize?${new URLSearchParams({client_id:app.clientId,redirect_uri:redirect,response_type:'code',scope:'openid email',state:'st'})}`,{cookie});return new URL(res.headers.get('location')).searchParams;};
 const redeem=(app,c,redirect,headers=basicAuth(app.clientId,app.clientSecret),extra={})=>tokenRequest(r,{grant_type:'authorization_code',code:c,redirect_uri:redirect,...extra},headers);
 // Wrong secret, the other method, and two methods at once.
 for(const [headers,extra] of [[basicAuth(a.clientId,'wrong'),{}],[{},{client_id:a.clientId,client_secret:a.clientSecret}],[basicAuth(a.clientId,a.clientSecret),{client_secret:a.clientSecret}]]) {
  const res=await redeem(a,(await code(a,`${RP}/a`)).get('code'),`${RP}/a`,headers,extra);assert.equal(res.status,401);assert.equal((await res.json()).error,'invalid_client');
 }
 // Redirect substitution: refused locally at authorize; a changed redirect fails at the token endpoint.
 const substituted=await browse(r,`/oidc/authorize?${new URLSearchParams({client_id:a.clientId,redirect_uri:`${RP}/evil`,response_type:'code',scope:'openid'})}`,{cookie:r.ada});
 assert.equal(substituted.status,400);assert.equal(substituted.headers.get('location'),null);
 assert.equal((await (await redeem(a,(await code(a,`${RP}/a`)).get('code'),`${RP}/elsewhere`)).json()).error,'invalid_grant');
 // Replay, and a code issued to one app presented by another.
 const once=(await code(a,`${RP}/a`)).get('code');
 assert.equal((await redeem(a,once,`${RP}/a`)).status,200);assert.equal((await (await redeem(a,once,`${RP}/a`)).json()).error,'invalid_grant');
 const stolen=(await code(a,`${RP}/a`)).get('code');
 assert.equal((await (await tokenRequest(r,{grant_type:'authorization_code',code:stolen,redirect_uri:`${RP}/a`,client_id:b.clientId,client_secret:b.clientSecret})).json()).error,'invalid_grant');
 for(const grant of ['password','client_credentials','refresh_token']) {
  const res=await tokenRequest(r,{grant_type:grant,username:'ada',password:'x',refresh_token:'x'},basicAuth(a.clientId,a.clientSecret));
  assert.equal(res.status,400);assert.equal((await res.json()).error,'unsupported_grant_type');
 }
 // Rotation: the new secret works at once, the old one only through its overlap.
 const rotated=await (await r.admin('oidc-apps/rotate-secret',{appId:a.id,overlapHours:1})).json();
 assert.equal((await redeem(a,(await code(a,`${RP}/a`)).get('code'),`${RP}/a`,basicAuth(a.clientId,rotated.clientSecret))).status,200);
 assert.equal((await redeem(a,(await code(a,`${RP}/a`)).get('code'),`${RP}/a`)).status,200);
 r.tick=()=>{r.now=Date.now()+3600001;};
 const late=(await code(a,`${RP}/a`)).get('code');
 assert.equal((await redeem(a,late,`${RP}/a`)).status,401);
 assert.equal((await redeem(a,(await code(a,`${RP}/a`)).get('code'),`${RP}/a`,basicAuth(a.clientId,rotated.clientSecret))).status,200);
 r.tick=()=>{r.now=Date.now();};
 // Unassigned: access_denied, no code.
 const denied=await code(a,`${RP}/a`,r.bob);assert.equal(denied.get('error'),'access_denied');assert.equal(denied.get('code'),null);
 // An ID token is not a UserInfo credential.
 const issued=await (await redeem(a,(await code(a,`${RP}/a`)).get('code'),`${RP}/a`,basicAuth(a.clientId,rotated.clientSecret))).json();
 assert.equal((await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+issued.id_token}})).status,401);
 // Implicit and hybrid: refused unless the app opted in; then validated by the relying party library.
 const implicit=await browse(r,`/oidc/authorize?${new URLSearchParams({client_id:a.clientId,redirect_uri:`${RP}/a`,response_type:'id_token',scope:'openid',nonce:'n1',state:'st'})}`,{cookie:r.ada});
 assert.equal(new URLSearchParams(new URL(implicit.headers.get('location')).hash.slice(1)).get('error'),'unauthorized_client');
 const legacy=await register(r,{name:'Old portal',authMethod:'client_secret_post',redirectUris:`${RP}/legacy`,legacyFlows:true});
 const config=await relyingParty(r,legacy.clientId,oidc.ClientSecretPost(legacy.clientSecret));
 oidc.useIdTokenResponseType(config);
 const nonce=oidc.randomNonce(),url=oidc.buildAuthorizationUrl(config,{redirect_uri:`${RP}/legacy`,scope:'openid email',nonce,state:'st'});
 const fragment=new URL((await browse(r,url.pathname+url.search,{cookie:r.ada})).headers.get('location'));
 assert.equal((await oidc.implicitAuthentication(config,fragment,nonce,{expectedState:'st'})).email,'ada@example.com');
 const hybridConfig=await relyingParty(r,legacy.clientId,oidc.ClientSecretPost(legacy.clientSecret));oidc.useCodeIdTokenResponseType(hybridConfig);
 const hybrid=await signIn(r,hybridConfig,{redirect:`${RP}/legacy`});assert.ok(new URLSearchParams(hybrid.location.hash.slice(1)).get('id_token'));
 const viaHybrid=new URL(`${RP}/legacy`);viaHybrid.hash=hybrid.location.hash;
 assert.equal((await oidc.authorizationCodeGrant(hybridConfig,viaHybrid,{pkceCodeVerifier:hybrid.verifier,expectedState:hybrid.state,expectedNonce:hybrid.nonce})).claims().email,'ada@example.com');
 // The connection's advertised profile, as an administrator reads it.
 const model=(await (await r.call('/api/auth/company-apps',{cookie:r.owner.cookie})).json()).companyApps;
 assert.deepEqual(model.filter(x=>x.protocol==='oidc').map(x=>[x.name,x.oidc.authMethod,x.oidc.legacyFlows]).sort(),[['Board','client_secret_post',false],['Ledger','client_secret_basic',false],['Old portal','client_secret_post',true]]);
 // Inside the overlap both secrets are live, and the page says until when.
 const ledger=model.find(x=>x.name==='Ledger').oidc;assert.equal(ledger.liveSecrets,2);assert.equal(ledger.previousSecretUntil,rotated.previousValidUntil);
});
