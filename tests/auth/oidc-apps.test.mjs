import {hookServer,verifiedHook} from './hooks-server.mjs';
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

test('inline hooks add only approved token and SAML fields, deny registration and imports, enforce signed minimal payloads and timeout choices, and refuse private DNS and protected identity changes',async t=>{
 const r=await samlInstall(t),edge=await hookServer(t);r.edges=edge.edges;await ready(r);
 const app=await register(r,{name:'Hooked payroll',authMethod:'client_secret_basic',redirectUris:`${RP}/hooks`});
 const config=await relyingParty(r,app.clientId,oidc.ClientSecretBasic(app.clientSecret));
 const create=async data=>{const response=await r.admin('hooks/register',data);assert.equal(response.status,201);return response.json();};
 const disable=async id=>assert.equal((await r.admin('hooks/disable',{id})).status,200);
 assert.equal((await r.admin('hooks/register',{point:'password_import',url:'https://hooks.example.com/password',allowedFields:['roles']})).status,400,'password verification hooks cannot modify identity or roles');
 const passwordHook=await create({point:'password_import',url:'https://hooks.example.com/password',allowedFields:[]});assert.deepEqual(passwordHook.allowedFields,[]);await disable(passwordHook.id);
 const tokenHook=await create({point:'token',appId:app.id,url:'https://hooks.example.com/token',allowedFields:['cost_center']});
 const issued=await (await signIn(r,config,{redirect:`${RP}/hooks`})).grant();assert.equal(issued.claims().cost_center,'CC-42');
 assert.ok(verifiedHook(tokenHook.secret,edge.received[0]));
 const payload=JSON.parse(edge.received[0].body);assert.deepEqual(Object.keys(payload.data).sort(),['appId','personId']);assert.equal(payload.data.personId,'ada');assert.equal(payload.version,1);
 const unchanged=issued.claims().sub;
 // A subject, administrator role, MFA or policy change is forbidden even for a fail-open hook.
 await disable(tokenHook.id);
 const unsafe=await create({point:'token',appId:app.id,url:'https://hooks.example.com/unsafe',allowedFields:['cost_center'],failClosed:false});
 for(const claims of [{sub:'other'},{roles:['administrator']},{amr:[]},{policy:'allow'}]){
  edge.responses.set('/unsafe',{body:{claims}});
  await assert.rejects((await signIn(r,config,{redirect:`${RP}/hooks`})).grant());
 }
 assert.equal((await r.admin('hooks/register',{point:'token',appId:app.id,url:'https://hooks.example.com/token',allowedFields:['roles']})).status,400);
 await disable(unsafe.id);
 // Real timeout at the network edge: fail closed gives a clear public error; fail open continues unchanged.
 edge.responses.set('/timeout','hang');
 const timeout=await create({point:'token',appId:app.id,url:'https://hooks.example.com/timeout',allowedFields:[],timeoutMs:100});
 let flow=await signIn(r,config,{redirect:`${RP}/hooks`});
 let response=await tokenRequest(r,{grant_type:'authorization_code',code:flow.location.searchParams.get('code'),redirect_uri:`${RP}/hooks`,code_verifier:flow.verifier},basicAuth(app.clientId,app.clientSecret));
 assert.equal(response.status,503);const failure=await response.json();assert.equal(failure.error,'hook_timeout');assert.match(failure.message,/timed out/);assert.equal(failure.id_token,undefined);
 await disable(timeout.id);
 const open=await create({point:'token',appId:app.id,url:'https://hooks.example.com/timeout',timeoutMs:100,failClosed:false});
 const continued=await (await signIn(r,config,{redirect:`${RP}/hooks`})).grant();assert.equal(continued.claims().sub,unchanged);assert.equal(continued.claims().cost_center,undefined);
 const activity=(await (await r.call('/api/auth/activity',{cookie:r.owner.cookie})).json()).map(a=>a.detail?JSON.parse(a.detail):{});
 assert.ok(activity.some(a=>a.outcome==='hook_timeout'&&a.latencyMs>=0));assert.ok(activity.some(a=>a.outcome==='ignored_hook_timeout'&&a.latencyMs>=0));
 await disable(open.id);
 // DNS is checked both at registration and at invocation; a fail-open choice never bypasses SSRF.
 for(const url of ['http://hooks.example.com/a','https://127.0.0.1/a','https://private.example.com/a'])assert.equal((await r.admin('hooks/register',{point:'token',appId:app.id,url})).status,400);
 const rebinding=await create({point:'token',appId:app.id,url:'https://hooks.example.com/token',failClosed:false});edge.privateHosts.add('hooks.example.com');
 const before=edge.received.length;await assert.rejects((await signIn(r,config,{redirect:`${RP}/hooks`})).grant());assert.equal(edge.received.length,before);
 edge.privateHosts.delete('hooks.example.com');await disable(rebinding.id);
 // Self-registration may deny an otherwise allowed outside domain, with the same non-enumerating email response.
 await r.admin('people/domain',{domain:'outside.example.com'});
 edge.responses.set('/registration',request=>({body:{allow:request.data.email.endsWith('@example.com'),...(request.data.email.endsWith('@example.com')?{profile:{name:'Hooked employee'}}:{})}}));
 const registration=await create({point:'registration',url:'https://hooks.example.com/registration',allowedFields:['name']});
 const mail=(await r.mails()).length;
 assert.equal((await r.call('/auth/identity/email/request',{method:'POST',data:{email:'outside@outside.example.com'}})).status,202);
 assert.equal(await r.db.prepare("SELECT id FROM oa_operators WHERE email='outside@outside.example.com'").first(),null);assert.equal((await r.mails()).length,mail);
 await r.admin('people/domain',{domain:'example.com'});
 await (await import('./runtime.mjs')).emailSession(r,'new@example.com');assert.equal((await r.db.prepare("SELECT display_name FROM oa_operators WHERE email='new@example.com'").first()).display_name,'Hooked employee');
 await disable(registration.id);
 // Directory source matching uses immutable source ids; the hook may deny or change an allowed profile field, never rebind a subject.
 const imported=await create({point:'user_import',url:'https://hooks.example.com/import',allowedFields:['name']});
 edge.responses.set('/import',{body:{allow:false}});
 assert.equal((await r.admin('directory/source',{source:'hr',records:[{sourceId:'synthetic-auth-3',personId:'bob',fields:{title:'Analyst'}}]})).status,403);
 assert.equal(await r.db.prepare("SELECT 1 FROM auth_person_sources WHERE source_id='synthetic-auth-3'").first(),null);
 edge.responses.set('/import',{body:{allow:true,profile:{name:'Robert Hook'}}});
 assert.equal((await r.admin('directory/source',{source:'hr',records:[{sourceId:'synthetic-auth-3',personId:'bob',fields:{title:'Analyst'}}]})).status,200);
 assert.equal((await r.db.prepare("SELECT display_name FROM oa_operators WHERE id='bob'").first()).display_name,'Robert Hook');await disable(imported.id);
 // An independent service provider reads the hook attribute from the signed assertion.
 const {spCredentials,idpCertificates,serviceProvider,metadataOf,addApp,signIn:signInSaml,posted}=await import('./saml-helpers.mjs');
 const sp=await spCredentials('hook-saml.example.com'),saml=serviceProvider(r,{entity:'https://hook-saml.example.com',sp,idpCerts:await idpCertificates(r)});
 const sa=await addApp(r,{metadata:metadataOf(saml,sp),sign:'both',attributes:'email=email'});
 const sh=await create({point:'saml',appId:sa.id,url:'https://hooks.example.com/saml',allowedFields:['cost_center']});
 const output=await saml.validatePostResponseAsync({SAMLResponse:(await posted(await signInSaml(r,saml,r.ada))).SAMLResponse});assert.equal(output.profile.cost_center,'CC-42');
 await disable(sh.id);
 // Ordinary sessions, signed-out callers and stale administrator email proof cannot configure hooks.
 for(const cookie of [undefined,r.ada])assert.equal((await r.call('/api/auth/hooks/register',{method:'POST',cookie,data:{point:'registration',url:'https://hooks.example.com/registration'}})).status,cookie?403:401);
 // Revocation while a remote hook is running is rechecked before any token is signed.
 let entered,release;const started=new Promise(done=>{entered=done;}),held=new Promise(done=>{release=done;});
 edge.responses.set('/held',async()=>{entered();await held;return {body:{claims:{cost_center:'CC-42'}}};});
 const heldHook=await create({point:'token',appId:app.id,url:'https://hooks.example.com/held',allowedFields:['cost_center']});
 const pendingFlow=await signIn(r,config,{redirect:`${RP}/hooks`}),pendingGrant=pendingFlow.grant();
 await started;assert.equal((await r.admin('people/suspend',{personId:'ada'})).status,200);release();await assert.rejects(pendingGrant);await disable(heldHook.id);
 r.tick=()=>{r.now=Date.now()+660000;};assert.equal((await r.admin('hooks/register',{point:'registration',url:'https://hooks.example.com/registration'})).status,403);
});

test('resource APIs use live app roles and tenant resources for employees and distinct accountable OAuth services',async t=>{
 const r=await samlInstall(t);
 const {addApp}=await import('./saml-helpers.mjs');
 const app=await addApp(r,{name:'Engineering documents',entityId:'https://documents.example.com',acsUrl:'https://documents.example.com/acs',assign:[]});
 const command=async(path,data,status=200)=>{const response=await r.admin(path,data);assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const group=await command('groups/create',{name:'Document editors'},201);await command('groups/add',{groupId:group.id,personId:'ada'});
 const api=await command('resource-apis/register',{appId:app.id,name:'Documents API',audience:'https://documents.example.com/api',scopes:['read','write'],roles:[{role:'editor',scopes:['read','write'],resources:['document:*'],relations:{ownerId:'$person'}},{role:'reader',scopes:['read'],resources:['document:*']}],resources:[{id:'document:budget',attributes:{ownerId:'ada'}},{id:'document:private',attributes:{ownerId:'bob'}}]},201);
 await command('resource-apis/assign',{apiId:api.id,principalType:'group',principalId:group.id,role:'editor'});
 const check=async(data,cookie=r.ada,token)=>{
  const response=await r.call('/api/auth/resource-apis/check',{method:'POST',cookie,data:{apiId:api.id,action:'read',resource:'document:budget',...data},headers:token?{authorization:'bearer '+token,origin:''}:{}});return {response,body:await response.json()};
 };
 assert.equal((await check({})).body.allowed,true);assert.equal((await check({action:'write'})).body.allowed,true);
 assert.equal((await check({},r.bob)).body.allowed,false,'unassigned role denied');
 assert.equal((await check({resource:{id:'document:budget',organizationId:'foreign'}})).body.allowed,false);
 assert.equal((await check({resource:{id:'document:private',ownerId:'ada'}})).body.allowed,false,'caller cannot forge registered relation');
 assert.equal((await check({audience:'https://wrong.example.com/api'})).body.allowed,false);
 assert.equal((await check({action:'delete'})).body.allowed,false);
 assert.equal((await check({subject:'bob'})).response.status,403);
 const pair=await generateKeyPair('ES256'),jwk={...await exportJWK(pair.publicKey),kid:'synthetic-auth-1',alg:'ES256',use:'sig'};
 const service=await command('resource-apis/service-create',{apiId:api.id,name:'Search indexer',purpose:'Index explicitly assigned documents',ownerId:'ada',jwks:{keys:[jwk]},scopes:['read'],resources:['document:budget'],expiresAt:new Date(r.now+3600000).toISOString()},201);
 const assertion=async(audience=r.origin+'/oidc/token')=>new (await import('jose')).SignJWT({jti:crypto.randomUUID()}).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(service.clientId).setSubject(service.clientId).setAudience(audience).setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(pair.privateKey);
 const oauth=async(scope='read',signed)=>r.call('/oidc/token',{method:'POST',form:{grant_type:'client_credentials',client_id:service.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:signed??await assertion(),scope}});
 assert.equal((await oauth('write')).status,400,'service cannot request excess scope');assert.equal((await oauth('read',await assertion('https://wrong.example.com/oidc/token'))).status,401);
 const signed=await assertion(),issued=await oauth('read',signed);assert.equal(issued.status,200,await issued.clone().text());const token=(await issued.json()).access_token;
 const claims=decodeJwt(token);assert.notEqual(claims.sub,'ada');assert.equal(claims.aud,'https://documents.example.com/api');assert.equal(claims.amr,undefined);assert.equal(claims.sid,undefined);
 assert.equal((await oauth('read',signed)).status,401,'one-use client assertion');
 assert.equal((await check({},undefined,token)).body.allowed,true);assert.equal((await check({action:'write'},undefined,token)).body.allowed,false);
 const foreign=await command('organizations/create',{name:'Unrelated employer'},201);
 assert.equal((await r.call('/org/'+foreign.id+'/api/auth/resource-apis/check',{method:'POST',data:{apiId:api.id,action:'read',resource:'document:budget'},headers:{authorization:'Bearer '+token}})).status,401,'active cross-employer bearer denied');
 const otherApi=await command('resource-apis/register',{appId:app.id,name:'Different audience',audience:'https://documents.example.com/other-api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['record:1']}],resources:[{id:'record:1'}]},201);
 assert.equal((await check({apiId:otherApi.id,resource:'record:1'},undefined,token)).response.status,401,'token for another registered audience denied');
 assert.equal((await check({subject:'ada'},undefined,token)).response.status,403);
 assert.equal((await r.call('/api/auth/people',{headers:{authorization:'Bearer '+token}})).status,401);
 assert.equal((await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+token}})).status,401,'API token has no identity audience');
 assert.equal((await r.call('/auth/passkeys/register/options',{method:'POST',data:{},headers:{authorization:'Bearer '+token}})).status,401);
 await command('resource-apis/assign',{apiId:api.id,principalType:'group',principalId:group.id,remove:true});
 assert.equal((await check({})).body.allowed,false);assert.equal((await check({},undefined,token)).body.allowed,false,'role removal changes next service decision');
 assert.ok(!(await (await r.call('/api/auth/me',{cookie:r.ada})).json()).launcher.some(a=>a.id===app.id));
 await command('resource-apis/assign',{apiId:api.id,principalType:'group',principalId:group.id,role:'reader'});
 assert.equal((await check({})).body.allowed,true);assert.equal((await check({action:'write'})).body.allowed,false);
 await command('resource-apis/service-revoke',{clientId:service.clientId});assert.equal((await check({},undefined,token)).response.status,401);assert.equal((await oauth()).status,401);
 const audit=await (await r.call('/api/auth/activity',{cookie:r.owner.cookie})).json();assert.ok(audit.some(a=>a.event==='resource_permission_check'&&a.actor_id===service.clientId));

});

import {refreshLifecycle} from './refresh-flow.mjs';
test('native offline consent and SDK rotation preserve device binding, detect reuse and concurrency, and end resource authority on expiry, revocation, suspension and app removal',refreshLifecycle);
