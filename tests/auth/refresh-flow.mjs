import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {SignJWT,calculateJwkThumbprint,decodeJwt,exportJWK,generateKeyPair} from 'jose';
import {samlInstall,browse} from './saml-helpers.mjs';
import {createSessionClient} from '../../packages/session-sdk/index.mjs';

export async function refreshLifecycle(t) {
 const r=await samlInstall(t);await r.call('/.well-known/openid-configuration');
 await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const delivered=[],edge=createServer(async(req,res)=>{let body='';for await(const part of req)body+=part;delivered.push(decodeJwt(new URLSearchParams(body).get('logout_token')));res.writeHead(200);res.end();});
 await new Promise(done=>edge.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>edge.close(done)));
 r.edges={'https://native.example.com':`http://127.0.0.1:${edge.address().port}`};
 const command=async(path,data,status=200,cookie=r.owner.cookie)=>{const response=await r.call('/api/auth/'+path,{method:'POST',data,cookie});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const app=await command('oidc-apps/create',{name:'Northwind field documents',authMethod:'none',redirectUris:'com.northwind.field:/callback',backchannelLogoutUri:'https://native.example.com/logout'},201);
 const api=await command('resource-apis/register',{appId:app.id,name:'Field documents API',audience:'https://native.example.com/documents',scopes:['read','write'],roles:[{role:'reader',scopes:['read'],resources:['document:*']},{role:'editor',scopes:['read','write'],resources:['document:*']}],resources:[{id:'document:budget'},{id:'document:private'}]},201);
 await command('resource-apis/assign',{apiId:api.id,principalType:'person',principalId:'ada',role:'reader'});
 const profile=async(extra={})=>command('refresh/profile',{clientId:app.clientId,apiId:api.id,scopes:['read','write'],idleHours:1,absoluteHours:24,...extra});
 await profile();
 await command('refresh/profile',{clientId:app.clientId,apiId:api.id,scopes:['read'],idleHours:1,absoluteHours:24},403,r.ada);
 const key=await generateKeyPair('ES256',{extractable:true}),publicJwk=await exportJWK(key.publicKey),jkt=await calculateJwkThumbprint(publicJwk);
 let calls=0,saved=[],cleared=0;
 const transport=async(url,options={})=>{const u=new URL(url);if(u.pathname==='/oidc/token')calls++;return r.call(u.pathname+u.search,{method:options.method,headers:Object.fromEntries(new Headers(options.headers)),form:options.body?Object.fromEntries(new URLSearchParams(options.body)):undefined});};
 const make=()=>createSessionClient({issuer:r.origin,clientId:app.clientId,redirectUri:'com.northwind.field:/callback',keyPair:key,fetch:transport,storage:{async save(v){saved.push(v);},async clear(){cleared++;}}});
 const connect=async({scopes=['read'],deviceName='Erin’s managed field tablet',decision='approve',who=r.ada}={})=>{
  const sdk=await make(),auth=await sdk.authorization({resource:'https://native.example.com/documents',scopes,deviceName});
  r.tick();const u=new URL(auth.url),response=await r.call(u.pathname+u.search,{cookie:who});
  const location=new URL(response.headers.get('location'),r.origin);
  if(!location.searchParams.has('refreshConsent'))return {sdk,error:location.searchParams.get('error')};
  const id=location.searchParams.get('refreshConsent'),view=await (await r.call('/api/auth/refresh?refreshConsent='+id,{cookie:who})).json();
  assert.equal(view.consent.deviceName,deviceName);assert.deepEqual(view.consent.scopes,scopes);
  assert.equal((await r.call('/api/auth/refresh?refreshConsent='+id,{cookie:r.owner.cookie})).status,200);
  assert.equal((await (await r.call('/api/auth/refresh?refreshConsent='+id,{cookie:r.owner.cookie})).json()).consent,null);
  const consent=await command('refresh/consent',{id,decision},200,who);
  assert.equal((await r.call('/api/auth/refresh/consent',{method:'POST',data:{id,decision},cookie:who})).status,409,'consent is one use');
  if(decision==='deny'){await assert.rejects(sdk.complete(consent.redirect));return {sdk};}
  const tokens=await sdk.complete(consent.redirect);return {sdk,tokens};
 };
 const proof=async(path,access,keyPair=key)=>new SignJWT({jti:crypto.randomUUID(),iat:Math.floor(r.now/1000),htm:'POST',htu:r.origin+path,...(access?{ath:await (await import('../../src/auth/core.mjs')).hash(access)}:{})}).setProtectedHeader({alg:'ES256',typ:'dpop+jwt',jwk:await exportJWK(keyPair.publicKey)}).sign(keyPair.privateKey);
 const rawRefresh=async(token,extra={},keyPair=key)=>r.call('/oidc/token',{method:'POST',form:{grant_type:'refresh_token',client_id:app.clientId,refresh_token:token,...extra},headers:{dpop:await proof('/oidc/token',null,keyPair)}});
 const check=async(token,extra={},keyPair=key)=>r.call('/api/auth/resource-apis/check',{method:'POST',data:{apiId:api.id,action:'read',resource:'document:budget',...extra},headers:{authorization:'DPoP '+token,dpop:await proof('/api/auth/resource-apis/check',token,keyPair)}});
 const inventory=async(cookie=r.ada,query='')=>(await (await r.call('/api/auth/refresh'+query,{cookie})).json()).grants;
 assert.equal((await connect({scopes:['write']})).error,'invalid_scope','consent cannot exceed the current app role');
 await connect({decision:'deny'});
 assert.equal((await inventory()).length,0);
 const first=await connect(),before=calls;assert.equal(first.error,undefined,'approved native flow');
 const rotations=await Promise.all([first.sdk.refresh(),first.sdk.refresh(),first.sdk.refresh()]);
 assert.equal(calls-before,1,'one SDK refresh serves concurrent callers');assert.equal(new Set(rotations.map(v=>v.refresh_token)).size,1);assert.notEqual(rotations[0].refresh_token,first.tokens.refresh_token);assert.equal(saved.at(-1).refresh_token,rotations[0].refresh_token);
 assert.equal((await check(rotations[0].access_token)).status,200);assert.equal((await (await check(rotations[0].access_token)).json()).allowed,true);
 assert.equal((await (await check(rotations[0].access_token,{action:'write'})).json()).allowed,false);
 const stranger=await generateKeyPair('ES256',{extractable:true});assert.equal((await rawRefresh(rotations[0].refresh_token,{},stranger)).status,401,'wrong device does not revoke a rightful grant');
 assert.equal((await check(rotations[0].access_token,{},stranger)).status,401);assert.equal((await check(rotations[0].access_token,{subject:'bob'})).status,403);
 assert.equal((await rawRefresh(rotations[0].refresh_token,{scope:'write'})).status,400);
 assert.equal((await rawRefresh(first.tokens.refresh_token)).status,400,'old token reuse ends family');
 assert.equal((await check(rotations[0].access_token)).status,401);await assert.rejects(first.sdk.refresh());assert.equal(first.sdk.getTokens(),null);assert.ok(cleared>0);
 assert.ok(delivered.some(c=>c.sid===first.tokens.grant_id));
 const revoke=await connect({deviceName:'Erin’s laptop'});
 await command('refresh/revoke',{id:revoke.tokens.grant_id},403,r.bob);
 await command('refresh/revoke',{id:revoke.tokens.grant_id},200,r.ada);
 assert.equal((await check(revoke.tokens.access_token)).status,401);assert.equal((await rawRefresh(revoke.tokens.refresh_token)).status,400);
 assert.ok((await inventory()).some(g=>g.id===revoke.tokens.grant_id&&g.status==='revoked'));
 const race=await connect({deviceName:'Concurrent raw clients'});
 const contested=await Promise.all([rawRefresh(race.tokens.refresh_token),rawRefresh(race.tokens.refresh_token)]);
 assert.ok(contested.some(res=>res.status===400));
 for(const res of contested)if(res.status===200)assert.equal((await check((await res.json()).access_token)).status,401,'concurrent raw replay cannot leave successor authority');
 // Offline use survives browser expiry. An independent process restarts with
 // the durable device key and token; it does not gain a browser/admin session.
 const durable=await connect({deviceName:'Restarted tablet'});await r.restart();
 const reused=await rawRefresh(durable.tokens.refresh_token);assert.equal(reused.status,200);const resumed=await reused.json();
 await r.db.prepare('UPDATE auth_sessions SET expires_at=? WHERE id=(SELECT session_id FROM auth_refresh_families WHERE id=?)').bind(r.now-1,resumed.grant_id).run();
 assert.equal((await rawRefresh(resumed.refresh_token)).status,200);
 assert.equal((await r.call('/api/auth/people',{headers:{authorization:'DPoP '+resumed.access_token}})).status,401);
 // Reauthenticate in the normal browser after its expiry.
 r.ada=await (await import('./runtime.mjs')).emailSession(r,'ada@example.com');
 await profile({idleHours:0.001,absoluteHours:0.01});
 const idle=await connect({deviceName:'Idle tablet'});r.tick=()=>{};r.now+=4000;
 assert.equal((await rawRefresh(idle.tokens.refresh_token)).status,400);assert.equal((await check(idle.tokens.access_token)).status,401);
 r.tick=()=>{r.now=Date.now();};r.tick();
 await profile({idleHours:0.001,absoluteHours:0.002});const absolute=await connect({deviceName:'Short absolute lifetime'});r.tick=()=>{};
 for(let step=0;step<2;step++){r.now+=2500;const res=await rawRefresh(absolute.sdk.getTokens().refresh_token);assert.equal(res.status,200);absolute.sdk.restore(await res.json());}
 r.now+=2500;assert.equal((await rawRefresh(absolute.sdk.getTokens().refresh_token)).status,400,'absolute expiry never slides');assert.equal((await check(absolute.sdk.getTokens().access_token)).status,401);
 r.tick=()=>{r.now=Date.now();};r.tick();await profile();
 const adminEnded=await connect({deviceName:'Administrator inventory'});assert.ok((await inventory(r.owner.cookie,'?refreshAdmin=1')).some(g=>g.id===adminEnded.tokens.grant_id));await command('refresh/revoke',{id:adminEnded.tokens.grant_id});assert.equal((await check(adminEnded.tokens.access_token)).status,401);
 const suspended=await connect({deviceName:'Suspended worker tablet'});await command('people/suspend',{personId:'ada'});assert.equal((await rawRefresh(suspended.tokens.refresh_token)).status,400);assert.equal((await check(suspended.tokens.access_token)).status,401);assert.ok(delivered.some(c=>c.sid===suspended.tokens.grant_id));
 // A second active worker proves app removal independently of suspension.
 await command('resource-apis/assign',{apiId:api.id,principalType:'person',principalId:'bob',role:'reader'});
 const removed=await connect({who:r.bob,deviceName:'Bob’s field tablet'});await command('company-apps/remove',{id:app.id});assert.notEqual((await rawRefresh(removed.tokens.refresh_token)).status,200);assert.equal((await check(removed.tokens.access_token)).status,401);assert.ok(delivered.some(c=>c.sid===removed.tokens.grant_id));
 const audit=await (await r.call('/api/auth/activity',{cookie:r.owner.cookie})).json();assert.ok(audit.some(row=>row.event==='refresh_consent_approved'));assert.ok(audit.some(row=>row.event==='refresh_rotated'));assert.ok(audit.some(row=>row.event==='refresh_family_ended'));
 // Strict RER discovery/issuance remains covered by protocol.test's live code
 // flow, which asserts there is no refresh token and refuses offline_access.
}
