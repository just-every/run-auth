import {test} from 'node:test';
import assert from 'node:assert/strict';
import {jwtVerify,createLocalJWKSet,generateKeyPair,SignJWT} from 'jose';
import {randomBytes} from 'node:crypto';
import {fixture} from './protocol-helpers.mjs';
import {register} from './webauthn.mjs';
import {requestProof,finishProof,sessionCookie} from './policy-helpers.mjs';
test('code flow preserves ES256 ID token claims and adds a userinfo access token',async t=>{
 const r=await fixture(t),grant=await r.authorize();assert.equal(grant.response.status,302);
 const redirect=new URL(grant.response.headers.get('location'));assert.equal(redirect.searchParams.get('iss'),r.origin);assert.equal(redirect.searchParams.get('state'),'state-to-bind');
 const response=await r.redeem(grant);assert.equal(response.status,200);const body=await response.json();assert.ok(body.id_token);assert.ok(body.access_token);assert.equal(body.refresh_token,undefined);
 const keys=await (await r.call('/oidc/jwks')).json();const {payload,protectedHeader}=await jwtVerify(body.id_token,createLocalJWKSet(keys),{issuer:r.origin,audience:'app',currentDate:new Date(r.now)});
 assert.equal(protectedHeader.alg,'ES256');assert.equal(payload.nonce,'nonce-to-bind');assert.equal(payload.email,'owner@example.com');assert.equal(payload.name,'owner');assert.equal(payload.role,undefined);assert.equal(payload.roles,undefined);assert.ok(payload.sid);assert.equal(payload.install_owner,true);assert.ok(payload.email_verified_at<r.now/1000+1);assert.notEqual(payload.sub,'owner');
 assert.equal((await r.redeem(grant)).status,400);
 const again=await (await r.redeem(await r.authorize())).json();const next=(await jwtVerify(again.id_token,createLocalJWKSet(keys),{currentDate:new Date(r.now)})).payload;assert.equal(next.sub,payload.sub);assert.equal(next.install_owner,undefined);
});
test('bad client and callback show local error without redirect; code needs matching PKCE and assertion',async t=>{
 const r=await fixture(t);
 for(const input of [{client:'unknown'},{redirect:'https://other.example.com/callback'},{redirect:r.clientOrigin+'/callback?changed=1'},{extra:{code_challenge_method:'plain'}}]){const out=await r.authorize(input);assert.equal(out.response.status,400);assert.equal(out.response.headers.get('location'),null);assert.match(out.response.headers.get('content-type'),/text\/html/);}
 const grant=await r.authorize();assert.equal((await r.redeem(grant,{code_verifier:'z'.repeat(43)})).status,400);assert.equal((await r.redeem(grant,{client_assertion:'not-a-jwt'})).status,401);assert.equal((await r.redeem(grant,{client_secret:'shared'})).status,401);assert.equal((await r.redeem(grant)).status,200);
});
test('only the advertised query response mode is answered; other modes are refused after client and callback checks',async t=>{
 const r=await fixture(t);assert.deepEqual((await (await r.call('/.well-known/openid-configuration')).json()).response_modes_supported,['query']);
 for(const mode of ['form_post','fragment','query.jwt','jwt','']) {
  const out=await r.authorize({extra:{response_mode:mode}}),location=new URL(out.response.headers.get('location'),r.origin);
  assert.equal(out.response.status,302);assert.equal(location.origin+location.pathname,r.clientOrigin+'/callback');assert.equal(location.searchParams.get('error'),'invalid_request');assert.equal(location.searchParams.get('state'),'state-to-bind');assert.equal(location.searchParams.get('code'),null);assert.equal(location.hash,'');
 }
 const refused=await r.authorize({extra:{response_mode:'form_post'}});assert.equal(refused.code,null);
 assert.ok((await r.authorize({extra:{response_mode:'query'}})).code);
 for(const input of [{client:'unknown'},{redirect:'https://other.example.com/callback'}]){const out=await r.authorize({...input,extra:{response_mode:'form_post'}});assert.equal(out.response.status,400);assert.equal(out.response.headers.get('location'),null);}
});
test('every client authentication failure at the token endpoint answers 401 invalid_client with the same body and headers',async t=>{
 const r=await fixture(t),grant=async()=>r.authorize(),seen=new Set();
 await r.db.prepare('INSERT INTO auth_clients(id,name,origin,sector_id,redirect_uris,jwks,owner_person_id,source,created_at,disabled_at) SELECT ?,name,origin,?,redirect_uris,jwks,owner_person_id,source,created_at,? FROM auth_clients WHERE id=?').bind('retired','install-B',r.now,'app').run();
 const assertion=await r.assertion(),otherKey=await generateKeyPair('ES256');
 const wrong=claims=>new SignJWT({jti:randomBytes(8).toString('hex'),...claims.payload}).setProtectedHeader({alg:'ES256',kid:'client-signing'}).setIssuer(claims.iss||'app').setSubject('app').setAudience(claims.aud||r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+(claims.exp??120)).sign(claims.key||r.privateKey);
 const failures=[{client_id:'unknown'},{client_id:'retired'},{client_id:undefined},{client_id:''},{client_assertion:'not-a-jwt'},{client_assertion:undefined},{client_assertion:await wrong({payload:{},iss:'other'})},{client_assertion:await wrong({payload:{},aud:'https://elsewhere.example/oidc/token'})},{client_assertion:await wrong({payload:{},exp:-60})},{client_assertion:await wrong({payload:{},key:otherKey.privateKey})},{client_secret:'shared'},{client_assertion_type:'wrong'}];
 for(const extra of failures) {
  const out=await grant(),form={grant_type:'authorization_code',client_id:'app',redirect_uri:r.clientOrigin+'/callback',code:out.code,code_verifier:out.verifier,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await r.assertion(),...extra};
  for(const [k,v] of Object.entries(form))if(v===undefined)delete form[k];
  const response=await r.call('/oidc/token',{method:'POST',form});assert.equal(response.status,401,JSON.stringify(extra).slice(0,80));
  seen.add(JSON.stringify([await response.text(),[...response.headers].sort()]));
 }
 assert.equal(seen.size,1);assert.equal(JSON.parse(JSON.parse([...seen][0])[0]).error,'invalid_client');
 assert.equal((await r.redeem(await grant(),{client_assertion:assertion})).status,200);
});
test('assertion replay is refused and install_owner wins only one concurrent code exchange',async t=>{
 const r=await fixture(t),a=await r.authorize(),b=await r.authorize(),assertion=await r.assertion('single-assertion');
 assert.equal((await r.redeem(a,{client_assertion:assertion})).status,200);assert.equal((await r.redeem(b,{client_assertion:assertion})).status,401);
 await r.db.prepare("UPDATE auth_clients SET owner_claimed_at=NULL WHERE id='app'").run();
 const [c,d]=await Promise.all([r.authorize(),r.authorize()]);const replies=await Promise.all([c,d].map(async grant=>{const res=await r.redeem(grant);return {status:res.status,body:await res.json()};}));const keys=createLocalJWKSet(await(await r.call('/oidc/jwks')).json());
 const payloads=await Promise.all(replies.map(async res=>{assert.equal(res.status,200);return (await jwtVerify(res.body.id_token,keys,{currentDate:new Date(r.now)})).payload;}));assert.equal(payloads.filter(p=>p.install_owner).length,1);
});
test('keys publish before signing, ciphertext hides private material and rotation retains valid-token key',async t=>{
 const r=await fixture(t),old=r.stage.kid,owner=await register(r,r.cookie);
 const staged=await r.call('/api/auth/keys/stage',{method:'POST',data:{},cookie:owner.cookie});assert.equal(staged.status,201);const stage=await staged.json();
 const stored=await r.db.prepare('SELECT encrypted_private FROM auth_signing_keys WHERE kid=?').bind(stage.kid).first();assert.equal(stored.encrypted_private.includes('"d"'),false);
 const keys=await(await r.call('/oidc/jwks')).json();assert.ok(keys.keys.some(k=>k.kid===stage.kid));
 let token=await(await r.redeem(await r.authorize())).json();assert.equal((await jwtVerify(token.id_token,createLocalJWKSet(keys),{currentDate:new Date(r.now)})).protectedHeader.kid,old);
 r.now+=300001;token=await(await r.redeem(await r.authorize())).json();assert.equal((await jwtVerify(token.id_token,createLocalJWKSet(keys),{currentDate:new Date(r.now)})).protectedHeader.kid,stage.kid);
 // Rotation is a sensitive owner action: ten minutes on, it needs a new local email confirmation.
 const confirmed=await finishProof(r,await requestProof(r,'owner@example.com',owner.cookie));assert.equal(confirmed.status,200);
 assert.equal((await r.call('/api/auth/keys/retire',{method:'POST',data:{kid:old},cookie:sessionCookie(confirmed)})).status,200);assert.ok((await(await r.call('/oidc/jwks')).json()).keys.some(k=>k.kid===old));r.now+=300001;assert.equal((await(await r.call('/oidc/jwks')).json()).keys.some(k=>k.kid===old),false);
});
test('production clients refuse HTTP and all 127/8; dev serves loopback clients and marks tokens',async t=>{
 const prod=await fixture(t),issued=await prod.authorize();
 await prod.db.prepare("UPDATE auth_sessions SET amr='[\"dev\"]'").run();assert.equal((await prod.call('/api/auth/me',{cookie:prod.cookie})).status,401);assert.equal((await prod.redeem(issued)).status,400);
 for(const origin of ['http://app.example.com','https://127.2.3.4','https://[::1]']){await prod.db.prepare("UPDATE auth_clients SET origin=? WHERE id='app'").bind(origin).run();assert.equal((await prod.authorize()).response.status,400);}
 const dev=await fixture(t,{local:true}),reply=await dev.redeem(await dev.authorize()),body=await reply.json();assert.equal(reply.status,200);const claims=(await jwtVerify(body.id_token,createLocalJWKSet(await(await dev.call('/oidc/jwks')).json()),{currentDate:new Date(dev.now)})).payload;assert.deepEqual(claims.amr,['dev']);
 await dev.db.prepare("UPDATE auth_clients SET origin='https://remote.example.com' WHERE id='app'").run();assert.equal((await dev.authorize()).response.status,400);
});
