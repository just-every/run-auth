import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openApp,cookieOf} from './runtime.mjs';

test('emitted Auth protects private documents and Base authority seams; email proof belongs to the requesting browser',async t=>{
 const app=await openApp();t.after(()=>app.close());
 const baseCookie=await app.claim();
 assert.equal((await app.get('/auth/session',{cookie:baseCookie})).status,200);
 assert.equal((await app.get('/api/auth/me',{cookie:baseCookie})).status,401,'Base owner bootstrap grants no Auth session');
 assert.equal((await app.post('/auth/identity/passkeys/register/options',{},baseCookie)).status,401);
 for(const path of ['/cdn-cgi/local/explorer/api/config','/cdn-cgi/handler/scheduled','/.rer/local/dev-key.env','/.seed/installer/state.json'])assert.equal((await app.get(path)).status,404,path);
 const anonymous=await app.get('/app/people');assert.equal(anonymous.status,303);assert.match(anonymous.headers.get('location'),/^\/signin/);
 const setup=await app.post('/setup');assert.equal(setup.status,401);
 const requested=await app.post('/auth/identity/email/request',{email:app.vars.OWNER_EMAIL,returnTo:'/app/methods?from=oidc'});
 assert.equal(requested.status,202);const link=await app.link(),binding=cookieOf(requested);
 assert.equal((await app.get('/__dev/outbox')).status,404);
 assert.equal((await app.post('/auth/identity/email/confirm',{token:link.searchParams.get('token')})).status,400);
 const confirmed=await fetch(link,{method:'POST',redirect:'manual',headers:{origin:app.origin,'content-type':'application/x-www-form-urlencoded',cookie:binding},body:''});
 assert.equal(confirmed.status,303);assert.equal(confirmed.headers.get('location'),'/app/methods?from=oidc');const cookie=cookieOf(confirmed);
 const me=await(await app.get('/api/auth/me',{cookie})).json();assert.equal(me.user.email,app.vars.OWNER_EMAIL);assert.equal(me.isAdmin,false);
 const finished=await fetch(app.origin+'/setup',{method:'POST',redirect:'manual',headers:{origin:app.origin,'content-type':'application/x-www-form-urlencoded',cookie},body:'confirm=yes'});assert.equal(finished.status,303);
 assert.equal((await app.get('/app/account',{cookie})).status,200);
 assert.equal((await app.get('/app/people',{cookie})).status,403);
 assert.equal((await app.post('/api/auth/people/invite',{email:'intruder@example.com'},cookie)).status,403);
 // These inherited routes bypass Auth passkey policy if exposed by the seed.
 for(const path of ['/auth/operators','/auth/invite','/auth/operator/role','/auth/operator/status','/auth/domain-rules','/auth/magic-link','/auth/confirm']){
  assert.equal((await app.get(path,{cookie})).status,404,path);
  assert.equal((await app.post(path,{email:'intruder@example.com',role:'owner'},cookie)).status,404,path);
 }
 const register=await app.post('/auth/identity/passkeys/register/options',{},cookie);assert.equal(register.status,200,'first enrollment requires own Auth session');
 assert.equal((await app.post('/auth/identity/passkeys/register/options')).status,401);
 assert.equal((await app.get('/.well-known/openid-configuration')).status,200);
 const jwks=await(await app.get('/oidc/jwks')).json();assert.ok(jwks.keys.length>0,'discovery stages genuine encrypted signing key');assert.ok(jwks.keys.every(key=>!key.d));
 assert.equal((await app.post('/api/auth/keys/stage',{},cookie)).status,403);
 await app.post('/api/auth/signout',{},cookie);
 assert.equal((await app.get('/api/auth/me',{cookie})).status,401);
});
