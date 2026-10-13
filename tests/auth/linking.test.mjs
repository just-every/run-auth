import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openLink} from './link/runtime.mjs';
import {AUTH_ORIGIN,APP_ORIGIN} from './link/origins.mjs';
import {emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';

const INTERFACE='oidc-provider@1',APP_SETUP='app-setup-token-0123456789abcdef';

test('an app links with a one-use token, signs a person in through Auth, and Sign out everywhere ends that app session',async t=>{
 const r=await openLink();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');
 const owner=await register(r,await emailSession(r,'owner@example.com'));
 await r.call('/.well-known/openid-configuration');
 // Signing keys publish a cache lifetime before use; this run does not wait it out.
 await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(Date.now()-1).run();

 const minted=await r.call('/api/auth/apps/link-token',{method:'POST',data:{origin:APP_ORIGIN},cookie:owner.cookie});
 assert.equal(minted.status,201,await minted.clone().text());
 const envelope=await minted.json();
 assert.deepEqual(envelope.callbacks,[APP_ORIGIN+'/.well-known/rer-link/callback',APP_ORIGIN+'/auth/oidc/auth/callback',APP_ORIGIN+'/auth/oidc/auth/logout'].sort());
 assert.ok(envelope.expiresAt-envelope.issuedAt<=3600000);

 // What rer setup does in the app: open its own approval, claim its owner, then ask Auth.
 assert.equal((await r.send(APP_ORIGIN+'/auth/dependencies/setup',{method:'POST',json:{issuer:AUTH_ORIGIN,interface:INTERFACE,token:APP_SETUP}})).status,200);
 assert.equal((await r.send(APP_ORIGIN+'/auth/bootstrap',{method:'POST',json:{token:APP_SETUP,displayName:'Owner'}})).status,303);
 const initiate=json=>r.send(AUTH_ORIGIN+'/oidc/link/initiate',{method:'POST',json,cookies:false});
 const linked=await initiate({origin:APP_ORIGIN,interface:INTERFACE,token:envelope.token});
 assert.equal(linked.status,200,await linked.clone().text());
 assert.equal((await linked.json()).source,'token');
 const status=await(await r.send(APP_ORIGIN+'/auth/dependencies/status')).json();
 assert.deepEqual(status.links,[{interface:INTERFACE,issuer:AUTH_ORIGIN,linked:true}]);
 assert.equal((await initiate({origin:APP_ORIGIN,interface:INTERFACE,token:envelope.token})).status,403,'a link token is single use');
 assert.ok((await r.mails()).some(m=>m.subject.includes(APP_ORIGIN)),'administrators hear about a token-made link');

 // A person signs in to the app through Auth in one browser.
 r.jar[APP_ORIGIN].clear();r.jar[AUTH_ORIGIN].set(...owner.cookie.split('='));
 const signedIn=await r.follow(APP_ORIGIN+'/auth/oidc/auth/start',{method:'POST',json:{returnTo:'/'}});
 assert.ok(signedIn.status<400,`sign-in ended at ${signedIn.status}`);
 const session=await r.send(APP_ORIGIN+'/auth/session');
 assert.equal(session.status,200);
 assert.equal((await session.json()).operator.email,'owner@example.com');

 const everywhere=await r.call('/api/auth/signout-everywhere',{method:'POST',data:{},cookie:owner.cookie});
 assert.equal(everywhere.status,200);
 assert.equal((await everywhere.json()).apps,1);
 assert.equal((await r.send(APP_ORIGIN+'/auth/session')).status,401,'the app session ended with the back-channel logout');
 assert.equal((await r.call('/api/auth/me',{cookie:owner.cookie})).status,401);
});
