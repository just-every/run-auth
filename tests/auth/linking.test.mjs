import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {openLink} from './link/runtime.mjs';
import {AUTH_ORIGIN,APP_ORIGIN} from './link/origins.mjs';
import {emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';
import {scriptedApps} from './link/scripted-app.mjs';
import {mint,file,approve,proposal,passkeyPerson} from './agents-helpers.mjs';

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
 const followup=async()=>{const response=await r.call('/api/auth/followup',{cookie:owner.cookie});assert.equal(response.status,200);return response.json();};
 const pending=(await followup()).obligations.find(ob=>ob.kind==='app_link_token');assert.equal(pending.state,'open');
 for(const secret of [envelope.token,createHash('sha256').update(envelope.token).digest('base64url')])assert.ok(!JSON.stringify(await followup()).includes(secret),'follow-up never exposes link credentials or their digests');

 // What rer setup does in the app: open its own approval, claim its owner, then ask Auth.
 assert.equal((await r.send(APP_ORIGIN+'/auth/dependencies/setup',{method:'POST',json:{issuer:AUTH_ORIGIN,interface:INTERFACE,token:APP_SETUP}})).status,200);
 assert.equal((await r.send(APP_ORIGIN+'/auth/bootstrap',{method:'POST',json:{token:APP_SETUP,displayName:'Owner'}})).status,303);
 const initiate=json=>r.send(AUTH_ORIGIN+'/oidc/link/initiate',{method:'POST',json,cookies:false});
 const linked=await initiate({origin:APP_ORIGIN,interface:INTERFACE,token:envelope.token});
 assert.equal(linked.status,200,await linked.clone().text());
 assert.equal((await linked.json()).source,'token');
 assert.equal((await followup()).obligations.find(ob=>ob.id===pending.id).state,'completed');
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

// An install with an owner and scripted apps; links by token as `rer setup` does.
async function scriptedInstall(t) {
 const apps=scriptedApps(),r=await openLink({scripted:apps});apps.bind(r);t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');
 const owner=await register(r,await emailSession(r,'owner@example.com'));
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(Date.now()-1).run();
 const linkByToken=async app=>{
  const {token}=await(await r.call('/api/auth/apps/link-token',{method:'POST',data:{origin:app.origin},cookie:owner.cookie})).json();
  return r.send(AUTH_ORIGIN+'/oidc/link/initiate',{method:'POST',json:{origin:app.origin,interface:INTERFACE,token},cookies:false});
 };
 const request=async(origin,cookie)=>{const response=await r.call('/api/auth/apps/request',{method:'POST',data:{origin},cookie});assert.equal(response.status,201);return response.json();};
 const approveRequest=async(id,cookie)=>{const response=await r.call('/api/auth/apps/approve',{method:'POST',data:{id},cookie});return {status:response.status,error:(await response.json()).error};};
 return {r,apps,owner,linkByToken,request,approveRequest};
}

test('a link that would take over another app\'s identity names that app to the approver, and runs only on an approval that named it',async t=>{
 const {r,apps,owner,linkByToken,request,approveRequest}=await scriptedInstall(t);
 const victim=await apps.add('https://victim.example.net');
 assert.equal((await linkByToken(victim)).status,200);
 await r.person('pat','pat@example.com');const pat=await emailSession(r,'pat@example.com');
 const before=await apps.signIn(victim,pat);assert.equal(before.status,200);

 // A sector is public: another origin publishes the victim's with its own key.
 const evil=await apps.add('https://evil.example.org',{sector:victim.sector});
 const moved=[{name:'App at victim.example.net',origin:victim.origin,change:'moves'}];
 const key=await mint(r,owner.cookie);
 const filed=await file(r,key,{kind:'approve_app_link',target:evil.origin,reason:'Link the reporting app'});
 assert.deepEqual(JSON.parse((await proposal(r,filed)).effect).app.replaces,moved,'the agent proposal names the app it takes over');
 assert.deepEqual((await request(evil.origin,owner.cookie)).replaces,moved,'so does the Apps page');

 // Approvals filed before another app held the sector: both are refused, nothing moves.
 const late=await apps.add('https://late.example.net');
 const lateRequest=await request(late.origin,owner.cookie),lateProposal=await file(r,key,{kind:'approve_app_link',target:late.origin,reason:'Link the late app'});
 assert.deepEqual(lateRequest.replaces,[]);
 const holder=await apps.add('https://holder.example.net',{sector:late.sector});
 assert.equal((await linkByToken(holder)).status,200);
 assert.deepEqual(await approveRequest(lateRequest.id,owner.cookie),{status:409,error:'app_changed_since_request'});
 const admin=await passkeyPerson(r,'adm','adm@example.com','admin');
 const stale=await approve(r,admin,lateProposal);
 assert.equal(stale.status,409);assert.equal((await stale.json()).error,'proposal_stale');
 assert.deepEqual((await r.db.prepare('SELECT origin FROM auth_clients WHERE sector_id=?').bind(late.sector).first()).origin,holder.origin);
 const after=await apps.signIn(victim,pat);
 assert.deepEqual([after.status,after.claims.aud,after.claims.sub],[200,before.claims.aud,before.claims.sub],'the victim keeps its client and people\'s identifiers');
});

test('only the owner accepts a lower interface version, also when an administrator approves a re-link',async t=>{
 const {r,apps,owner,linkByToken,request,approveRequest}=await scriptedInstall(t);
 const app=await apps.add('https://versions.example.net',{version:'oidc-provider@1.2'});
 assert.equal((await linkByToken(app)).status,200);
 app.version='oidc-provider@1.0';
 const versions=async()=>(await r.db.prepare('SELECT version,approved_at IS NOT NULL AS approved FROM auth_client_versions WHERE client_id=? ORDER BY version').bind(app.clientId).all()).results.map(v=>`${v.version}:${v.approved?'approved':'held'}`);

 const admin=await passkeyPerson(r,'adm','adm@example.com','admin');
 assert.deepEqual(await approveRequest((await request(app.origin,admin.cookie)).id,admin.cookie),{status:409,error:'downgrade_requires_owner'});
 const key=await mint(r,owner.cookie);
 const proposed=await approve(r,admin,await file(r,key,{kind:'approve_app_link',target:app.origin,reason:'Re-link the versions app'}));
 assert.equal((await proposed.json()).followUp,'failed','an administrator\'s proposal approval does not link the lower version');
 assert.deepEqual(await versions(),['oidc-provider@1.0:held','oidc-provider@1.2:approved']);

 const accepted=await r.call('/api/auth/apps/version',{method:'POST',data:{id:app.clientId,version:'oidc-provider@1.0'},cookie:owner.cookie});
 assert.equal(accepted.status,200);
 assert.deepEqual(await approveRequest((await request(app.origin,admin.cookie)).id,admin.cookie),{status:200,error:undefined},'after the owner accepted it');
 const followup=async id=>{const response=await r.call('/api/auth/followup',{cookie:owner.cookie});assert.equal(response.status,200);return (await response.json()).obligations.find(ob=>ob.source_id===id);};
 const uncertain=await file(r,key,{kind:'approve_app_link',target:app.origin,reason:'Confirm app callback outcome'});
 app.refuseCallback=true;
 const refused=await approve(r,owner,uncertain);assert.equal(refused.status,200);assert.equal((await refused.json()).followUp,'failed');
 assert.equal((await proposal(r,uncertain)).status,'done');
 assert.equal((await followup(uncertain)).state,'open','proposal claim and redeemed client cannot stand in for callback confirmation');
 assert.equal((await followup(uncertain)).last_error,'approved_app_link_effect_unconfirmed');
 app.refuseCallback=false;
 const confirmed=await file(r,key,{kind:'approve_app_link',target:app.origin,reason:'Finish app setup with successful callback'});
 const keyId=(await proposal(r,confirmed)).key_id;
 assert.equal((await r.call('/api/auth/agents/revoke',{method:'POST',cookie:owner.cookie,data:{keyId}})).status,200);
 assert.equal((await followup(confirmed)).state,'open','ending a preparer key preserves a filed human decision');
 assert.equal((await approve(r,owner,confirmed)).status,200);
 assert.equal((await followup(confirmed)).state,'completed','real callback and redemption confirm the link');

});
