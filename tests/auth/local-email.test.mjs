import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openRuntime,emailSession} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {requestProof,finishProof,beginPasskey,finishPasskey,sessionCookie} from './policy-helpers.mjs';

const post=(data={},cookie)=>({method:'POST',data,cookie});
const change=(r,cookie,providerId='company')=>r.call('/api/auth/people/domain-rule',post({domain:'company.example',providerId},cookie));
async function fixture(t) {
 const r=await openRuntime();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');
 r.upstreamProviders=[{id:'company',preset:'google',clientId:'test-client',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only'}];
 r.owner=await register(r,await emailSession(r,'owner@example.com'));
 return r;
}
async function refused(r,cookie) {
 for(const [path,data] of [
  ['/people/domain-rule',{domain:'company.example',providerId:'company'}],
  ['/people/domain-rule',{domain:'company.example',providerId:''}],
  ['/people/domain',{domain:'new.example'}],
  ['/domains/add',{domain:'alias.example'}],
 ]) {
  const response=await r.call('/api/auth'+path,post(data,cookie));
  assert.equal(response.status,403,path);assert.equal((await response.json()).error,'local_email_step_up_required');
 }
}

test('domain changes require recent local proof on this session, including existing sessions without provenance',async t=>{
 const r=await fixture(t);
 assert.equal((await change(r,r.owner.cookie)).status,200);
 r.now+=10*60000+1;
 await refused(r,r.owner.cookie);
 const elsewhere=await emailSession(r,'owner@example.com');
 await refused(r,r.owner.cookie);
 assert.equal((await change(r,elsewhere)).status,403,'email alone has no hardware authority');
 const separate=await authenticate(r,r.owner.key);assert.equal(separate.response.status,200);
 await refused(r,sessionCookie(separate.response));
 await r.db.prepare('UPDATE auth_sessions SET local_email_verified_at=NULL').run();
 assert.equal((await r.call('/api/auth/people',{cookie:r.owner.cookie})).status,200,'older sessions keep ordinary administration');
 await refused(r,r.owner.cookie);
 assert.equal((await r.db.prepare("SELECT provider_id FROM oa_domain_rules WHERE domain='company.example'").first()).provider_id,'company');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_domains').first()).n,0);
});

test('browser email confirmation retains active hardware authority and its deadline without granting it to independent email sign-in',async t=>{
 const r=await fixture(t);r.now+=11*60000;
 const original=await r.db.prepare("SELECT expires_at FROM auth_sessions WHERE person_id='owner' AND amr LIKE '%hwk%'").first();
 const proof=await requestProof(r,'owner@example.com',r.owner.cookie);
 const stranger=await requestProof(r,'owner@example.com');
 assert.equal((await finishProof(r,{...proof,binding:stranger.binding})).status,400);
 const confirmed=await finishProof(r,proof);assert.equal(confirmed.status,200);
 const cookie=sessionCookie(confirmed);
 assert.equal((await r.call('/api/auth/people',{cookie})).status,200);
 assert.equal((await change(r,cookie)).status,200);
 assert.equal((await r.call('/api/auth/people/domain',post({domain:'company.example'},cookie))).status,201);
 assert.equal((await r.call('/api/auth/domains/add',post({domain:'alias.example'},cookie))).status,201);
 assert.equal((await change(r,cookie,'')).status,200);
 assert.equal((await finishProof(r,proof)).status,400,'confirmation remains one use');
 const latest=await r.db.prepare('SELECT expires_at FROM auth_sessions ORDER BY created_at DESC LIMIT 1').first();
 assert.ok(latest.expires_at<=original.expires_at,'email confirmation cannot extend hardware authority');
 const independent=await finishProof(r,stranger);assert.equal(independent.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(independent)})).status,403);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},sessionCookie(independent)))).status,403);
});

test('passkey sign-in carries only the same person’s live browser email proof and never renews its age',async t=>{
 const r=await fixture(t);r.now+=11*60000;
 const local=await emailSession(r,'owner@example.com');
 assert.equal((await change(r,local)).status,403);
 const signedIn=await finishPasskey(r,await beginPasskey(r,r.owner.key,local));assert.equal(signedIn.status,200);
 const cookie=sessionCookie(signedIn);assert.equal((await change(r,cookie)).status,200);
 r.now+=9*60000;
 const renewed=await finishPasskey(r,await beginPasskey(r,r.owner.key,cookie));assert.equal(renewed.status,200);
 assert.equal((await change(r,sessionCookie(renewed),'')).status,200);
 r.now+=60000+1;await refused(r,sessionCookie(renewed));
 await r.person('other','other@example.com','admin');
 const other=await register(r,await emailSession(r,'other@example.com'));
 const freshOwner=await emailSession(r,'owner@example.com');
 const switched=await finishPasskey(r,await beginPasskey(r,other.key,freshOwner));assert.equal(switched.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(switched)})).status,200);
 await refused(r,sessionCookie(switched));
});

test('pending email confirmation cannot restore revoked, expired or changed hardware sessions',async t=>{
 for(const state of ['revoked','expired','changed'])await t.test(state,async t=>{
  const r=await fixture(t);
  if(state==='expired')await r.db.prepare("UPDATE auth_sessions SET expires_at=? WHERE amr LIKE '%hwk%'").bind(r.now+1000).run();
  const proof=await requestProof(r,'owner@example.com',r.owner.cookie);
  if(state==='revoked')assert.equal((await r.call('/api/auth/signout',post({},r.owner.cookie))).status,200);
  if(state==='expired')r.now+=2000;
  if(state==='changed')await r.db.prepare("UPDATE oa_operators SET version=version+1 WHERE id='owner'").run();
  const response=await finishProof(r,proof);assert.ok([400,403].includes(response.status));
  assert.equal(sessionCookie(response),undefined);
  assert.equal((await r.call('/api/auth/people',{cookie:r.owner.cookie})).status,401);
 });
});

test('revocation during a passkey challenge removes inherited local proof and request labels grant no authority',async t=>{
 const r=await fixture(t),local=await emailSession(r,'owner@example.com');
 const attempt=await beginPasskey(r,r.owner.key,local);
 assert.equal((await r.call('/api/auth/signout',post({},local))).status,200);
 const authenticated=await finishPasskey(r,attempt);assert.equal(authenticated.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(authenticated)})).status,200);
 await refused(r,sessionCookie(authenticated));
 const forged=await emailSession(r,'owner@example.com',{amr:['hwk'],localEmailVerifiedAt:r.now,hardwareSessionId:'owner',upstreamProofId:'company'});
 assert.equal((await r.call('/api/auth/people',{cookie:forged})).status,403);
 assert.equal((await change(r,forged)).status,403);
});
