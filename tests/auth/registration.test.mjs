import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openRuntime,cookieOf,emailSession} from './runtime.mjs';
import {authenticator,register,authenticate} from './webauthn.mjs';

const post=(data,cookie)=>({method:'POST',data,cookie});
async function fixture(t,additional=false) {
 const r=await openRuntime();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');
 const email=await emailSession(r,'owner@example.com');
 const existing=additional?await register(r,email):null;
 return {r,cookie:existing?.cookie||email,existing};
}
async function begin(r,cookie,key=authenticator(r.origin)) {
 const offered=await r.call('/auth/passkeys/register/options',post({},cookie));assert.equal(offered.status,200);
 const tx=await offered.json();
 return {key,cookie:`${cookie}; ${cookieOf(offered)}`,data:{transaction:tx.transaction,response:key.register(tx.options)}};
}
const finish=(r,attempt)=>r.call('/auth/passkeys/register/verify',post(attempt.data,attempt.cookie));
async function stored(r) {
 return {
  keys:(await r.db.prepare('SELECT * FROM auth_passkeys ORDER BY id').all()).results,
  sessions:(await r.db.prepare('SELECT count(*) AS n FROM auth_sessions').first()).n,
  audits:(await r.db.prepare("SELECT count(*) AS n FROM auth_activity WHERE event='passkey_registered'").first()).n,
 };
}
async function noCandidate(r,attempt,response,before,status) {
 assert.equal(response.status,status);assert.equal(cookieOf(response),undefined);
 assert.deepEqual(await stored(r),before);
 assert.equal((await authenticate(r,attempt.key)).response.status,400);
}

test('registration rechecks source authority in the credential transaction',async t=>{
 const changes={
  revoked:'UPDATE auth_sessions SET revoked_at=1',
  person_version:'UPDATE oa_operators SET version=version+1',
  source_version:'UPDATE auth_sessions SET person_version=person_version+1',
  expired:'UPDATE auth_sessions SET expires_at=1',
  changed_deadline:'UPDATE auth_sessions SET expires_at=expires_at-1',
  changed_methods:`UPDATE auth_sessions SET amr='["email"]'`,
  stale_proof:'UPDATE auth_sessions SET local_email_verified_at=local_email_verified_at-600000',
  inactive:"UPDATE oa_operators SET status='inactive' WHERE id='owner'",
 };
 for(const [state,sql] of Object.entries(changes))await t.test(state,async t=>{
  const {r,cookie}=await fixture(t,true),attempt=await begin(r,cookie),before=await stored(r);
  if(state==='inactive')await r.person('continuing-owner','continuing@example.com','owner');
  await r.db.prepare(`CREATE TRIGGER test_source_change AFTER DELETE ON auth_challenges WHEN OLD.purpose='register' BEGIN ${sql}; END`).run();
  try {await noCandidate(r,attempt,await finish(r,attempt),before,403);}
  finally {await r.db.prepare('DROP TRIGGER test_source_change').run();}
 });
 await t.test('revoked email source cannot create a first credential',async t=>{
  const {r,cookie}=await fixture(t),attempt=await begin(r,cookie),before=await stored(r);
  await r.db.prepare("CREATE TRIGGER test_source_change AFTER DELETE ON auth_challenges WHEN OLD.purpose='register' BEGIN UPDATE auth_sessions SET revoked_at=1; END").run();
  try {await noCandidate(r,attempt,await finish(r,attempt),before,403);}
  finally {await r.db.prepare('DROP TRIGGER test_source_change').run();}
 });
});

test('session and registration audit storage failures roll back the complete enrollment',async t=>{
 for(const additional of [false,true])for(const stage of ['session','audit'])await t.test(`${additional?'additional':'first'} ${stage}`,async t=>{
  const {r,cookie,existing}=await fixture(t,additional),attempt=await begin(r,cookie),before=await stored(r);
  const table=stage==='session'?'auth_sessions':'auth_activity';
  const condition=stage==='session'?"NEW.amr LIKE '%hwk%'":"NEW.event='passkey_registered'";
  await r.db.prepare(`CREATE TRIGGER test_storage_failure BEFORE INSERT ON ${table} WHEN ${condition} BEGIN SELECT RAISE(ABORT,'test enrollment storage failure'); END`).run();
  try {await noCandidate(r,attempt,await finish(r,attempt),before,500);}
  finally {await r.db.prepare('DROP TRIGGER test_storage_failure').run();}
  if(existing)assert.equal((await authenticate(r,existing.key)).response.status,200);
 });
});

test('malformed and duplicate enrollment preserve existing keys and sessions',async t=>{
 const {r,cookie,existing}=await fixture(t,true),before=await stored(r);
 const malformed=await begin(r,cookie);malformed.data.response.response.attestationObject='invalid';
 await noCandidate(r,malformed,await finish(r,malformed),before,400);
 const duplicate=await begin(r,cookie,existing.key),response=await finish(r,duplicate);
 assert.equal(response.status,500);assert.equal(cookieOf(response),undefined);assert.deepEqual(await stored(r),before);
 assert.equal((await authenticate(r,existing.key)).response.status,200);
});

test('concurrent first enrollment commits one credential and refused credentials cannot sign in',async t=>{
 const {r,cookie}=await fixture(t),a=await begin(r,cookie),b=await begin(r,cookie),before=await stored(r);
 const attempts=[a,b],responses=await Promise.all(attempts.map(attempt=>finish(r,attempt)));
 assert.deepEqual(responses.map(response=>response.status).sort(),[200,403]);
 const accepted=responses.findIndex(response=>response.status===200),refused=1-accepted;
 assert.equal(cookieOf(responses[refused]),undefined);
 const after=await stored(r);assert.equal(after.keys.length,1);assert.equal(after.keys[0].id,attempts[accepted].key.id);
 assert.equal(after.sessions,before.sessions+1);assert.equal(after.audits,before.audits+1);
 assert.equal((await authenticate(r,attempts[refused].key)).response.status,400);
 const signed=await authenticate(r,attempts[accepted].key);assert.equal(signed.response.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:cookieOf(signed.response)})).status,200);
 const additional=await register(r,cookieOf(responses[accepted]));assert.equal((await authenticate(r,additional.key)).response.status,200);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},cookie))).status,403);
 await r.person('member','member@example.com');
 const member=await register(r,await emailSession(r,'member@example.com'));
 assert.equal((await r.call('/api/auth/people',{cookie:member.cookie})).status,403);
});
