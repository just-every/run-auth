import assert from 'node:assert/strict';
import {openRuntime} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
const DAY=86400000;
export async function retentionSessionProofsFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());
 let owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 const command=async(path,data)=>{
  const response=await r.call('/api/auth/retention/'+path,{method:'POST',cookie:owner.cookie,data});
  assert.equal(response.status,200,path+' '+await response.clone().text());return response.json();
 };
 const read=async()=>{
  const response=await r.call('/api/auth/retention',{cookie:owner.cookie});
  assert.equal(response.status,200,await response.clone().text());return response.json();
 };
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_directory_sources').first()).n,0);
 const classes=(await read()).policy.classes;
 await command('settings',{confirm:true,classes:{...classes,authentication:{unit:'days',value:90}}});
 // Age persisted fixtures only; policy, preview and scheduled cleanup use the
 // public retention routes and the same maintenance door as the Worker cron.
 const aged=r.now-120*DAY,expired=['expired-proof-1','expired-proof-2','expired-proof-3'];
 const kept=['unexpired-proof','recent-expired-proof'];
 for(const id of [...expired,...kept]) {
  const created=id==='recent-expired-proof'?r.now-30*DAY:aged;
  const expires=id==='unexpired-proof'?r.now+30*DAY:created+DAY;
  await r.db.prepare("INSERT INTO auth_sessions(id,token_hash,person_id,person_version,amr,created_at,expires_at) VALUES(?,?,'owner',1,'[\"hwk\"]',?,?)").bind(id,id,created,expires).run();
  await r.db.prepare("INSERT INTO auth_passkey_session_proofs(session_id,person_id,verified_at) VALUES(?,'owner',?)").bind(id,id==='unexpired-proof'?r.now:created).run();
 }
 for(const id of ['expired-proof-1','unexpired-proof'])await r.db.prepare("INSERT INTO auth_factor_proofs(session_id,person_id,factor_id,verified_at) VALUES(?,'owner','synthetic-factor',?)").bind(id,id==='unexpired-proof'?r.now:aged).run();
 const liveFactor=await r.db.prepare("SELECT * FROM auth_factor_proofs WHERE session_id='unexpired-proof'").first();
 const before=await r.db.prepare("SELECT * FROM auth_passkey_session_proofs WHERE session_id IN ('unexpired-proof','recent-expired-proof') ORDER BY session_id").all();
 const queued=await command('preview',{});
 assert.equal(queued.run.summary.authentication.stores.auth_sessions,3);
 assert.equal(queued.run.summary.authentication.count,3,'only the three old expired sessions enter the plan');
 r.now+=8*DAY;
 await r.restart();
 const cleanup=await r.call('/',{action:'maintain'});
 assert.equal(cleanup.status,200,await cleanup.clone().text());
 for(const id of expired) {
  assert.equal(await r.db.prepare('SELECT id FROM auth_sessions WHERE id=?').bind(id).first(),null,id+' session expired');
  assert.equal(await r.db.prepare('SELECT session_id FROM auth_passkey_session_proofs WHERE session_id=?').bind(id).first(),null,id+' proof removed before its session');
 }
 assert.equal(await r.db.prepare("SELECT session_id FROM auth_factor_proofs WHERE session_id='expired-proof-1'").first(),null,'expired session factor proof removed too');
 assert.deepEqual(await r.db.prepare("SELECT * FROM auth_factor_proofs WHERE session_id='unexpired-proof'").first(),liveFactor,'live factor proof unchanged');
 for(const id of kept)assert.ok(await r.db.prepare('SELECT id FROM auth_sessions WHERE id=?').bind(id).first(),id+' session retained');
 assert.deepEqual((await r.db.prepare("SELECT * FROM auth_passkey_session_proofs WHERE session_id IN ('unexpired-proof','recent-expired-proof') ORDER BY session_id").all()).results,before.results,'unexpired and younger proofs remain unchanged');
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_directory_sources').first()).n,0);
 owner=await signInAgain(r,owner,'owner@example.com');
 const completed=(await read()).runs.find(run=>run.id===queued.run.id);
 assert.equal(completed.status,'completed');
 assert.equal(completed.result['auth_sessions:authentication'],3);
}
