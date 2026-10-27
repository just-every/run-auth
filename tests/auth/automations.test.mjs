import {test} from 'node:test';
import assert from 'node:assert/strict';
import {samlInstall} from './saml-helpers.mjs';
import {passkeyPerson} from './agents-helpers.mjs';
import {portableTables} from '../../src/auth/stores.mjs';

import {host,credentials,service} from './automations-service.mjs';
async function ok(response,status=200){assert.equal(response.status,status,await response.clone().text());return response.json();}
async function setup(t) {
 const r=await samlInstall(t),remote=await service(t,r);
 const group=await ok(await r.admin('groups/create',{name:'Automation group'}),201);
 await ok(await r.admin('groups/add',{groupId:group.id,personId:'ada'}));
 const connection=await ok(await r.admin('automations/connect',{name:'REST connection',origin:host,tokenUrl:host+'/token',groupId:group.id,paths:['/first','/second'],...credentials,grant:true}),201);
 const config={id:connection.id,name:'Group workflow',paths:['/first','/second'],responseField:'id',version:0};
 await ok(await r.admin('automations/save',config),201);
 const prepare=async()=>ok(await r.admin('automations/prepare',{id:connection.id,personId:'ada'}),201);
 const approve=async id=>ok(await r.admin('automations/approve',{id:connection.id,runId:id,confirm:id}));
 const execute=id=>r.admin('automations/execute',{id:connection.id,runId:id});
 return {r,remote,group,connection,config,prepare,approve,execute};
}

test('automation public doors dry run without calls, acquire OAuth and chain two signed steps, retain history and exclude credentials from projections and archives',async t=>{
 const {r,remote,connection,prepare,approve,execute}=await setup(t);
 const dry=await ok(await r.admin('automations/dry-run',{id:connection.id,personId:'ada'}),201);
 assert.equal(dry.outboundCalls,0);assert.equal(dry.intended.length,2);assert.deepEqual(remote.calls,[]);assert.deepEqual(remote.state,[]);
 const pending=await prepare();assert.equal((await execute(pending.id)).status,409);
 assert.equal((await r.admin('automations/approve',{id:connection.id,runId:pending.id,confirm:'someone-else'})).status,403);
 await approve(pending.id);assert.deepEqual(remote.calls,[]);
 // An approved queue survives a Worker restart and is claimed exactly once.
 await r.restart();await ok(await r.call('/',{action:'maintain'}));
 assert.deepEqual(remote.state,[{path:'/first',personId:'ada'},{path:'/second',personId:'ada',responseId:'remote-record-1'}]);
 assert.deepEqual(remote.calls.map(c=>c.path),['/token','/first','/second']);
 assert.equal((await execute(pending.id)).status,409);
 await r.call('/',{action:'maintain'});assert.equal(remote.calls.length,3);
 const model=await ok(await r.call('/api/auth/automations',{cookie:r.owner.cookie}));
 const run=model.runs.find(x=>x.id===pending.id);assert.equal(run.state,'completed');assert.deepEqual(run.steps.map(s=>[s.ordinal,s.state,s.status]),[[1,'completed',200],[2,'completed',200]]);
 const diagnostic=JSON.stringify(model)+JSON.stringify((await r.db.prepare('SELECT detail FROM auth_activity_details').all()).results);
 for(const secret of [...Object.values(credentials),'synthetic-auth-5'])assert.ok(!diagnostic.includes(secret));
 const stored=await r.db.prepare('SELECT sealed_credentials FROM auth_automation_connections').first();assert.ok(!stored.sealed_credentials.includes(credentials.clientSecret));
 const existing=new Set((await r.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all()).results.map(r=>r.name));
 const archive=[];for(const table of portableTables().filter(table=>existing.has(table)))archive.push(...(await r.db.prepare('SELECT * FROM '+table).all()).results);
 for(const secret of Object.values(credentials))assert.ok(!JSON.stringify(archive).includes(secret));
});

test('automation refuses lost permission, foreign scope and stale configuration, and holds failed or interrupted effects as person obligations without replay',async t=>{
 const {r,remote,connection,config,group,prepare,approve,execute}=await setup(t);
 assert.equal((await r.call('/api/auth/automations')).status,401);
 assert.equal((await r.call('/api/auth/automations',{cookie:r.ada})).status,403);
 assert.equal((await r.admin('automations/prepare',{id:connection.id,personId:'bob'})).status,403);
 assert.equal((await r.admin('automations/save',{...config,paths:['/outside','/second'],version:1})).status,403);
 const changed=await prepare();await approve(changed.id);
 await ok(await r.admin('automations/save',{...config,version:1}),201);
 assert.equal((await execute(changed.id)).status,409);assert.equal(remote.calls.length,0);
 const membership=await prepare();await approve(membership.id);
 await ok(await r.admin('groups/remove',{groupId:group.id,personId:'ada'}));
 assert.equal((await execute(membership.id)).status,403);assert.equal(remote.calls.length,0);
 await ok(await r.admin('groups/add',{groupId:group.id,personId:'ada'}));
 const triggers=await ok(await r.call('/api/auth/automations',{cookie:r.owner.cookie}));assert.ok(triggers.runs.some(run=>run.state==='awaiting_approval'),'native membership prepares a run without executing');
 // Recover a crash between durable event recording and queue creation.
 const eventRun=await r.db.prepare('SELECT * FROM auth_automation_runs WHERE event_id IS NOT NULL').first();assert.ok(eventRun);
 await r.db.prepare('DELETE FROM auth_automation_steps WHERE run_id=?').bind(eventRun.id).run();
 await r.db.prepare('DELETE FROM auth_automation_runs WHERE id=?').bind(eventRun.id).run();
 await r.restart();await r.call('/',{action:'maintain'});await r.call('/',{action:'maintain'});
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_automation_runs WHERE event_id=?').bind(eventRun.event_id).first()).n,1);assert.equal(remote.calls.length,0);
 const failed=await prepare();await approve(failed.id);remote.script.push({}, {},{status:503,body:credentials.clientSecret});
 assert.equal((await ok(await execute(failed.id))).state,'uncertain');
 await r.call('/',{action:'maintain'});
 const ob=await r.db.prepare("SELECT person_id,state,next_action FROM auth_obligations WHERE source_id=?").bind('automation:'+failed.id).first();
 assert.deepEqual(ob,{person_id:'ada',state:'open',next_action:'review_automation_remote_effect_before_new_approval'});
 const count=remote.calls.length;await r.restart();await r.call('/',{action:'maintain'});assert.equal(remote.calls.length,count);
 // Crash after a durable intent: recovery preserves uncertainty and does not send.
 const interrupted=await prepare();await approve(interrupted.id);
 await r.db.prepare("UPDATE auth_automation_runs SET state='running',lease_until=0 WHERE id=?").bind(interrupted.id).run();
 await r.db.prepare("UPDATE auth_automation_steps SET state='running' WHERE run_id=? AND ordinal=1").bind(interrupted.id).run();
 await r.restart();await r.call('/',{action:'maintain'});assert.equal(remote.calls.length,count);
 assert.equal((await r.db.prepare('SELECT state FROM auth_automation_runs WHERE id=?').bind(interrupted.id).first()).state,'uncertain');
 // A delegated holder needs the named permission plus its person and group scope.
 const delegate=await passkeyPerson(r,'delegate','delegate@example.com');
 const roleChange=async data=>{const preview=await ok(await r.admin('roles/preview',data));return ok(await r.admin('roles/apply',{previewId:preview.previewId}));};
 const role=await roleChange({kind:'role',role:{name:'Automation operator',rank:10,permissions:['automations.manage']}});
 const resources={view:{people:['ada'],groups:[group.id]},edit:{people:['ada'],groups:[group.id]}};
 const grant=await roleChange({kind:'grant',personId:'delegate',roleId:role.plan.role.id,resources});
 const asDelegate=(action,data)=>r.call('/api/auth/automations/'+action,{method:'POST',cookie:delegate.cookie,data});
 const own=await ok(await asDelegate('connect',{name:'Scoped REST',origin:host,tokenUrl:host+'/token',groupId:group.id,paths:['/first','/second'],...credentials,grant:true}),201);
 await ok(await asDelegate('save',{...config,id:own.id,version:0}),201);
 assert.equal((await asDelegate('prepare',{id:own.id,personId:'bob'})).status,403);
 assert.equal((await asDelegate('prepare',{id:connection.id,personId:'ada'})).status,403,'permission alone cannot borrow another connection');
 const delegatedRun=await ok(await asDelegate('prepare',{id:own.id,personId:'ada'}),201);
 await ok(await asDelegate('approve',{id:own.id,runId:delegatedRun.id,confirm:delegatedRun.id}));
 await roleChange({kind:'revoke',grantId:grant.plan.id});
 assert.equal((await asDelegate('execute',{id:own.id,runId:delegatedRun.id})).status,403);assert.equal(remote.calls.length,count);
 // Connection authority changed while the token service was answering: no effect starts.
 const tokenRace=await prepare();await approve(tokenRace.id);
 remote.script.push({beforeReply:async()=>r.db.prepare('UPDATE auth_automation_connections SET version=version+1 WHERE id=?').bind(connection.id).run()});
 assert.equal((await ok(await execute(tokenRace.id))).state,'failed');assert.equal(remote.calls.length,count+1);assert.equal(remote.state.length,2);
 const afterRace=remote.calls.length;
 const staleEmail=await prepare();await approve(staleEmail.id);
 await r.db.prepare("UPDATE auth_sessions SET local_email_verified_at=0 WHERE person_id='owner'").run();
 assert.equal((await execute(staleEmail.id)).status,403);assert.equal(remote.calls.length,afterRace);
 await r.db.prepare("UPDATE auth_sessions SET local_email_verified_at=? WHERE person_id='owner'").bind(r.now).run();
 const lost=await prepare();await approve(lost.id);
 await r.db.prepare("UPDATE auth_sessions SET amr='[\"email\"]' WHERE person_id='owner'").run();
 assert.equal((await execute(lost.id)).status,403);assert.equal(remote.calls.length,afterRace);
});

test('automation hosted destinations refuse private addresses and DNS, redirects and unbounded response mapping without credential diagnostics',async t=>{
 const {r,remote,connection,group,prepare,approve,execute}=await setup(t);
 for(const origin of ['https://127.0.0.1','https://intranet.internal','http://10.0.0.1'])assert.equal((await r.admin('automations/connect',{name:'Bad',origin,tokenUrl:origin+'/token',groupId:group.id,paths:['/first','/second'],...credentials,grant:true})).status,400);
 let pending=await prepare();await approve(pending.id);
 const result=await r.call('/api/auth/automations/execute',{method:'POST',cookie:r.owner.cookie,data:{id:connection.id,runId:pending.id},privateAutomationDns:true});
 assert.equal((await ok(result)).state,'failed');assert.equal(remote.calls.length,0);
 pending=await prepare();await approve(pending.id);remote.script.push({redirect:true});
 assert.equal((await ok(await execute(pending.id))).state,'failed');assert.equal(remote.calls.length,1);assert.equal(remote.state.length,0);
 pending=await prepare();await approve(pending.id);remote.script.push({}, {body:JSON.stringify({id:'x'.repeat(257)})});
 assert.equal((await ok(await execute(pending.id))).state,'uncertain');assert.equal(remote.state.length,1,'step two never receives the unbounded value');
 const diagnostics=JSON.stringify(await ok(await r.call('/api/auth/automations',{cookie:r.owner.cookie})));
 assert.ok(!diagnostics.includes('x'.repeat(257)));assert.ok(!diagnostics.includes(credentials.clientSecret));
 const revoked=await prepare();await approve(revoked.id);const count=remote.calls.length;
 await ok(await r.admin('automations/revoke',{id:connection.id}));
 assert.equal((await execute(revoked.id)).status,403);assert.equal(remote.calls.length,count);
});
