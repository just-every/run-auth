import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {ownerInstall,post} from './agents-helpers.mjs';
import {cookieOf,emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';
import {hookServer,verifiedHook} from './hooks-server.mjs';
import {issueClient} from './policy-helpers.mjs';

export async function legacyBridgeFlow(t) {
 const {r,owner}=await ownerInstall(t),edge=await hookServer(t);r.edges=edge.edges;
 const json=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
 const command=(path,data,cookie=owner.cookie)=>r.call('/api/auth/'+path,post(data,cookie));
 const custom={format:'auth-custom-directory',version:1,people:[
  {directory_id:'synthetic-auth-81',email:'legacy@example.com',name:'Legacy Worker',disabled:false,history:[{at:'2025-01-01T00:00:00Z',values:{department:'Support',title:'Analyst'}}],password_hash:'synthetic-auth-unsupported',factors:['synthetic-auth-factor']},
  {directory_id:'synthetic-auth-82',email:'disabled@example.com',name:'Disabled Worker',disabled:true,history:[]},
  {directory_id:'synthetic-auth-83',email:'interrupted@example.com',name:'Interrupted Worker',disabled:false,history:[]},
  {directory_id:'synthetic-auth-86',email:'cutover@example.com',name:'Cutover Worker',disabled:false,history:[]},
 ]};
 const staged=await json(await command('move-in/stage',{fileName:'custom-directory.json',exportDate:'2026-10-23',text:JSON.stringify(custom)}),201);
 const review=await json(await r.call('/api/auth/move-in?batch='+staged.batchId,{cookie:owner.cookie}));assert.deepEqual(review.rows[0].profileHistory,custom.people[0].history);assert.ok(!JSON.stringify(review).includes('synthetic-auth-unsupported'));
 await json(await command('move-in/admit',{batchId:staged.batchId,rows:[0,1,2,3]}));
 const mapping=(await (await r.call('/api/auth/move-in/subjects.csv?batch='+staged.batchId,{cookie:owner.cookie})).text());assert.ok(mapping.includes('synthetic-auth-81'));
 const people=await json(await r.call('/api/auth/people',{cookie:owner.cookie})),legacy=people.find(person=>person.email==='legacy@example.com'),disabled=people.find(person=>person.email==='disabled@example.com'),interrupted=people.find(person=>person.email==='interrupted@example.com'),cutover=people.find(person=>person.email==='cutover@example.com');
 assert.ok(legacy&&disabled&&interrupted);
 const credential='synthetic-auth-84',password='synthetic-auth-85';
 edge.responses.set('/legacy',(body,record)=>{
  const expected='v1,'+createHmac('sha256',credential).update(record.headers['bridge-call-id']+'.'+record.headers['bridge-timestamp']+'.'+record.body).digest('base64url');assert.equal(record.headers['bridge-signature'],expected);
  assert.deepEqual(Object.keys(body).sort(),['id','password','subject','version']);
  return {body:{authenticated:body.password===password,subject:body.subject}};
 });
 const registration=(subjects,url='https://hooks.example.com/legacy')=>command('migration/bridge/register',{url,credential,expiresAt:r.now+3600000,subjects,confirm:true});
 const source=person=>({sourceSystem:'custom',sourceSubject:custom.people.find(row=>row.email===person.email).directory_id,personId:person.id,batchId:staged.batchId});
 assert.equal((await registration([source(disabled)])).status,409,'disabled source is ineligible even after a deliberate import');
 assert.equal((await registration([{...source(legacy),personId:interrupted.id}])).status,409,'email/source collision cannot rebind a person');
 assert.equal((await registration([source(legacy)],'https://private.example.com/legacy')).status,400,'bridge registration refuses a private DNS destination');
 const bridge=await json(await registration([source(legacy),source(interrupted),source(cutover)]),201);assert.equal(bridge.passwordHashes,'reset-required');assert.equal(bridge.factors,'reenrollment-required');assert.ok(!JSON.stringify(bridge).includes(credential));
 const hook=await json(await command('hooks/register',{point:'password_import',url:'https://hooks.example.com/password-gate',allowedFields:[]}),201);edge.responses.set('/password-gate',{body:{allow:true}});
 const login=(subject,attempt=password)=>command('migration/bridge/login',{bridgeId:bridge.id,sourceSubject:subject,password:attempt},undefined);
 const denied=await login('synthetic-auth-81','synthetic-auth-wrong');assert.equal(denied.status,403);assert.equal((await r.db.prepare('SELECT completed_at FROM auth_migration_subjects WHERE person_id=?').bind(legacy.id).first()).completed_at,null);
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE person_id=?').bind(legacy.id).first()).n,0,'wrong password creates no authority');
 edge.responses.set('/password-gate',{body:{allow:false}});assert.equal((await login('synthetic-auth-81')).status,403,'inherited password hook can refuse before verification');edge.responses.set('/password-gate',{body:{allow:true}});
 const first=await login('synthetic-auth-81');assert.equal(first.status,202,await first.clone().text());assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE person_id=?').bind(legacy.id).first()).n,0,'old password alone creates no Auth session');
 const link=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]);
 assert.equal((await r.call('/auth/identity/email/confirm',post({token:link.searchParams.get('token')},undefined))).status,400,'Auth email proof is still browser-bound');
 const confirmed=await r.call('/auth/identity/email/confirm',post({token:link.searchParams.get('token')},cookieOf(first)));assert.equal(confirmed.status,200);const employee=await register(r,cookieOf(confirmed));
 const app=await issueClient(r),token=await app.redeem(await app.authorize(employee.cookie));assert.equal(token.status,200,'migrated worker signs into a real linked app');
 assert.equal(await (await r.call('/api/auth/move-in/subjects.csv?batch='+staged.batchId,{cookie:owner.cookie})).text(),mapping.replace('synthetic-auth-81,legacy@example.com,invited,','synthetic-auth-81,legacy@example.com,active,'),'reviewed downstream old-subject mapping survives first login and enrollment');
 const verifiedCalls=edge.received.filter(row=>row.path==='/legacy').length;
 assert.equal((await json(await login('synthetic-auth-81'),202)).state,'already-migrated');assert.equal(edge.received.filter(row=>row.path==='/legacy').length,verifiedCalls,'completed migration never rechecks or trusts the old password');
 const verifier=edge.responses.get('/legacy');edge.responses.set('/legacy','hang');
 const timeoutStarted=performance.now();assert.equal((await login('synthetic-auth-83')).status,503,'a hanging verifier fails closed');
 const elapsed=performance.now()-timeoutStarted;assert.ok(elapsed>=4500&&elapsed<15000,'the actual verifier call is bounded');console.log('MEASURED legacy verifier timeout '+Math.round(elapsed)+' ms');
 edge.responses.set('/legacy',{body:{authenticated:true,subject:'synthetic-auth-foreign'}});assert.equal((await login('synthetic-auth-83')).status,403,'a verifier cannot substitute a reviewed identity');
 edge.responses.set('/legacy',{status:503,body:{}});
 assert.equal((await login('synthetic-auth-83')).status,503,'verifier outage is unavailable and creates no migration completion');
 assert.equal((await r.db.prepare('SELECT completed_at FROM auth_migration_subjects WHERE person_id=?').bind(interrupted.id).first()).completed_at,null);
 edge.responses.set('/legacy',verifier);
 // A mail transport interruption occurs after the durable one-time completion.
 const deliveredBefore=(await r.mails()).length;r.mailEdge='http://127.0.0.1:1';const interruptedReply=await login('synthetic-auth-83');assert.equal(interruptedReply.status,202,'email requests preserve their anti-enumeration response during outage');assert.equal((await r.mails()).length,deliveredBefore,'the transport outage delivers no proof');assert.ok(await r.db.prepare("SELECT id FROM auth_activity WHERE event='email_delivery_failed' AND subject_id=?").bind(interrupted.id).first(),'actual delivery failure is retained');assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE person_id=?').bind(interrupted.id).first()).n,0);delete r.mailEdge;
 await r.restart();assert.equal((await json(await login('synthetic-auth-83'),202)).state,'already-migrated');assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_migration_subjects WHERE person_id=? AND completed_at IS NOT NULL').bind(interrupted.id).first()).n,1);
 assert.ok(await emailSession(r,'interrupted@example.com'),'normal email recovery resumes the interrupted completion without a second imported person');
 for(const call of edge.received.filter(row=>row.path==='/password-gate')){assert.ok(verifiedHook(hook.secret,call));assert.deepEqual(Object.keys(JSON.parse(call.body).data).sort(),['personId','sourceId']);assert.ok(!call.body.includes(password));assert.ok(!call.body.includes(credential));}
 // Cutover while a verifier response is in flight must fence the result,
 // including after a restart; the old credential cannot complete this worker.
 let received,release;
 const arrived=new Promise(resolve=>{received=resolve;}),resume=new Promise(resolve=>{release=resolve;});
 edge.responses.set('/legacy',async body=>{received();await resume;return {body:{authenticated:true,subject:body.subject}};});
 const pending=login('synthetic-auth-86');await arrived;
 await json(await command('migration/bridge/disable',{bridgeId:bridge.id}));release();
 assert.equal((await pending).status,409,'cutover refuses an already verified in-flight result');
 assert.equal((await r.db.prepare('SELECT completed_at FROM auth_migration_subjects WHERE person_id=?').bind(cutover.id).first()).completed_at,null);
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE person_id=?').bind(cutover.id).first()).n,0);
 await r.restart();assert.equal((await login('synthetic-auth-86')).status,403);
assert.equal((await login('synthetic-auth-81')).status,403,'disabled bridge permanently refuses old authentication');assert.equal((await r.db.prepare('SELECT sealed_credential FROM auth_migration_bridges WHERE id=?').bind(bridge.id).first()).sealed_credential,null);
 const audit=await json(await r.call('/api/auth/activity',{cookie:owner.cookie}));for(const secret of [credential,password,'synthetic-auth-wrong','synthetic-auth-unsupported'])assert.ok(!JSON.stringify(audit).includes(secret));
 assert.deepEqual((await r.db.prepare('SELECT history FROM auth_import_history WHERE person_id=?').bind(legacy.id).all()).results.map(row=>JSON.parse(row.history)),[custom.people[0].history]);
}
