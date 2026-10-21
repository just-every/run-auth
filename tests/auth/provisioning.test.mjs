import {test} from 'node:test';
import assert from 'node:assert/strict';
import {samlInstall,addApp} from './saml-helpers.mjs';
import {scimServer} from './scim-server.mjs';

const BASE='https://scim.example.com/scim/v2';
const remote=(scim,externalId)=>[...scim.users.values()].find(u=>u.externalId===externalId);
const appModel=async(r,id)=>(await (await r.call('/api/auth/company-apps',{cookie:r.owner.cookie})).json()).companyApps.find(a=>a.id===id);
const obligation=(r,appId,subject)=>r.db.prepare("SELECT * FROM auth_provisioning WHERE app_id=? AND subject_id=? AND state!='superseded' ORDER BY event_at DESC LIMIT 1").bind(appId,subject).first();
async function provisioned(t,{pushGroups=true}={}) {
 const r=await samlInstall(t),scim=await scimServer(t);r.scimServer=scim.url;
 await r.person('carol','carol@example.com');
 const app=await addApp(r,{entityId:'https://crm.example.com',acsUrl:'https://crm.example.com/acs',assign:[]});
 return {r,scim,app,connect:async(token=scim.token)=>{const res=await r.admin('provisioning/connect',{appId:app.id,baseUrl:BASE,token,pushGroups});assert.equal(res.status,201,await res.clone().text());}};
}

test('a group assignment provisions its members and the group over SCIM; role changes update the one account; unassignment and suspension deactivate, verified by read-back',async t=>{
 const {r,scim,app,connect}=await provisioned(t);
 // A wrong credential fails the connection test; rotating it fixes it. The credential never comes back out.
 await connect('wrong-token-123');
 const failing=await (await r.admin('provisioning/test',{appId:app.id})).json();assert.equal(failing.ok,false);assert.equal(failing.usersStatus,401);
 assert.equal((await r.admin('provisioning/rotate',{appId:app.id,token:scim.token})).status,200);
 const passing=await (await r.admin('provisioning/test',{appId:app.id})).json();assert.equal(passing.ok,true);assert.equal(passing.patch,true);
 const stored=await r.db.prepare('SELECT sealed_token FROM auth_scim_connectors').first();assert.doesNotMatch(stored.sealed_token,new RegExp(scim.token));
 assert.doesNotMatch(JSON.stringify(await appModel(r,app.id)),new RegExp(scim.token));
 assert.equal((await r.call('/api/auth/company-apps',{cookie:r.ada})).status,403);
 // Group Sales (ada, carol) assigned with role sales: two users and one group, linked by stable external IDs.
 const group=await (await r.admin('groups/create',{name:'Sales'})).json();
 for(const email of ['ada@example.com','carol@example.com'])assert.equal((await r.admin('groups/add',{groupId:group.id,email})).status,200);
 const plan=await (await r.admin('provisioning/preview',{appId:app.id})).json();assert.deepEqual(plan.changes,[]);
 assert.equal((await r.admin('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id,role:'sales'})).status,200);
 const ada=remote(scim,'ada'),carol=remote(scim,'carol');
 assert.equal(ada.userName,'ada@example.com');assert.equal(ada.active,true);assert.deepEqual(ada.roles.map(x=>x.value),['sales']);assert.ok(carol);
 const pushed=[...scim.groups.values()];assert.equal(pushed.length,1);assert.equal(pushed[0].displayName,'Sales');assert.deepEqual(pushed[0].members.map(m=>m.value).sort(),[ada.id,carol.id].sort());
 const done=await obligation(r,app.id,'ada');assert.equal(done.state,'verified');assert.equal(done.operation,'create');assert.ok(done.dispatched_at>=done.event_at&&done.verified_at>=done.dispatched_at);
 assert.ok(done.verified_at-done.event_at<60000);
 const preview=(await (await r.admin('provisioning/preview',{appId:app.id})).json()).changes;
 assert.deepEqual(preview.filter(c=>c.type==='person').map(c=>[c.email,c.operation,c.attributes.role]).sort(),[['ada@example.com','update','sales'],['carol@example.com','update','sales']]);
 // Role change: the same accounts are updated, never recreated.
 assert.equal((await r.admin('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id,role:'manager'})).status,200);
 assert.deepEqual(remote(scim,'ada').roles.map(x=>x.value),['manager']);
 assert.equal(scim.writes().filter(w=>w.method==='POST'&&w.path.endsWith('/Users')).length,2);
 // Bob directly, then unassigned: created, then deactivated and read back inactive.
 await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'bob',role:'viewer'});assert.equal(remote(scim,'bob').active,true);
 const destructive=(await (await r.admin('provisioning/preview',{appId:app.id})).json()).changes.find(c=>c.id==='bob');assert.equal(destructive.destructive,false);
 await r.admin('company-apps/unassign',{appId:app.id,principalType:'person',principalId:'bob'});
 assert.equal(remote(scim,'bob').active,false);assert.equal((await obligation(r,app.id,'bob')).operation,'deactivate');
 // Reassigned: the same account is reactivated, not recreated.
 const bobId=remote(scim,'bob').id;await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'bob'});
 assert.equal(remote(scim,'bob').active,true);assert.equal(remote(scim,'bob').id,bobId);assert.equal(remote(scim,'bob').roles,undefined);
 await r.admin('company-apps/unassign',{appId:app.id,principalType:'person',principalId:'bob'});assert.equal(remote(scim,'bob').active,false);
 // Carol leaves the group: deactivated there, and the group's members follow.
 await r.admin('groups/remove',{groupId:group.id,personId:'carol'});
 assert.equal(remote(scim,'carol').active,false);assert.deepEqual([...scim.groups.values()][0].members.map(m=>m.value),[ada.id]);
 // Suspension: Auth refuses ada at once, then the app account is deactivated and verified.
 assert.equal((await r.call('/api/auth/launcher',{cookie:r.ada})).status,200);
 assert.equal((await r.admin('people/suspend',{personId:'ada'})).status,200);
 assert.equal((await r.call('/api/auth/launcher',{cookie:r.ada})).status,401);
 assert.equal(remote(scim,'ada').active,false);
 const leaver=await obligation(r,app.id,'ada');assert.equal(leaver.state,'verified');assert.equal(leaver.reason,'person_suspended');assert.equal(leaver.operation,'deactivate');
 assert.equal([...scim.groups.values()][0].members.length,0);
 assert.equal(scim.users.size,3);
});

test('a provider answering 429 and 503, or losing a response, is retried until it recovers with no duplicate account; a name collision waits for an administrator; drift is found across pages',async t=>{
 const {r,scim,app,connect}=await provisioned(t,{pushGroups:false});
 for(let i=0;i<150;i++)scim.users.set('other-'+i,{id:'other-'+i,userName:`u${i}@other.example`,active:true});
 await connect();
 // 429 with Retry-After, then 503: the obligation stays open with its status; nothing is written yet.
 scim.fail(1,429,30);
 await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'ada'});
 let ob=await obligation(r,app.id,'ada');assert.equal(ob.state,'pending');assert.equal(ob.last_status,429);assert.equal(ob.dispatched_at,null);assert.equal(ob.next_attempt_at,ob.event_at+30000);
 const maintain=async()=>r.call('/',{action:'maintain'});
 await maintain();assert.equal((await obligation(r,app.id,'ada')).attempts,1);
 r.now+=30001;scim.fail(1,503);await maintain();
 ob=await obligation(r,app.id,'ada');assert.equal(ob.state,'pending');assert.equal(ob.last_status,503);assert.equal(ob.attempts,2);
 // The create is applied but its answer is lost: the retry finds the account by external ID instead of making another.
 r.now+=60001;scim.fail(0);scim.lose(503);
 const before=scim.users.size;await maintain();
 assert.equal(scim.users.size,before+1);ob=await obligation(r,app.id,'ada');assert.equal(ob.state,'pending');assert.ok(ob.dispatched_at);
 r.now+=300001;await maintain();
 ob=await obligation(r,app.id,'ada');assert.equal(ob.state,'verified');assert.equal(scim.users.size,before+1);assert.equal(remote(scim,'ada').active,true);
 assert.equal(scim.writes().filter(w=>w.method==='POST').length,1);
 // A remote account with Bob's address that Auth did not make: held, not taken over, until an administrator binds it.
 const theirs={id:'pre-existing-bob',userName:'bob@example.com',active:true};scim.users.set(theirs.id,theirs);
 await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'bob'});
 ob=await obligation(r,app.id,'bob');assert.equal(ob.state,'blocked');assert.equal(ob.last_error,'remote_account_exists');assert.equal(theirs.externalId,undefined);
 assert.equal((await appModel(r,app.id)).obligations.find(o=>o.subject_id==='bob').state,'blocked');
 assert.equal((await r.admin('provisioning/adopt',{appId:app.id,personId:'bob',remoteId:theirs.id})).status,200);
 assert.equal((await obligation(r,app.id,'bob')).state,'verified');assert.equal(theirs.externalId,'bob');
 // Drift: someone re-enables a deactivated account in the app. Reconciliation reads every page and repairs it.
 await r.admin('company-apps/unassign',{appId:app.id,principalType:'person',principalId:'bob'});assert.equal(theirs.active,false);
 theirs.active=true;remote(scim,'ada').roles=[{value:'admin'}];
 const result=await (await r.admin('provisioning/sync',{appId:app.id})).json();
 assert.equal(result.ok,true);assert.equal(result.remoteUsers,152);assert.equal(result.pages,2);assert.equal(result.drift,2);
 assert.equal(theirs.active,false);assert.equal(remote(scim,'ada').roles,undefined);
 // An unhealthy connector is visible with its error; an overdue obligation is flagged past 15 minutes.
 scim.fail(10,503);await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'carol'});
 r.now+=16*60000;const model=await appModel(r,app.id);
 assert.equal(model.provisioning.lastError,'http_503');assert.equal(model.obligations.find(o=>o.subject_id==='carol').overdue,true);
});

test('owner erasure previews every store, honors legal holds, anonymizes decisions and keeps refused remote deletion visible',async t=>{
 const {r,scim,app,connect}=await provisioned(t,{pushGroups:false});await connect('synthetic-auth-1');scim.token='synthetic-auth-1';
 const {register}=await import('./webauthn.mjs');const first=await register(r,r.ada),second=await register(r,first.cookie);
 const command=async(path,data,status=200)=>{const response=await r.admin(path,data);assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 await command('company-apps/assign',{appId:app.id,principalType:'person',principalId:'ada',role:'reader'});assert.ok(remote(scim,'ada'));
 await command('directory/source',{source:'hr',records:[{sourceId:'synthetic-auth-2',personId:'ada',fields:{department:'Engineering',name:'Ada Employee'}}]});
 const staged=await command('move-in/stage',{fileName:'workers.csv',exportDate:'2026-10-21',text:'user_id,email,name,email_verified\nsynthetic-auth-3,ada@example.com,Ada Employee,true\n'},201);
 const {generateKeyPair,exportJWK}=await import('jose'),pair=await generateKeyPair('ES256');
 const api=await command('resource-apis/register',{appId:app.id,name:'Erasure test API',audience:'https://crm.example.com/api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['record:1']}],resources:[{id:'record:1'}]},201);
 await command('resource-apis/service-create',{apiId:api.id,name:'Ada automation',purpose:'Employee-approved work',ownerId:'ada',jwks:{keys:[{...await exportJWK(pair.publicKey),kid:'synthetic-auth-4',alg:'ES256',use:'sig'}]},scopes:['read'],resources:['record:1'],expiresAt:new Date(r.now+3600000).toISOString()},201);
 assert.equal((await r.call('/api/auth/erasure/preview',{method:'POST',cookie:r.bob,data:{kind:'person',target:'ada'}})).status,403);
 await command('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 await command('erasure/preview',{kind:'person',target:'owner'},409);
 const hold=await command('erasure/hold',{kind:'person',target:'ada',reason:'Active employment dispute'},201);
 const held=await command('erasure/preview',{kind:'person',target:'ada'});assert.equal(held.holds.length,1);
 await command('erasure/confirm',{previewId:held.id,confirmation:'ERASE',confirmRemoteDeletion:true},409);assert.equal((await r.call('/api/auth/me',{cookie:second.cookie})).status,200);
 await command('erasure/hold',{release:true,id:hold.id});
 const plan=await command('erasure/preview',{kind:'person',target:'ada'});assert.ok(plan.stores.find(s=>s.store==='auth_passkeys').deleted>=2);assert.ok(plan.stores.find(s=>s.store==='auth_import_rows').deleted);
 await command('erasure/confirm',{previewId:plan.id,confirmation:'ERASE',confirmRemoteDeletion:true,destinations:['https://unapproved.example.com']},400);
 const erased=await command('erasure/confirm',{previewId:plan.id,confirmation:'ERASE',confirmRemoteDeletion:false,destinations:[]});assert.equal(erased.local,'complete');assert.equal((await r.call('/api/auth/me',{cookie:second.cookie})).status,401);
 assert.equal(remote(scim,'ada').active,false,'revocation does not wait for downstream deletion consent');
 const receipt=(await (await r.call('/api/auth/erasure/receipts',{cookie:r.owner.cookie})).json()).receipts.find(x=>x.id===erased.id);assert.equal(receipt.status,'remote_unfinished');assert.ok(receipt.remote.some(task=>task.state==='blocked'));assert.ok(receipt.stores.every(store=>store.status==='complete'));
 const tables=(await r.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND (name GLOB 'auth_*' OR name GLOB 'oa_*' OR name GLOB 'rer_*')").all()).results;
 for(const {name} of tables) {
  const text=JSON.stringify((await r.db.prepare(`SELECT * FROM "${name}"`).all()).results);
  assert.ok(!text.includes('ada@example.com'),name+' retains no erased email');
  assert.ok(!text.includes('synthetic-auth-2'),name+' retains no source identity');
 }
 const activity=await (await r.call('/api/auth/activity',{cookie:r.owner.cookie})).json();assert.ok(activity.some(row=>row.subject_id===erased.reference));assert.ok(activity.some(row=>row.event==='erasure_completed'));
 assert.equal((await r.call('/api/auth/move-in/subjects.csv?batch='+staged.batchId,{cookie:r.owner.cookie})).status,200);
 const later=await r.db.prepare('SELECT epoch FROM rer_portability_state').first();assert.ok(later.epoch>0);assert.ok((await r.db.prepare('SELECT COUNT(*) AS n FROM rer_portability_journal').first()).n>0);
 assert.ok(receipt.remote.some(task=>task.kind==='scim-delete'&&task.consentRequired));
 scim.fail(1,403);await command('erasure/retry',{receiptId:erased.id,confirmRemoteDeletion:true,destinations:['https://scim.example.com']});
 const refused=(await (await r.call('/api/auth/erasure/receipts',{cookie:r.owner.cookie})).json()).receipts.find(x=>x.id===erased.id);assert.ok(refused.remote.some(task=>task.kind==='scim-delete'&&task.lastStatus===403));
 await command('erasure/retry',{receiptId:erased.id,confirmRemoteDeletion:true,destinations:['https://scim.example.com']});assert.equal(remote(scim,'ada'),undefined);
 const complete=(await (await r.call('/api/auth/erasure/receipts',{cookie:r.owner.cookie})).json()).receipts.find(x=>x.id===erased.id);assert.equal(complete.status,'remote_unfinished');assert.ok(complete.remote.some(task=>task.kind==='scim-delete'&&task.state==='verified'));assert.ok(complete.remote.some(task=>task.kind==='partner-delete'&&task.state==='blocked'),'independently held partner data remains explicitly unresolved');
 await command('erasure/abandon',{receiptId:erased.id,confirmation:'ABANDON',destinations:complete.remote.filter(x=>x.state!=='verified').map(x=>x.partner)});
 const abandoned=(await (await r.call('/api/auth/erasure/receipts',{cookie:r.owner.cookie})).json()).receipts.find(x=>x.id===erased.id);assert.equal(abandoned.status,'remote_abandoned');assert.ok(abandoned.remote.some(x=>x.state==='abandoned'));assert.ok((await r.db.prepare('SELECT sealed_work FROM auth_erasure_remote WHERE receipt_id=?').bind(erased.id).all()).results.every(x=>x.sealed_work===null));
 const integrityPath='/api/auth/erasure/integrity?receiptId='+erased.id;let verified=await (await r.call(integrityPath,{cookie:r.owner.cookie})).json();assert.equal(verified.valid,true);assert.ok(verified.checked>0);
 const committedEvent=await r.db.prepare('SELECT id FROM auth_activity ORDER BY id LIMIT 1').first();await r.db.prepare("UPDATE auth_activity SET event='tampered' WHERE id=?").bind(committedEvent.id).run();verified=await (await r.call(integrityPath,{cookie:r.owner.cookie})).json();assert.equal(verified.valid,false);assert.ok(verified.changed>0);
});

test('app erasure removes connector custody and protected organization reset erases its last owner without touching another employer',async t=>{
 const {r,scim,app,connect}=await provisioned(t,{pushGroups:false});await connect();
 const {register}=await import('./webauthn.mjs'),{emailSession}=await import('./runtime.mjs');
 const command=async(client,cookie,path,data,status=200)=>{const response=await client.call('/api/auth/'+path,{method:'POST',data,cookie});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const admin=(path,data,status)=>command(r,r.owner.cookie,path,data,status);
 await admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'ada',role:'employee'});assert.ok(remote(scim,'ada'));
 await admin('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 let preview=await admin('erasure/preview',{kind:'app',target:app.id});
 const erased=await admin('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',confirmRemoteDeletion:true,destinations:[...new Set(preview.remote.map(x=>x.partner))]});assert.equal(erased.local,'complete');
 assert.equal(await r.db.prepare('SELECT app_id FROM auth_scim_connectors WHERE app_id=?').bind(app.id).first(),null);assert.equal(await r.db.prepare('SELECT id FROM auth_apps WHERE id=?').bind(app.id).first(),null);assert.equal(remote(scim,'ada'),undefined);assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,200,'app erasure preserves the person');
 const org=await admin('organizations/create',{name:'Subsidiary to be erased'},201),other=await admin('organizations/create',{name:'Retained partner workspace'},201);
 const scoped=id=>({origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+id+path,options)});
 const selected=scoped(org.id),kept=scoped(other.id),owner=await register(selected,await emailSession(selected,'owner@example.com')),keptOwner=await register(kept,await emailSession(kept,'owner@example.com'));
 const subsidiaryApp=await command(selected,owner.cookie,'company-apps/create',{entityId:'https://subsidiary-crm.example.com',acsUrl:'https://subsidiary-crm.example.com/acs'},201);
 await command(selected,owner.cookie,'provisioning/connect',{appId:subsidiaryApp.id,baseUrl:BASE,token:scim.token,pushGroups:false},201);
 await command(selected,owner.cookie,'company-apps/assign',{appId:subsidiaryApp.id,principalType:'person',principalId:(await (await selected.call('/api/auth/me',{cookie:owner.cookie})).json()).user.id,role:'employee'});
 scim.fail(2,403);
 await command(selected,owner.cookie,'erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 await command(selected,owner.cookie,'erasure/preview',{kind:'organization',target:org.id},403);
 preview=await admin('erasure/preview',{kind:'organization',target:org.id});
 await admin('erasure/confirm',{organizationId:org.id,previewId:preview.id,confirmation:'ERASE',confirmRemoteDeletion:true},400);
 const reset=await admin('erasure/confirm',{organizationId:org.id,previewId:preview.id,destinations:[...new Set(preview.remote.map(x=>x.partner))],confirmation:'RESET '+r.origin+'/org/'+org.id,confirmRemoteDeletion:true});assert.equal(reset.local,'complete');assert.ok(reset.journal.proof);assert.ok(reset.receipt.stores.find(s=>s.store==='oa_operators').deleted);
 assert.equal((await selected.call('/api/auth/me',{cookie:owner.cookie})).status,404,'erased organization cannot reappear as an empty issuer');assert.equal((await selected.call('/.well-known/openid-configuration')).status,404);
 assert.equal((await kept.call('/api/auth/me',{cookie:keptOwner.cookie})).status,200);assert.equal((await r.call('/api/auth/me',{cookie:r.owner.cookie})).status,200);
 const registry=await r.db.prepare('SELECT * FROM auth_organizations WHERE id=?').bind(org.id).first();assert.equal(registry.status,'erased');assert.equal(registry.name,reset.reference);
 const retained=(await (await r.call('/api/auth/erasure/receipts',{cookie:r.owner.cookie})).json()).receipts.find(x=>x.id===reset.id);assert.equal(retained.organizationId,org.id);assert.equal(retained.status,'remote_unfinished');assert.ok(retained.remote.some(x=>x.kind==='scim-delete'&&x.state==='blocked'));
 assert.doesNotMatch(JSON.stringify(retained),/sealed_work|sealed_token|owner@example.com/);
 await command(kept,keptOwner.cookie,'erasure/retry',{organizationId:org.id,receiptId:reset.id,confirmRemoteDeletion:true},403);
 await command(r,r.ada,'erasure/retry',{organizationId:org.id,receiptId:reset.id,confirmRemoteDeletion:true},403);
 const retried=await admin('erasure/retry',{organizationId:org.id,receiptId:reset.id,confirmRemoteDeletion:true,destinations:['https://scim.example.com']});
 assert.ok(retried.receipts.find(x=>x.id===reset.id).remote.some(x=>x.kind==='scim-delete'&&x.state==='verified'));
 assert.equal((await selected.call('/.well-known/openid-configuration')).status,404,'retained custody never reactivates the erased issuer');
 const integrity=await (await r.call('/api/auth/erasure/integrity?organizationId='+org.id+'&receiptId='+reset.id,{cookie:r.owner.cookie})).json();assert.equal(integrity.valid,true);assert.ok(integrity.checked>0);
 assert.equal((await r.call('/api/auth/erasure/journal?organizationId='+org.id+'&receiptId='+reset.id,{cookie:r.owner.cookie})).status,200);
});
