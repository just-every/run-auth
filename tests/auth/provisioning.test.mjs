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

test('app erasure removes connector custody and protected organization reset retains only installation-owner anonymous outcomes and credential-free pending work',async t=>{
 const {r,scim,app,connect}=await provisioned(t,{pushGroups:false});await connect();
 const {register}=await import('./webauthn.mjs'),{emailSession}=await import('./runtime.mjs');
 const {passkeyPerson,signInAgain}=await import('./agents-helpers.mjs'),{unseal}=await import('../../src/auth/keys.mjs');
 const command=async(client,cookie,path,data,status=200)=>{const response=await client.call('/api/auth/'+path,{method:'POST',data,cookie});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const admin=(path,data,status)=>command(r,r.owner.cookie,path,data,status);
 const receipts=async()=>{const response=await r.call('/api/auth/erasure/receipts',{cookie:r.owner.cookie});assert.equal(response.status,200);return (await response.json()).receipts;};
 await admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'ada',role:'employee'});assert.ok(remote(scim,'ada'));
 await admin('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 let preview=await admin('erasure/preview',{kind:'app',target:app.id});
 const erased=await admin('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',confirmRemoteDeletion:true,destinations:[...new Set(preview.remote.map(x=>x.partner))]});assert.equal(erased.local,'complete');
 assert.equal(await r.db.prepare('SELECT app_id FROM auth_scim_connectors WHERE app_id=?').bind(app.id).first(),null);assert.equal(await r.db.prepare('SELECT id FROM auth_apps WHERE id=?').bind(app.id).first(),null);assert.equal(remote(scim,'ada'),undefined);assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,200,'app erasure preserves the person');
 const installationAdmin=await passkeyPerson(r,'synthetic-auth-admin','admin@example.com','admin');
 const orgName='Subsidiary to be erased',org=await admin('organizations/create',{name:orgName},201),other=await admin('organizations/create',{name:'Retained partner workspace'},201);
 const scoped=id=>({origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+id+path,options)});
 const selected=scoped(org.id),kept=scoped(other.id);
 let owner=await register(selected,await emailSession(selected,'owner@example.com')),keptOwner=await register(kept,await emailSession(kept,'owner@example.com'));
 const subsidiaryApp=await command(selected,owner.cookie,'company-apps/create',{name:'Subsidiary CRM',entityId:'https://subsidiary-crm.example.com',acsUrl:'https://subsidiary-crm.example.com/acs'},201);
 const originalToken=scim.token;
 await command(selected,owner.cookie,'provisioning/connect',{appId:subsidiaryApp.id,baseUrl:BASE,token:originalToken,pushGroups:false},201);
 const employee=(await (await selected.call('/api/auth/me',{cookie:owner.cookie})).json()).user.id;
 await command(selected,owner.cookie,'company-apps/assign',{appId:subsidiaryApp.id,principalType:'person',principalId:employee,role:'employee'});
 await command(selected,owner.cookie,'erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const orgKeys=await (await selected.call('/oidc/jwks')).json();assert.ok(orgKeys.keys.length);
 await command(selected,owner.cookie,'erasure/preview',{kind:'organization',target:org.id},403);
 const stale=await command(selected,owner.cookie,'erasure/reset-preview',{});
 await command(selected,owner.cookie,'company-apps/update',{id:subsidiaryApp.id,name:'Subsidiary CRM renamed',entityId:'https://subsidiary-crm.example.com',acsUrl:'https://subsidiary-crm.example.com/acs'});
 await command(selected,owner.cookie,'erasure/reset-consent',{previewId:stale.id,confirmation:'AUTHORIZE DELETION',destinations:['https://scim.example.com'],confirmRemoteDeletion:true},409);
 const consent=async()=>{
  const plan=await command(selected,owner.cookie,'erasure/reset-preview',{});assert.ok(plan.remote.some(x=>x.partner==='https://scim.example.com'));
  return command(selected,owner.cookie,'erasure/reset-consent',{previewId:plan.id,confirmation:'AUTHORIZE DELETION',destinations:['https://scim.example.com'],confirmRemoteDeletion:true});
 };
 const expired=await consent();r.now=expired.expiresAt+1;
 r.owner=await signInAgain(r,r.owner,'owner@example.com');owner=await signInAgain(selected,owner,'owner@example.com');keptOwner=await signInAgain(kept,keptOwner,'owner@example.com');
 const expiredPreview=await admin('erasure/preview',{kind:'organization',target:org.id});assert.ok(expiredPreview.remote.every(x=>x.deletionPreauthorized===false),'expired employer consent cannot authorize a root deletion');
 await consent();
 preview=await admin('erasure/preview',{kind:'organization',target:org.id});
 assert.ok(preview.remote.some(x=>x.deletionPreauthorized===true));assert.ok(preview.remote.every(x=>!Object.hasOwn(x,'partner')),'root reset preview discloses no destination');
 await admin('erasure/confirm',{organizationId:org.id,previewId:preview.id,confirmation:'ERASE'},400);
 await admin('erasure/confirm',{organizationId:org.id,previewId:preview.id,confirmation:'RESET '+r.origin+'/org/'+org.id,destinations:['https://scim.example.com'],confirmRemoteDeletion:true},403);
 const resetStart=scim.log.length;scim.fail(2,403); // Both initial revocation PATCH and consented DELETE are refused.
 const reset=await admin('erasure/confirm',{organizationId:org.id,previewId:preview.id,confirmation:'RESET '+r.origin+'/org/'+org.id});assert.equal(reset.local,'complete');assert.ok(reset.journal.proof);assert.ok(reset.receipt.stores.find(s=>s.store==='oa_operators').deleted);
 assert.ok(scim.log.slice(resetStart).some(x=>x.method==='PATCH'));assert.ok(scim.log.slice(resetStart).some(x=>x.method==='DELETE'));assert.ok(remote(scim,employee),'provider refusal does not fabricate completed deletion');
 const doors=[['/'],['/signin'],['/app/account'],['/.well-known/openid-configuration'],['/oidc/jwks'],['/oidc/authorize'],['/oidc/userinfo'],['/oidc/token','POST'],['/oidc/logout'],['/saml/metadata'],['/saml/sso'],['/saml/slo'],['/api/auth/me'],['/api/auth/profile'],['/api/auth/roles'],['/api/auth/erasure/receipts'],['/api/auth/admin/v1/openapi.json'],['/api/auth/preparer'],['/auth/identity/email/request','POST'],['/auth/passkeys/authenticate/options','POST']];
 for(const [path,method='GET'] of doors)assert.equal((await selected.call(path,{method,cookie:owner.cookie,...(method==='POST'?{data:{email:'owner@example.com'}}:{})})).status,404,'erased issuer stays absent at '+path);
 assert.equal((await kept.call('/api/auth/me',{cookie:keptOwner.cookie})).status,200);assert.equal((await r.call('/api/auth/me',{cookie:r.owner.cookie})).status,200);
 const registry=await r.db.prepare('SELECT * FROM auth_organizations WHERE id=?').bind(org.id).first();assert.equal(registry.status,'erased');assert.equal(registry.name,reset.reference);
 let retained=(await receipts()).find(x=>x.id===reset.id);assert.equal(retained.retained,true);assert.equal(retained.organizationId,undefined);assert.equal(retained.status,'remote_unfinished');
 const removal=retained.remote.find(x=>x.kind==='scim-delete'),revocation=retained.remote.find(x=>x.kind==='scim-deactivate'),unconsented=retained.remote.find(x=>x.kind==='partner-delete'&&x.consentRequired);
 assert.ok(removal&&revocation&&unconsented);assert.equal(removal.state,'blocked');assert.equal(revocation.state,'blocked');
 const rootProjection=value=>{
  const rendered=JSON.stringify(value);
  for(const secret of [originalToken,employee,org.id,r.origin+'/org/'+org.id,'owner@example.com','https://scim.example.com','https://subsidiary-crm.example.com',...orgKeys.keys.map(k=>k.kid)])assert.ok(!rendered.includes(secret),'root projection excludes employer identity, destination, credentials and keys');
  assert.doesNotMatch(rendered,/sealed_work|sealed_token|encrypted_private/);
 };
 rootProjection(retained);rootProjection(reset.journal);assert.ok(retained.remote.every(x=>x.partner===undefined&&x.appLabel));
 const table=registry.namespace+'auth_erasure_remote',pending=async()=>(await r.db.prepare('SELECT * FROM "'+table+'" WHERE receipt_id=?').bind(reset.id).all()).results;
 const sealed=await pending();assert.ok(sealed.some(row=>row.sealed_work));
 for(const row of sealed.filter(row=>row.sealed_work)) {
  const work=await unseal({secret:'1a'.repeat(32)},'erasure:'+row.id,row.sealed_work);
  assert.ok(!JSON.stringify(work).includes(originalToken));
  const credentialFree=value=>{if(value&&typeof value==='object')for(const [key,v] of Object.entries(value)){assert.doesNotMatch(key,/token|secret|credential|private|jwk|signing/i,'pending work retains no credential material');credentialFree(v);}};
  credentialFree(work);
 }
 const allRows=async()=>{
  const tables=(await r.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").all()).results;
  return JSON.stringify(await Promise.all(tables.map(({name})=>r.db.prepare('SELECT * FROM "'+name.replaceAll('"','""')+'"').all().then(result=>result.results))));
 };
 assert.ok(!(await allRows()).includes(originalToken),'the employer connector credential has been destroyed everywhere in persistence');
 const retry={retained:true,receiptId:reset.id,workId:removal.id,confirmRetry:true};
 await command(kept,keptOwner.cookie,'erasure/retry',retry,403);await command(r,r.ada,'erasure/retry',retry,403);
 const freshAdmin=await signInAgain(r,installationAdmin,'admin@example.com');
 await command(r,freshAdmin.cookie,'erasure/retry',retry,403);assert.equal((await r.call('/api/auth/erasure/receipts',{cookie:freshAdmin.cookie})).status,403);
 await admin('erasure/retry',{...retry,destinations:['https://scim.example.com'],confirmRemoteDeletion:true},403);
 await admin('erasure/retry',{...retry,workId:unconsented.id},403);
 await admin('erasure/retry',{...retry,confirmRetry:false},400);
 const without=scim.log.length;await admin('erasure/retry',retry);assert.equal(scim.log.length,without,'no destroyed connector credential is reused');
 retained=(await receipts()).find(x=>x.id===reset.id);assert.equal(retained.remote.find(x=>x.id===removal.id).state,'blocked');
 scim.token='synthetic-auth-9';
 const refusedConnection=async token=>{
  const start=scim.log.length,result=await admin('erasure/retry',{...retry,connection:{token}}),item=result.receipts.find(x=>x.id===reset.id).remote.find(x=>x.id===removal.id);
  assert.equal(item.state,'blocked');assert.ok(scim.log.slice(start).some(x=>x.method==='GET'));assert.ok(scim.log.slice(start).every(x=>x.method==='GET'),'unverified binding never sends a DELETE');return item;
 };
 assert.equal((await refusedConnection('synthetic-auth-8')).lastStatus,401,'a wrong fresh credential cannot establish tenant binding');
 const account=remote(scim,employee);scim.users.delete(account.id);
 assert.equal((await refusedConnection(scim.token)).lastStatus,404,'an unbound absence is not proof of tenant authority or completed deletion');scim.users.set(account.id,account);
 account.externalId='synthetic-auth-foreign-person';assert.equal((await refusedConnection(scim.token)).lastStatus,200,'another account binding is refused despite a valid token');account.externalId=employee;
 const retried=await admin('erasure/retry',{...retry,connection:{token:scim.token}}),after=retried.receipts.find(x=>x.id===reset.id);assert.equal(after.remote.find(x=>x.id===removal.id).state,'verified');assert.equal(remote(scim,employee),undefined);
 assert.equal(after.remote.find(x=>x.id===revocation.id).state,'blocked','one-purpose retry does not dispatch a sibling work item');assert.equal((await pending()).find(row=>row.id===removal.id).sealed_work,null,'completion destroys its sealed identifier');
 assert.ok(!(await allRows()).includes(scim.token),'the one-purpose fresh connection is never persisted');rootProjection(after);
 const journalResponse=await r.call('/api/auth/erasure/journal?receiptId='+reset.id,{cookie:r.owner.cookie});assert.equal(journalResponse.status,200);const journal=await journalResponse.json();rootProjection(journal);
 const {proof,...commitment}=journal,installationKey=await crypto.subtle.importKey('raw',Buffer.from('1a'.repeat(32),'hex'),{name:'HMAC',hash:'SHA-256'},false,['verify']);
 assert.equal(proof.algorithm,'HMAC-SHA256');assert.equal(journal.receiptId,reset.id);assert.ok(await crypto.subtle.verify('HMAC',installationKey,Buffer.from(proof.signature,'base64url'),new TextEncoder().encode(JSON.stringify(commitment))),'anonymous receipt is authenticated by the installation');
 const integrity=await r.call('/api/auth/erasure/integrity?receiptId='+reset.id,{cookie:r.owner.cookie});assert.equal(integrity.status,200);const verified=await integrity.json();assert.equal(verified.valid,true);assert.ok(verified.checked>0);rootProjection(verified);
 assert.equal((await r.call('/api/auth/erasure/journal?receiptId='+reset.id,{cookie:freshAdmin.cookie})).status,403);
 const replacement=await admin('organizations/create',{name:orgName},201),recreated=scoped(replacement.id),replacementOwner=await register(recreated,await emailSession(recreated,'owner@example.com'));
 assert.notEqual(replacement.id,org.id);const own=await recreated.call('/api/auth/erasure/receipts',{cookie:replacementOwner.cookie});assert.equal(own.status,200);assert.deepEqual((await own.json()).receipts,[]);
 await command(recreated,replacementOwner.cookie,'erasure/retry',retry,403);assert.equal((await recreated.call('/api/auth/erasure/journal?receiptId='+reset.id,{cookie:replacementOwner.cookie})).status,404);
 const abandoned=await admin('erasure/abandon',{retained:true,receiptId:reset.id,workIds:after.remote.filter(x=>x.state!=='verified').map(x=>x.id),confirmation:'ABANDON'});assert.equal(abandoned.receipts.find(x=>x.id===reset.id).status,'remote_abandoned');assert.ok((await pending()).every(row=>row.sealed_work===null));
 const audit=(await r.db.prepare("SELECT event,subject_id FROM auth_activity WHERE event LIKE 'erasure_custody_%'").all()).results;
 for(const kind of ['view','retry','connection','abandon'])assert.ok(audit.some(x=>x.event==='erasure_custody_'+kind),'installation audit records custody '+kind);
 assert.equal((await selected.call('/.well-known/openid-configuration')).status,404,'root custody and a same-named replacement never revive the erased issuer');
});
