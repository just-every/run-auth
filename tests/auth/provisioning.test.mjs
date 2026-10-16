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
