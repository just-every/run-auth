import assert from 'node:assert/strict';
import {samlInstall,addApp} from './saml-helpers.mjs';
import {passkeyPerson,post} from './agents-helpers.mjs';
import {authenticate} from './webauthn.mjs';
import {cookieOf} from './runtime.mjs';
import {scimServer} from './scim-server.mjs';

const result=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
export async function decisionProof(r,actor,data) {
 const offered=await r.call('/api/auth/decisions/options',post(data,actor.cookie));
 if(offered.status!==200)return {refused:offered};
 const tx=await offered.json();return {transaction:tx.transaction,cookie:actor.cookie+'; '+cookieOf(offered),response:actor.key.authenticate(tx.options)};
}
export async function decide(r,actor,data) {
 const proof=await decisionProof(r,actor,data);
 return proof.refused??r.call('/api/auth/decisions/commit',post({transaction:proof.transaction,response:proof.response},proof.cookie));
}
export async function accessDecisionsFlow(t) {
 const r=await samlInstall(t),manager=await passkeyPerson(r,'manager','manager@example.com','member');
 // Sign in again with a passkey, without transferring the enrollment email proof.
 manager.cookie=cookieOf((await authenticate(r,manager.key)).response);
 const session=await r.db.prepare("SELECT local_email_verified_at FROM auth_sessions WHERE person_id='manager' ORDER BY created_at DESC,rowid DESC LIMIT 1").first();assert.equal(session.local_email_verified_at,null);
 const group=await result(await r.admin('groups/create',{name:'Product operations'},),201);
 await result(await r.admin('groups/owners/add',{groupId:group.id,personId:'manager'}));
 const params={kind:'group',targetId:group.id,personId:'ada@example.com',operation:'add',reason:'Project delivery access'};
 assert.equal((await r.call('/api/auth/decisions/options',post(params,r.bob))).status,403,'email alone is not a decision proof');
 await result(await decide(r,manager,params));
 assert.ok(await r.db.prepare("SELECT 1 FROM auth_group_members WHERE group_id=? AND person_id='ada'").bind(group.id).first());
 const replay=await decisionProof(r,manager,{...params,personId:'bob'});await result(await r.call('/api/auth/decisions/commit',post({transaction:replay.transaction,response:replay.response},replay.cookie)));
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:replay.transaction,response:replay.response},replay.cookie))).status,400);
 assert.equal((await decide(r,manager,{...params,personId:'manager'})).status,403);
 const stale=await decisionProof(r,manager,{...params,operation:'remove'});
 await result(await r.admin('groups/add',{groupId:group.id,personId:'owner'}));
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:stale.transaction,response:stale.response},stale.cookie))).status,409);
 const removed=await decisionProof(r,manager,{...params,operation:'remove'});
 await result(await r.admin('groups/owners/remove',{groupId:group.id,personId:'manager'}));
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:removed.transaction,response:removed.response},removed.cookie))).status,403);
 await result(await r.admin('groups/owners/add',{groupId:group.id,personId:'manager'}));
 await result(await r.admin('decisions/privilege',{kind:'group',targetId:group.id,privileged:true}));
 assert.equal((await decide(r,manager,{...params,operation:'remove'})).status,403);
 await result(await decide(r,r.owner,{...params,operation:'remove'}));
 assert.equal((await r.call('/api/auth/recovery/approve',post({id:'not-a-recovery'},manager.cookie))).status,403);
 assert.equal((await r.call('/api/auth/decisions/privilege',post({kind:'group',targetId:group.id,privileged:false},manager.cookie))).status,403);
 // App classification protects every group that grants that app.
 const app=await addApp(r,{name:'Salesforce project workspace',entityId:'https://salesforce.example.com',acsUrl:'https://salesforce.example.com/acs',assign:[]});
 await result(await r.admin('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id,role:'reader'}));
 await result(await r.admin('decisions/privilege',{kind:'group',targetId:group.id,privileged:false}));
 await result(await r.admin('decisions/privilege',{kind:'app',targetId:app.id,privileged:true}));
 assert.equal((await decide(r,manager,params)).status,403);
 const history=(await r.db.prepare("SELECT * FROM auth_decision_operations WHERE actor_id='manager'").all()).results;assert.equal(history.length,2);assert.ok(history.every(h=>h.reason));
}
export async function requestDecisionsFlow(t) {
 const r=await samlInstall(t),manager=await passkeyPerson(r,'manager','manager@example.com','member'),employee=await passkeyPerson(r,'worker','worker@example.com','member');
 manager.cookie=cookieOf((await authenticate(r,manager.key)).response);
 const app=await addApp(r,{name:'Salesforce',entityId:'https://salesforce.example.com',acsUrl:'https://salesforce.example.com/acs',assign:[]});
 await result(await r.admin('decisions/privilege',{kind:'app',targetId:app.id,privileged:false}));
 await result(await r.admin('requests/policy',{appId:app.id,deciderId:'manager',maxDurationMs:3600000}));
 const request=await result(await r.call('/api/auth/requests/create',post({appId:app.id,purpose:'Quarterly customer account handover',role:'reader',durationMs:60000},employee.cookie)),201);
 assert.equal((await decide(r,employee,{kind:'request',targetId:request.id,operation:'approve',reason:'Self approval'})).status,403);
 const stale=await decisionProof(r,manager,{kind:'request',targetId:request.id,operation:'approve',reason:'Need access for handover'});
 await result(await r.admin('requests/policy',{appId:app.id,deciderId:'owner',maxDurationMs:3600000}));
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:stale.transaction,response:stale.response},stale.cookie))).status,409);
 await result(await r.call('/api/auth/requests/cancel',post({id:request.id},employee.cookie)));
 await result(await r.admin('requests/policy',{appId:app.id,deciderId:'manager',maxDurationMs:3600000}));
 const next=await result(await r.call('/api/auth/requests/create',post({appId:app.id,purpose:'Read project records',role:'reader',durationMs:60000},employee.cookie)),201);
 const proof=await decisionProof(r,manager,{kind:'request',targetId:next.id,operation:'approve',reason:'Approved read-only handover'});
 await result(await r.call('/api/auth/decisions/commit',post({transaction:proof.transaction,response:proof.response},proof.cookie)));
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:proof.transaction,response:proof.response},proof.cookie))).status,400);
 assert.deepEqual((await result(await r.call('/api/auth/launcher',{cookie:employee.cookie}))).apps.map(a=>a.id),[app.id]);
 r.now+=61000;await r.call('/',{action:'maintain'});
 assert.deepEqual((await result(await r.call('/api/auth/launcher',{cookie:employee.cookie}))).apps,[]);
 const expired=await r.db.prepare('SELECT * FROM auth_access_requests WHERE id=?').bind(next.id).first();assert.equal(expired.state,'revocation_pending','no connector acknowledgment can close remote removal');
 await r.restart();assert.equal((await r.db.prepare('SELECT state FROM auth_access_requests WHERE id=?').bind(next.id).first()).state,'revocation_pending');
}
export async function accessReviewsFlow(t) {
 const r=await samlInstall(t),manager=await passkeyPerson(r,'manager','manager@example.com','member'),alternate=await passkeyPerson(r,'alternate','alternate@example.com','member'),edge=await scimServer(t,'synthetic-auth-9');r.scimServer=edge.url;
 manager.cookie=cookieOf((await authenticate(r,manager.key)).response);alternate.cookie=cookieOf((await authenticate(r,alternate.key)).response);
 await result(await r.admin('directory/edit',{personId:'bob',set:{kind:'contractor'}}));
 await r.person('build-service','build-service@example.com');await result(await r.admin('directory/edit',{personId:'build-service',set:{kind:'service'}}));
 const app=await addApp(r,{name:'Project CRM',entityId:'https://crm.example.com',acsUrl:'https://crm.example.com/acs',assign:['ada','bob','build-service']});
 await result(await r.admin('provisioning/connect',{appId:app.id,baseUrl:'https://scim.example.com/scim/v2',token:'synthetic-auth-9'}),201);
 const periodEnd=r.now,periodStart=r.now-86400000;
 const review=await result(await r.admin('reviews/create',{name:'Quarterly access certification',reviewerId:'manager',periodStart,periodEnd,dueAt:r.now+3600000,intervalMonths:3}),201);
 const read=async cookie=>result(await r.call('/api/auth/reviews',{cookie:cookie??r.owner.cookie}));
 const initial=(await read()).reviews[0];assert.deepEqual(initial.items.map(i=>i.snapshot.identity.kind).sort(),['contractor','employee','service']);
 const ada=initial.items.find(i=>i.subject_id==='ada'),bob=initial.items.find(i=>i.subject_id==='bob'),service=initial.items.find(i=>i.subject_id==='build-service');
 await result(await r.admin('reviews/delegate',{itemId:service.id,reviewerId:'alternate',reason:'Service access reviewed by platform owner'}));
 assert.equal((await decide(r,manager,{kind:'review',targetId:service.id,operation:'certify',reason:'No longer assigned'})).status,403);
 await result(await decide(r,alternate,{kind:'review',targetId:service.id,operation:'certify',reason:'Build integration is still used'}));
 await result(await decide(r,manager,{kind:'review',targetId:ada.id,operation:'certify',reason:'Employee still needs read access'}));
 edge.fail(10,503);
 await result(await decide(r,manager,{kind:'review',targetId:bob.id,operation:'revoke',reason:'Contract concluded'}));
 const exported=await result(await r.call('/api/auth/reviews/export?id='+review.id,{cookie:r.owner.cookie}));
 assert.equal(exported.review.completion.complete,false);assert.ok(exported.review.completion.unfinished>0);
 assert.equal((await r.admin('reviews/close',{id:review.id})).status,409);
 await result(await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'manager',role:'reader'}));
 const changed=(await read()).reviews[0];assert.ok(changed.newAccess.some(i=>i.identity.id==='manager'));assert.deepEqual(changed.items.find(i=>i.id===bob.id).snapshot,bob.snapshot);
 r.now=periodEnd+3600001;await r.call('/',{action:'maintain'});await r.restart();
 assert.equal((await read()).reviews[0].overdue,true);assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM auth_review_events WHERE review_id=? AND event='overdue_escalated'").bind(review.id).first()).n,1);
 edge.faults.length=0;await r.admin('provisioning/retry',{appId:app.id});
 const final=(await read()).reviews[0];assert.equal(final.completion.complete,true,JSON.stringify(final.completion));
 await result(await r.admin('reviews/close',{id:review.id}));
 assert.equal((await read()).reviews[0].status,'closed');
}
