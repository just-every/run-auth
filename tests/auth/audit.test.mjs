import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ownerInstall,passkeyPerson,post} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';

const read=async(r,path,cookie)=>{const response=await r.call(path,{cookie});assert.equal(response.status,200,await response.clone().text());return response.json();};
async function plan(r,cookie,data) {
 const response=await r.call('/api/auth/roles/preview',post(data,cookie));assert.equal(response.status,200,await response.clone().text());
 const preview=await response.json(),applied=await r.call('/api/auth/roles/apply',post({previewId:preview.previewId},cookie));assert.equal(applied.status,200,await applied.clone().text());return preview.plan;
}

test('interactive audit finds twelve-month sign-ins and reconciles a frozen authorized set beyond the old cap across restart and concurrent appends',async t=>{
 const {r,owner}=await ownerInstall(t),now=r.now;
 await r.person('worker','synthetic-auth-1@example.com');
 const old=new Date(now);old.setUTCFullYear(old.getUTCFullYear()-1);r.now=old.getTime();await emailSession(r,'synthetic-auth-1@example.com');r.now=now;
 const historical=await read(r,'/api/auth/audit?person=worker&event=email_confirmed&from='+old.getTime()+'&to='+old.getTime(),owner.cookie);
 assert.equal(historical.total,1);assert.equal(historical.events[0].created_at,old.getTime());
 assert.equal((await read(r,'/api/auth/retention',owner.cookie)).policy.configured,false);
 const expected=[];
 for(let start=0;start<1105;start+=100) {
  const batch=Array.from({length:Math.min(100,1105-start)},()=>r.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES('owner','person_invited','worker',?) RETURNING id").bind(now-1000));
  const results=await r.db.batch(batch);expected.push(...results.map(result=>result.results[0].id));
 }
 const base='/api/auth/audit?person=worker&event=person_invited&limit=100&from='+(now-2000)+'&to='+now;
 let page=await read(r,base,owner.cookie);assert.equal(page.total,1105);assert.equal(page.events.length,100);
 r.now+=15*60000;assert.equal((await r.call(base+'&cursor='+encodeURIComponent(page.nextCursor),{cookie:owner.cookie})).status,410);
 assert.equal((await read(r,base,owner.cookie)).total,1105,'a new read needs current authority without fresh email write proof');r.now=now;
 const rolePage=await read(r,base.replace('/api/auth/audit','/api/auth/roles/audit'),owner.cookie);
 assert.equal(rolePage.total,1105);assert.deepEqual(rolePage.events,page.events);assert.ok(rolePage.nextCursor);
 const first=page.events[0].eventId,ids=page.events.map(e=>e.id),eventIds=page.events.map(e=>e.eventId);
 await r.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES('owner','person_invited','worker',?)").bind(now-1000).run();
 await r.restart();
 assert.equal((await r.call(base+'&cursor='+encodeURIComponent(page.nextCursor)+'x',{cookie:owner.cookie})).status,400);
 assert.equal((await r.call(base.replace('limit=100','limit=99')+'&cursor='+encodeURIComponent(page.nextCursor),{cookie:owner.cookie})).status,409);
 while(page.nextCursor) {
  page=await read(r,base+'&cursor='+encodeURIComponent(page.nextCursor),owner.cookie);
  assert.equal(page.total,1105);ids.push(...page.events.map(e=>e.id));eventIds.push(...page.events.map(e=>e.eventId));
 }
 assert.deepEqual(ids,expected.reverse());assert.equal(new Set(eventIds).size,1105);
 assert.equal((await read(r,base,owner.cookie)).total,1106);
 assert.equal((await r.call(base+'&cursor=bad',{cookie:owner.cookie})).status,400);
 assert.equal((await r.call(base+'&to=0',{cookie:owner.cookie})).status,400);
 const reread=await read(r,base,owner.cookie);assert.equal(reread.events[1].eventId,first);
 for(const query of ['limit=101','from=invalid','from=2&to=1','event=bad%20event'])assert.equal((await r.call('/api/auth/audit?'+query,{cookie:owner.cookie})).status,400);
});

test('interactive audit rechecks employer, person scope and revoked auditor authority without conferring directory or export writes',async t=>{
 const {r,owner}=await ownerInstall(t);
 const auditor=await passkeyPerson(r,'auditor','synthetic-auth-2@example.com','member');
 await r.person('inside','synthetic-auth-3@example.com');await r.person('outside','synthetic-auth-4@example.com');
 const groupResponse=await r.call('/api/auth/groups/create',post({name:'Audit scope'},owner.cookie));assert.equal(groupResponse.status,201);const group=await groupResponse.json();
 const appResponse=await r.call('/api/auth/company-apps/create',post({name:'Audit app',entityId:'https://audit.example.com',acsUrl:'https://audit.example.com/acs'},owner.cookie));assert.equal(appResponse.status,201);const app=await appResponse.json();
 const resources={view:{people:['inside'],groups:[group.id],apps:[app.id]},edit:{}};
 const granted=await plan(r,owner.cookie,{kind:'grant',personId:'auditor',roleId:'auditor',resources});
 for(const subject of ['inside','outside','inside'])await r.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES('owner','person_invited',?,?)").bind(subject,r.now).run();
 for(const personId of ['inside','outside']) {
  for(const action of ['assign','unassign'])assert.equal((await r.call('/api/auth/company-apps/'+action,post({appId:app.id,principalType:'person',principalId:personId},owner.cookie))).status,200);
  for(const action of ['add','remove'])assert.equal((await r.call('/api/auth/groups/'+action,post({groupId:group.id,personId},owner.cookie))).status,200);
 }
 const excludedGroup=await (await r.call('/api/auth/groups/create',post({name:'Excluded audit group'},owner.cookie))).json();
 for(const groupId of [group.id,excludedGroup.id])for(const action of ['assign','unassign'])assert.equal((await r.call('/api/auth/company-apps/'+action,post({appId:app.id,principalType:'group',principalId:groupId},owner.cookie))).status,200);
 for(const personId of ['inside','outside'])for(const action of ['add','remove'])assert.equal((await r.call('/api/auth/roles/group',post({groupId:group.id,personId,action},owner.cookie))).status,200);
 for(const event of ['app_assigned','app_unassigned','group_member_added','group_member_removed','roles.group.add','roles.group.remove'])for(const door of ['/api/auth/audit','/api/auth/roles/audit']) {
  const result=await read(r,door+'?event='+event+'&limit=1',auditor.cookie);
  const expected=event.startsWith('app_')?2:1;
  assert.equal(result.total,expected,event+' excludes related resources from the count');assert.equal(result.events.length,1);
  if(expected===2){assert.ok(result.nextCursor);const next=await read(r,door+'?event='+event+'&limit=1&cursor='+encodeURIComponent(result.nextCursor),auditor.cookie);assert.equal(next.total,2);assert.equal(next.events.length,1);assert.notEqual(next.events[0].id,result.events[0].id);assert.equal(next.nextCursor,null);}else assert.equal(result.nextCursor,null);
 }
 const base='/api/auth/audit?event=person_invited&limit=1',page=await read(r,base,auditor.cookie);
 assert.equal(page.total,2);assert.deepEqual(page.events.map(e=>e.subject_id),['inside']);assert.equal(page.events[0].detail,undefined);assert.equal(page.events[0].actor_email,undefined);
 assert.equal((await r.call(base)).status,401);
 const emailOnly=await emailSession(r,'synthetic-auth-2@example.com');assert.equal((await r.call(base,{cookie:emailOnly})).status,403,'interactive audit still requires hardware proof');
 assert.equal((await r.call('/api/auth/audit?person=outside',{cookie:auditor.cookie})).status,403);
 assert.equal((await r.call('/api/auth/activity',{cookie:auditor.cookie})).status,403,'legacy full-detail feed stays administrator only');
 assert.equal((await r.call('/api/auth/directory/edit',post({personId:'inside',set:{name:'Unauthorized'}},auditor.cookie))).status,403);
 assert.equal((await r.call('/api/auth/roles/profile',post({personId:'inside',set:{name:'Unauthorized'}},auditor.cookie))).status,403);
 assert.equal((await r.db.prepare("SELECT display_name FROM oa_operators WHERE id='inside'").first()).display_name,'inside');
 const custom=await plan(r,owner.cookie,{kind:'role',role:{name:'Read logs only',rank:9,permissions:['audit.view']}});
 const reader=await passkeyPerson(r,'reader','synthetic-auth-5@example.com','member');
 await plan(r,owner.cookie,{kind:'grant',personId:'reader',roleId:custom.role.id,resources});
 assert.equal((await r.call('/api/auth/roles/audit/export',{cookie:reader.cookie})).status,403,'interactive view never grants export');
 const org=await (await r.call('/api/auth/organizations/create',post({name:'Separate employer'},owner.cookie))).json();assert.ok(org.id);
 const client={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+org.id+path,options)};
 const orgOwner=await register(client,await emailSession(client,'owner@example.com'));
 assert.equal((await client.call('/api/auth/audit',{cookie:owner.cookie})).status,401);
 assert.equal((await client.call(base+'&cursor='+encodeURIComponent(page.nextCursor),{cookie:orgOwner.cookie})).status,409);
 const orgPage=await read(client,'/api/auth/audit?event=person_invited',orgOwner.cookie);assert.equal(orgPage.total,0);
 const current=await read(r,base,auditor.cookie);
 await plan(r,owner.cookie,{kind:'revoke',grantId:granted.id});
 for(const path of [base,base+'&cursor='+encodeURIComponent(current.nextCursor),'/api/auth/roles/audit'])assert.equal((await r.call(path,{cookie:auditor.cookie})).status,403);
});

test('interactive audit preserves stable event IDs and opaque projections after real subject erasure',async t=>{
 const {r,owner}=await ownerInstall(t);
 const response=await r.call('/api/auth/directory/onboard',post({email:'synthetic-auth-6@example.com',name:'Morgan Synthetic',kind:'employee'},owner.cookie));assert.equal(response.status,201);const worker=await response.json();
 const before=await read(r,'/api/auth/audit?person='+worker.id,owner.cookie);assert.ok(before.events.some(e=>e.event==='person_onboarded'));
 const original=before.events.find(e=>e.event==='person_onboarded');
 await r.call('/api/auth/erasure/policy',post({confirm:true,automaticDeletion:false,honorLegalHolds:true},owner.cookie));
 const preview=await r.call('/api/auth/erasure/preview',post({kind:'person',target:worker.id},owner.cookie));assert.equal(preview.status,200);const proposal=await preview.json();
 const erased=await r.call('/api/auth/erasure/confirm',post({previewId:proposal.id,confirmation:'ERASE',destinations:[]},owner.cookie));assert.equal(erased.status,200,await erased.clone().text());const receipt=await erased.json();
 await r.restart();
 const after=await read(r,'/api/auth/audit?event=person_onboarded',owner.cookie),row=after.events.find(e=>e.eventId===original.eventId);assert.ok(row);assert.equal(row.subject_id,receipt.reference);
 for(const personal of ['Morgan Synthetic','synthetic-auth-6@example.com',worker.id])assert.ok(!JSON.stringify(after).includes(personal));
 assert.equal(row.eventId,original.eventId);assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM oa_operators WHERE id=?').bind(worker.id).first()).n,0);
});
