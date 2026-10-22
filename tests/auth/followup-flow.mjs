import assert from 'node:assert/strict';
import {openRuntime,emailSession} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
import {register} from './webauthn.mjs';
import {scimServer} from './scim-server.mjs';
export async function followupFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.realOutbox=true;r.now=Date.parse('2026-03-06T14:00:00Z');
 r.owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 let recovering=await passkeyPerson(r,'ada','ada@example.com','member');
 await r.person('bob','bob@example.com');const bob=await emailSession(r,'bob@example.com');
 const admin=async(path,data,status=200)=>{const response=await r.call('/api/auth/'+path,{method:'POST',cookie:r.owner.cookie,data});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const read=async()=>{const response=await r.call('/api/auth/followup',{cookie:r.owner.cookie});assert.equal(response.status,200,await response.clone().text());return response.json();};
 const settings={confirm:true,enabled:true,calendar:{timezone:'America/New_York',weekdays:[1,2,3,4,5],holidays:['2026-03-10'],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:2,recipients:['owner'],escalationRecipients:['owner'],escalation:'repeat_until_resolved'};
 assert.equal((await r.call('/api/auth/followup',{cookie:bob})).status,403);
 assert.equal((await r.call('/api/auth/followup/settings',{method:'POST',cookie:bob,data:settings})).status,403);
 await admin('followup/settings',{...settings,confirm:false},400);
 await admin('followup/settings',{...settings,recipients:['bob']},400);
 await admin('followup/settings',settings);
 await admin('people/invite',{email:'newhire@example.com',name:'New hire'},201);
 await admin('people/invite',{email:'leaver@example.com',name:'Unenrolled leaver'},201);
 const leaverCookie=await emailSession(r,'leaver@example.com'),leaver=(await (await r.call('/api/auth/me',{cookie:leaverCookie})).json()).user;
 await admin('people/suspend',{personId:leaver.id});
 const cancelled=await admin('organizations/invite',{email:'cancelled@example.com'},201);
 const expiring=await admin('organizations/invite',{email:'expiring@example.com',expiresAt:r.now+3600000},201);
 const recovery=await r.call('/api/auth/recovery/start',{method:'POST',cookie:recovering.cookie,data:{}});assert.equal(recovery.status,201);const recoveryId=(await recovery.json()).id;
 const scim=await scimServer(t);r.scimServer=scim.url;
 const app=await admin('company-apps/create',{name:'Payroll',entityId:'https://payroll.example.com',acsUrl:'https://payroll.example.com/acs'},201);
 await admin('provisioning/connect',{appId:app.id,baseUrl:'https://scim.example.com/scim/v2',token:scim.token,pushGroups:false},201);
 await admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'bob'});
 const remote=()=>[...scim.users.values()].find(p=>p.externalId==='bob');assert.equal(remote().active,true);
 scim.fail(100,403);await admin('company-apps/unassign',{appId:app.id,principalType:'person',principalId:'bob'});assert.equal(remote().active,true,'a refused deprovision stays unresolved');
 const before=await read(),enrollment=before.obligations.find(o=>o.kind==='enrollment'&&o.state==='open'&&o.person_id!==cancelled.id&&o.person_id!==expiring.id),failed=before.obligations.find(o=>o.kind==='provisioning'&&o.state==='open');
 assert.ok(enrollment&&failed);assert.equal(before.obligations.find(o=>o.person_id===leaver.id).state,'cancelled','suspension stops email-activated enrollment before a passkey exists');
 const recoveringOb=before.obligations.find(o=>o.kind==='recovery');assert.equal(recoveringOb.owner_id,'ada');
 await admin('followup/schedule',{id:recoveringOb.id,ownerId:'owner',dueBusinessDays:1,deadlineBusinessDays:2});
 assert.equal((await read()).obligations.find(o=>o.id===recoveringOb.id).owner_id,'owner');
 assert.equal(failed.last_error,'remote_unverified_check_connector');
 for(const ob of [enrollment,failed]) {
  assert.equal(ob.owner_id,'owner');assert.equal(ob.next_due_at,Date.parse('2026-03-09T13:00:00Z'),'Monday 09:00 follows the weekend and DST shift');
  assert.equal(ob.deadline_at,Date.parse('2026-03-11T13:00:00Z'),'the declared Tuesday holiday moves the deadline to Wednesday');
 }
 await admin('organizations/cancel-invitation',{email:'cancelled@example.com'});
 const originals=new Set(before.obligations.map(o=>o.id));
 const pages=[],seen=new Set();let cursor='';
 do {
  const page=await (await r.call('/api/auth/followup?historyLimit=2'+(cursor?'&historyCursor='+encodeURIComponent(cursor):''),{cookie:r.owner.cookie})).json();
  for(const event of page.history){assert.ok(!seen.has(event.id),'history cursors never duplicate a stored event');seen.add(event.id);pages.push(event);}
  assert.equal(page.historyPage.hasMore,Boolean(page.historyPage.nextCursor));cursor=page.historyPage.nextCursor;
 }while(cursor);
 assert.deepEqual(new Set(pages.map(h=>h.id)),new Set((await read()).history.map(h=>h.id)),'every retained event is accessible through public cursor pages');
 assert.equal((await r.call('/api/auth/followup?historyCursor=invalid',{cookie:r.owner.cookie})).status,400);
 await r.restart();
 const restarted=await read();assert.deepEqual(new Set(restarted.obligations.map(o=>o.id)),originals,'actual Worker and SQLite restart preserves the same obligation records');
 r.now=Date.parse('2026-03-09T12:59:00Z');let count=(await r.mails()).length;
 await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count,'scheduler does not dispatch early');
 r.now+=60000;await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 let reminders=(await r.mails()).slice(count);assert.equal(reminders.length,3,'only the open enrollment, recovery and refused deprovision dispatch');
 assert.ok(reminders.every(m=>m.to.length===1&&m.to[0]==='owner@example.com'));assert.ok(reminders.every(m=>m.subject==='Auth follow-up is due'));
 assert.equal(remote().active,true,'mail delivery never verifies the refused remote change');
 await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count+3,'the persisted due claim prevents a second dispatch');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const monday=await read();assert.equal(monday.obligations.find(o=>o.person_id===cancelled.id).state,'cancelled');assert.equal(monday.obligations.find(o=>o.person_id===expiring.id).state,'expired');
 assert.equal(monday.obligations.find(o=>o.id===failed.id).state,'open');
 assert.equal(monday.obligations.find(o=>o.id===failed.id).next_due_at,Date.parse('2026-03-11T13:00:00Z'));
 // Source doors stop work; a reminder has no completion/cancellation shortcut.
 const newcomer=await register(r,await emailSession(r,'newhire@example.com'));
 assert.ok(newcomer.key);const cancellation=await r.call('/api/auth/recovery/cancel',{method:'POST',cookie:await emailSession(r,'ada@example.com'),data:{id:recoveryId}});assert.equal(cancellation.status,200);
 const stopped=await read();assert.equal(stopped.obligations.find(o=>o.id===enrollment.id).state,'completed');assert.equal(stopped.obligations.find(o=>o.kind==='recovery').state,'cancelled');
 // A weekend/DST-spanning escalation remains due until the actual SCIM retry
 // reads back the denied account. The real development outbox is the mail edge.
 r.now=Date.parse('2026-03-10T13:00:00Z');count=(await r.mails()).length;await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count,'holiday emits no reminder');
 r.now=Date.parse('2026-03-11T13:00:00Z');await r.restart();await r.call('/',{action:'maintain'});reminders=(await r.mails()).slice(count);assert.equal(reminders.length,1);assert.equal(reminders[0].subject,'Auth follow-up deadline reached');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');scim.faults.length=0;await admin('provisioning/retry',{appId:app.id});assert.equal(remote().active,false);
 let done=await read();assert.equal(done.obligations.find(o=>o.id===failed.id).state,'completed');
 const history=done.history.filter(h=>h.obligation_id===failed.id);assert.ok(history.some(h=>h.event==='reminder_accepted'));assert.ok(history.some(h=>h.event==='escalation_accepted'));assert.ok(history.some(h=>h.event==='completed'));
 r.now=Date.parse('2026-03-12T13:00:00Z');count=(await r.mails()).length;await r.restart();await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count,'completed, cancelled and expired sources remain silent after another restart');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');done=await read();assert.deepEqual(done.history.filter(h=>h.obligation_id===failed.id),history,'all follow-up history survives stop and restart');
 await admin('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const preview=await admin('erasure/preview',{kind:'person',target:enrollment.person_id});
 await admin('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',confirmRemoteDeletion:false,destinations:[]});
 const anonymous=await read(),retained=anonymous.obligations.find(ob=>ob.id===enrollment.id);
 assert.equal(retained.state,'completed');assert.equal(retained.person_id,null);assert.notEqual(retained.source_id,enrollment.source_id);
 assert.ok(anonymous.history.some(h=>h.obligation_id===enrollment.id&&h.event==='completed'),'anonymous source history remains after person erasure');
 assert.ok(!JSON.stringify(anonymous).includes(enrollment.person_id),'erasure removes personal references from follow-up records');

}
