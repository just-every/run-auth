import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {openRuntime,emailSession} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
import {register} from './webauthn.mjs';
import {scimServer} from './scim-server.mjs';
export async function followupFlow(t) {
 await followupSafety(t);
 await legacyFollowup(t);
 const r=await openRuntime();t.after(()=>r.close());r.realOutbox=true;r.now=Date.parse('2026-03-06T23:55:00Z');
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
 const recoveringOb=before.obligations.find(o=>o.kind==='recovery');assert.equal(recoveringOb.owner_id,'ada');assert.equal(recoveringOb.next_action,'wait_or_request_distinct_admin_approval');assert.equal(recoveringOb.state,'open');
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
 const restarted=await read();assert.equal(restarted.obligations.find(o=>o.id===recoveringOb.id).next_action,'wait_or_request_distinct_admin_approval','missing distinct administrator approval remains actionable after restart');assert.deepEqual(new Set(restarted.obligations.map(o=>o.id)),originals,'actual Worker and SQLite restart preserves the same obligation records');
 // The connector remains unavailable into Saturday. Escalation is due at
 // exactly fifteen minutes, outside the employer's business reminder window.
 const eventAt=r.now;let count=(await r.mails()).length;
 r.now=eventAt+899999;await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count,'unverified downstream escalation never fires early');
 r.now=eventAt+900000;await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 let urgent=(await r.mails()).slice(count);assert.equal(urgent.length,1);assert.equal(urgent[0].subject,'Auth downstream access unverified after 15 minutes');assert.deepEqual(urgent[0].to,['owner@example.com']);assert.equal(remote().active,true);
 await r.restart();await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count+1,'timing escalation is durable and not duplicated after restart');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const escalated=await read(),timing=escalated.history.find(h=>h.obligation_id===failed.id&&h.event==='timing_escalated');assert.equal(timing.created_at,eventAt+900000);assert.equal(escalated.obligations.find(o=>o.id===failed.id).state,'open');
 r.now=Date.parse('2026-03-09T12:59:00Z');count=(await r.mails()).length;
 await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count,'scheduler does not dispatch early');
 r.now+=60000;await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 let reminders=(await r.mails()).slice(count);assert.equal(reminders.length,3,'only the open enrollment, recovery and refused deprovision dispatch');
 assert.ok(reminders.every(m=>m.to.length===1&&m.to[0]==='owner@example.com'));assert.ok(reminders.every(m=>m.subject==='Auth follow-up is due'));
 assert.equal(remote().active,true,'mail delivery never verifies the refused remote change');
 await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,count+3,'the persisted due claim prevents a second dispatch');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const monday=await read();assert.equal(monday.obligations.find(o=>o.id===recoveringOb.id).next_action,'wait_or_request_distinct_admin_approval','distinct approval stays visible across the weekend and DST change');assert.equal(monday.obligations.find(o=>o.person_id===cancelled.id).state,'cancelled');assert.equal(monday.obligations.find(o=>o.person_id===expiring.id).state,'expired');
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

// These probes use the same public policy/source/cron doors. The scripted mail
// transport is the network edge; no hook changes the scheduler's decisions.
async function followupSafety(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-02T08:00:00Z');
 r.owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 const admin=async(path,data,status=200)=>{const response=await r.call('/api/auth/'+path,{method:'POST',cookie:r.owner.cookie,data});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const read=async()=>{const response=await r.call('/api/auth/followup',{cookie:r.owner.cookie});assert.equal(response.status,200);return response.json();};
 const settings={confirm:true,enabled:true,calendar:{timezone:'UTC',weekdays:[1,2,3,4,5],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:5,recipients:['first'],escalationRecipients:['owner'],escalation:'repeat_until_resolved'};
 for(const id of ['first','second'])await passkeyPerson(r,id,id+'@example.com','admin');
 const scoped={view:{groups:['*']},edit:{groups:['*']}};
 for(const roleId of ['help-desk','manager']) {
  const who=await passkeyPerson(r,roleId,roleId+'@example.com','member');
  const preview=await admin('roles/preview',{kind:'grant',personId:roleId,roleId,resources:scoped});await admin('roles/apply',{previewId:preview.previewId});
  const before=await read();
  assert.equal((await r.call('/api/auth/followup/settings',{method:'POST',cookie:who.cookie,data:settings})).status,403,roleId+' cannot authorize reminders');
  assert.deepEqual((await read()).policy,before.policy);
 }
 r.now+=11*60000;await admin('followup/settings',settings,403);
 assert.equal((await read()).policy.enabled,false,'stale email proof cannot save consent');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const isolated=await admin('organizations/create',{name:'Independent reminder employer'},201);
 const org={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+isolated.id+path,options)};
 const orgOwner=await register(org,await emailSession(org,'owner@example.com'));
 const installationAdmin=await passkeyPerson(r,'installation-admin','installation@example.com','admin');
 for(const cookie of [r.owner.cookie,installationAdmin.cookie]) {
  assert.ok([401,403].includes((await org.call('/api/auth/followup/settings',{method:'POST',cookie,data:settings})).status),'installation roles cannot write isolated employer policy');
 }
 const local=await org.call('/api/auth/followup',{cookie:orgOwner.cookie});assert.equal(local.status,200);assert.equal((await local.json()).policy.enabled,false);
 await admin('organizations/invite',{email:'silent@example.com'},201);
 r.now=Date.parse('2026-03-03T09:00:00Z');let count=(await r.mails()).length;
 await r.call('/',{action:'maintain'});
 assert.equal((await r.mails()).length,count,'without a saved policy the due obligation sends no mail');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 assert.ok((await read()).obligations.some(o=>o.state==='open'),'without a saved policy work stays visible');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');await admin('organizations/cancel-invitation',{email:'silent@example.com'});
 for(const escalation of ['repeat_until_resolved','stop_at_deadline'])await admin('followup/settings',{...settings,escalation,escalationRecipients:[]},400);
 assert.equal((await read()).policy.enabled,false,'enabling any schedule requires an approved fallback for failed recipient rechecks');
 await admin('followup/settings',settings);await admin('organizations/invite',{email:'pending@example.com'},201);
 const obligation=(await read()).obligations.find(o=>o.state==='open');assert.ok(obligation);
 await admin('people/role',{personId:'first',role:'member'});
 r.now=Date.parse('2026-03-04T09:00:00Z');count=(await r.mails()).length;await r.call('/',{action:'maintain'});
 let sent=(await r.mails()).slice(count);
 assert.deepEqual(sent.map(m=>m.to),['owner@example.com'],'a removed recipient role escalates immediately, before the deadline');
 assert.equal(sent[0].subject,'Auth follow-up recipient unavailable');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');await admin('people/role',{personId:'first',role:'admin'});
 await admin('followup/settings',{...settings,recipients:['first','second']});
 const transported=[];let handle=async(message,response)=>{if(message.subject.startsWith('Auth follow-up'))transported.push(message);if(message.to==='first@example.com')await admin('people/suspend',{personId:'second'});response.end('accepted');};
 const server=createServer(async(request,response)=>{try{let body='';for await(const chunk of request)body+=chunk;await handle(JSON.parse(body),response);}catch(error){response.statusCode=500;response.end(String(error));}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 r.mailEdge='http://127.0.0.1:'+server.address().port;
 r.now=Date.parse('2026-03-05T09:00:00Z');r.owner=await signInAgain(r,r.owner,'owner@example.com');
 await r.call('/',{action:'maintain'});
 assert.deepEqual(transported.map(m=>m.to),['first@example.com','owner@example.com'],'suspension between sends refuses the suspended recipient and escalates');
 const history=(await read()).history.filter(h=>h.obligation_id===obligation.id);
 assert.ok(history.some(h=>h.event==='recipient_recheck_failed'&&h.recipient_id==='second'));
 assert.ok(history.some(h=>h.event==='escalation_accepted'&&h.recipient_id==='owner'));
 // The transport has accepted the next reminder, but never returns its ACK.
 // Dispose the actual Worker before the schedule advances, then restart it.
 await admin('followup/settings',settings);
 let accepted;const arrived=new Promise(resolve=>{accepted=resolve;});
 handle=async(message,response)=>{if(!message.subject.startsWith('Auth follow-up')){response.end('accepted');return;}transported.push(message);accepted();};
 r.now=Date.parse('2026-03-06T09:00:00Z');r.owner=await signInAgain(r,r.owner,'owner@example.com');const due=(await read()).obligations.find(o=>o.id===obligation.id).next_due_at;
 const interrupted=r.call('/',{action:'maintain'}).catch(()=>null);await arrived;
 await r.restart();await interrupted;
 const beforeRetry=transported.length;
 handle=async(message,response)=>{if(message.subject.startsWith('Auth follow-up'))transported.push(message);response.end('accepted');};
 r.now+=120001;await r.call('/',{action:'maintain'});
 assert.equal(transported.length,beforeRetry,'restart after the claim lease must not resend the uncertain scheduled delivery');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const after=await read(),attempts=after.history.filter(h=>h.obligation_id===obligation.id&&h.created_at>=due);
 assert.equal(attempts.filter(h=>h.recipient_id==='first').length,1);
 assert.equal(attempts.find(h=>h.recipient_id==='first').event,'reminder_dispatching','uncertain transport result never becomes accepted');
 assert.equal(after.obligations.find(o=>o.id===obligation.id).state,'open');
 for(const message of transported) {
  assert.doesNotMatch(JSON.stringify(message),/pending@example.com|synthetic-auth-|authprep_|client_assertion|access_token|[?&]token=|[?&]code=/i,'follow-up mail contains no source contact or credential');
  const urls=message.text.match(/https?:\/\/\S+/g);assert.deepEqual(urls,[r.origin+'/app/activity']);
 }
}

// Arrange an actual persisted pre-check policy, then enter only the current
// read/admin/cron doors. No new recipient consent is inferred during upgrade.
async function legacyFollowup(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-02T08:00:00Z');
 r.owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 await passkeyPerson(r,'former','former@example.com','admin');
 const admin=async(path,data)=>{const response=await r.call('/api/auth/'+path,{method:'POST',cookie:r.owner.cookie,data});assert.equal(response.status,200,await response.clone().text());return response.json();};
 const settings={enabled:true,calendar:{timezone:'UTC',weekdays:[1,2,3,4,5],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:5,recipients:['former','owner'],escalationRecipients:[],escalation:'stop_at_deadline'};
 await r.db.prepare('INSERT INTO auth_followup_settings(id,policy,updated_by,updated_at) VALUES(1,?,?,?)').bind(JSON.stringify(settings),'owner',r.now).run();
 const invited=await r.call('/api/auth/organizations/invite',{method:'POST',cookie:r.owner.cookie,data:{email:'legacy@example.com'}});assert.equal(invited.status,201);
 // Persist the old shape after the source exists, as an upgraded installation
 // would contain it before its first current-runtime read or cron.
 await r.db.prepare('UPDATE auth_followup_settings SET policy=? WHERE id=1').bind(JSON.stringify(settings)).run();
 await admin('people/role',{personId:'former',role:'member'});
 await r.restart();r.now=Date.parse('2026-03-03T09:00:00Z');const count=(await r.mails()).length;
 await r.call('/',{action:'maintain'});
 const sent=(await r.mails()).slice(count);assert.equal(sent.filter(m=>m.subject==='Auth follow-up recipient unavailable').length,1,'a legacy policy escalates failed recheck to its already approved active owner');assert.ok(sent.every(m=>m.to==='owner@example.com'),'migration never adds or mails an unapproved recipient');
 r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const result=await(await r.call('/api/auth/followup',{cookie:r.owner.cookie})).json();
 assert.deepEqual(result.policy.escalationRecipients,settings.recipients);
 assert.ok(result.history.some(h=>h.event==='recipient_recheck_failed'&&h.recipient_id==='former'));
 assert.ok(result.history.some(h=>h.event==='escalation_accepted'&&h.recipient_id==='owner'));
 assert.equal(result.obligations[0].state,'open','an escalation does not accept the invitation');
 // A legacy policy may have already stopped at its deadline. Its upgrade must
 // not strand the unresolved record behind reminders_stopped_at.
 r.now+=60000;
 await r.db.prepare('UPDATE auth_followup_settings SET policy=? WHERE id=1').bind(JSON.stringify(settings)).run();
 await r.db.prepare("UPDATE auth_obligations SET deadline_at=?,reminders_stopped_at=?,next_due_at=? WHERE state='open'").bind(r.now,r.now,r.now+86400000).run();
 const atDeadline=(await r.mails()).length;await r.restart();await r.call('/',{action:'maintain'});
 const deadlineMail=(await r.mails()).slice(atDeadline);assert.deepEqual(deadlineMail.map(m=>[m.to,m.subject]),[['owner@example.com','Auth follow-up deadline reached']]);
 const migrated=await(await r.call('/api/auth/followup',{cookie:r.owner.cookie})).json();assert.equal(migrated.obligations[0].state,'open');assert.ok(migrated.obligations[0].reminders_stopped_at);
 // The Activity read is the public audit door used by this slice.
 const activity=await r.call('/api/auth/activity',{cookie:r.owner.cookie});
 assert.equal(activity.status,200);assert.match(await activity.text(),/followup_legacy_policy_migrated/);

 r.owner=await signInAgain(r,r.owner,'owner@example.com');await admin('organizations/cancel-invitation',{email:'legacy@example.com'});
 r.now=Date.parse('2026-03-04T09:00:00Z');const stopped=(await r.mails()).length;await r.restart();await r.call('/',{action:'maintain'});assert.equal((await r.mails()).length,stopped);
}
