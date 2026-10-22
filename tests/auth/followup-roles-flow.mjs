import assert from 'node:assert/strict';
import {openRuntime,emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';

export async function followupRolesFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-02T08:00:00Z');r.realOutbox=true;
 let owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 let manager=await passkeyPerson(r,'manager','manager@example.com','member');
 let desk=await passkeyPerson(r,'desk','desk@example.com','member');
 const post=async(who,path,data,status=200)=>{const response=await r.call('/api/auth/'+path,{method:'POST',cookie:who.cookie??who,data});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const refused=async(who,path,data,error)=>assert.equal((await post(who,path,data,403)).error,error,path);
 await post(owner,'people/invite',{email:'employee@example.com',name:'Employee'},201);
 const employee=await emailSession(r,'employee@example.com'),employeeId=(await(await r.call('/api/auth/me',{cookie:employee})).json()).user.id;
 const read=async(who)=>{const response=await r.call('/api/auth/followup',{cookie:who.cookie??who});assert.equal(response.status,200,await response.clone().text());return response.json();};
 const change=async data=>{const preview=await post(owner,'roles/preview',data);return post(owner,'roles/apply',{previewId:preview.previewId});};
 const definition={id:'followup-manager',name:'Follow-up manager',rank:15,permissions:['roles.view','followup.manage']};
 await change({kind:'role',role:definition});
 const grant=await change({kind:'grant',personId:'manager',roleId:definition.id,resources:{view:{},edit:{}}});
 const catalogue=await(await r.call('/api/auth/roles',{cookie:manager.cookie})).json();assert.ok(Object.hasOwn(catalogue.permissions,'followup.manage'));
 const settings={confirm:true,enabled:true,calendar:{timezone:'UTC',weekdays:[1,2,3,4,5],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:5,recipients:['employee','help_desk'],escalationRecipients:['owner'],escalation:'repeat_until_resolved'};
 await post(manager,'followup/settings',{...settings,recipients:['outside@example.com']},400);
 await post(manager,'followup/settings',settings);
 assert.equal((await read(manager)).canManage,true);
 assert.equal((await read(employee)).canManage,false);
 // Both invitation and active, email-only enrollment resolve the subject,
 // never the manager, unrelated employee or an injected address.
 await post(owner,'organizations/invite',{email:'invited@example.com'},201);
 const invited=(await read(owner)).obligations.find(ob=>ob.kind==='enrollment'&&ob.person_id!==employeeId);assert.ok(invited);
 const opening=await change({kind:'grant',personId:'desk',roleId:'help-desk',resources:{view:{people:[employeeId]},edit:{people:[employeeId]}}});
 const review=await post(desk,'roles/recovery-case',{action:'open',personId:employeeId,reason:'Verify recovery for the employee'},201);
 assert.ok(!(await read(desk)).obligations.some(ob=>ob.case_id===review.caseId),'people scope alone never grants case custody');
 const caseGrant=await change({kind:'grant',personId:'desk',roleId:'help-desk',resources:{view:{cases:[review.caseId]},edit:{cases:[review.caseId]}}});
 const caseOb=(await read(desk)).obligations.find(ob=>ob.case_id===review.caseId);assert.ok(caseOb);
 const before=(await r.mails()).length;
 await post(desk,'followup/send',{id:caseOb.id,recipients:['outside@example.com']});
 let sent=(await r.mails()).slice(before);assert.equal(sent.length,1);assert.deepEqual(sent[0].to,['desk@example.com']);
 await refused(manager,'followup/send',{id:caseOb.id},'followup_holder_required');
 await refused(employee,'followup/send',{id:caseOb.id},'followup_holder_required');
 await r.restart();await post(desk,'followup/send',{id:caseOb.id});assert.equal((await r.mails()).length,before+1,'early occurrence attempts survive a process restart');
 const earlyHistory=(await read(desk)).history;assert.ok(earlyHistory.some(h=>h.event==='early_send_requested'&&h.actor_id==='desk'));
 // A registered employee's recovery reminder targets that employee, even
 // when the follow-up is assigned to an administrator.
 let recovering=await passkeyPerson(r,'recovering','recovering@example.com','member');
 const recovery=await post(recovering,'recovery/start',{},201);
 const recoveryOb=(await read(recovering)).obligations.find(ob=>ob.source_id===recovery.id);assert.ok(recoveryOb);
 owner=await signInAgain(r,owner,'owner@example.com');
 await post(owner,'followup/schedule',{id:recoveryOb.id,ownerId:'owner',dueBusinessDays:1,deadlineBusinessDays:5});
 const pendingCount=(await r.mails()).length;await post(recovering,'followup/send',{id:recoveryOb.id});
 assert.deepEqual((await r.mails()).slice(pendingCount).map(m=>m.to),[['recovering@example.com']]);
 // Due cron resolves the same role recipients as early send. The first due
 // occurrence was sent early and is not sent again; the next business day's
 // scheduled reminder reaches the current case holder and the employee.
 r.now=Date.parse('2026-03-03T09:00:00Z');let dueCount=(await r.mails()).length;
 await r.call('/',{action:'maintain'});
 sent=(await r.mails()).slice(dueCount);
 assert.ok(sent.some(m=>m.to.includes('invited@example.com')));
 assert.ok(sent.some(m=>m.to.includes('employee@example.com')));
 assert.ok(!sent.some(m=>m.to.includes('desk@example.com')),'the case occurrence sent early is not sent again by cron');
 assert.ok(!sent.some(m=>m.to.includes('recovering@example.com')),'the due occurrence sent early is not sent again by cron');
 r.now=Date.parse('2026-03-04T09:00:00Z');dueCount=(await r.mails()).length;
 await r.call('/',{action:'maintain'});
 sent=(await r.mails()).slice(dueCount);
 const scheduled=(address,id)=>sent.filter(m=>m.to.includes(address)&&m.subject==='Auth follow-up is due'&&m.text.includes('Reference: '+id)).length;
 assert.equal(scheduled('desk@example.com',caseOb.id),1,'the holding help desk receives its scheduled case reminder');
 assert.equal(scheduled('recovering@example.com',recoveryOb.id),1,'the employee receives their own scheduled recovery reminder');
 assert.equal(scheduled('invited@example.com',invited.id),1,'the invited employee receives their own scheduled enrollment reminder');
 assert.ok(!sent.some(m=>m.to.includes('owner@example.com')||m.to.includes('manager@example.com')),'role reminders never fan out to administrators or policy managers');
 // The holder loses exact case authority: the next dispatch rechecks them,
 // sends them nothing and escalates to the policy's named owner.
 owner=await signInAgain(r,owner,'owner@example.com');desk=await signInAgain(r,desk,'desk@example.com');
 await post(owner,'followup/schedule',{id:caseOb.id,ownerId:'owner',dueBusinessDays:2,deadlineBusinessDays:5});
 await change({kind:'revoke',grantId:caseGrant.plan.id});
 await refused(desk,'followup/send',{id:caseOb.id},'followup_holder_required');
 const count=(await r.mails()).length;await post(owner,'followup/send',{id:caseOb.id});
 sent=(await r.mails()).slice(count);assert.equal(sent.length,1);assert.deepEqual(sent[0].to,['owner@example.com']);assert.equal(sent[0].subject,'Auth follow-up recipient unavailable');
 assert.ok((await read(owner)).history.some(h=>h.obligation_id===caseOb.id&&h.event==='recipient_recheck_failed'&&h.recipient_id==='desk'));
 recovering=await signInAgain(r,recovering,'recovering@example.com');
 await post(recovering,'recovery/cancel',{id:recovery.id});
 const afterCancel=(await read(recovering)).obligations.find(ob=>ob.id===recoveryOb.id);assert.equal(afterCancel.state,'cancelled');
 await post(recovering,'followup/send',{id:recoveryOb.id},404);
 assert.ok((await read(recovering)).obligations.every(ob=>ob.person_id==='recovering'));
 // An installation role confers nothing in an isolated employer: no
 // employer session, and no authority for the same person as its member.
 manager=await signInAgain(r,manager,'manager@example.com');
 const isolated=await post(owner,'organizations/create',{name:'Isolated follow-up employer'},201);
 const forbidden=await r.call('/org/'+isolated.id+'/api/auth/followup/settings',{method:'POST',cookie:manager.cookie,data:settings});assert.equal(forbidden.status,401,'an installation session is not an employer session');
 const org={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+isolated.id+path,options)};
 const orgOwner=await register(org,await emailSession(org,'owner@example.com'));
 const registry=await r.db.prepare('SELECT namespace FROM auth_organizations WHERE id=?').bind(isolated.id).first();
 // Persist the pre-0048 employer shape. Its next public request must obtain
 // the current case binding store without requiring a column migration in
 // every already existing employer table.
 const columns=(await r.db.prepare('PRAGMA table_info('+registry.namespace+'auth_obligations)').all()).results;
 if(columns.some(column=>column.name==='case_id'))await r.db.exec('ALTER TABLE '+registry.namespace+'auth_obligations DROP COLUMN case_id');
 await r.db.exec('DROP TABLE IF EXISTS '+registry.namespace+'auth_followup_cases');
 const upgraded=await org.call('/api/auth/followup',{cookie:orgOwner.cookie});assert.equal(upgraded.status,200,'an existing employer upgrades through its normal follow-up door');
 const localPost=async(path,data,status=200)=>{const response=await org.call('/api/auth/'+path,{method:'POST',cookie:orgOwner.cookie,data});assert.equal(response.status,status,await response.clone().text());return response.json();};
 await localPost('organizations/invite',{email:'manager@example.com',name:'Manager'},201);
 const orgManager=await register(org,await emailSession(org,'manager@example.com'));
 const memberWrite=await org.call('/api/auth/followup/settings',{method:'POST',cookie:orgManager.cookie,data:settings});
 assert.equal(memberWrite.status,403);assert.equal((await memberWrite.json()).error,'role_permission_required','the installation follow-up role is not an employer role');
 assert.equal((await(await org.call('/api/auth/followup',{cookie:orgManager.cookie})).json()).canManage,false);
 await localPost('people/invite',{email:'local-employee@example.com'},201);
 const localEmployee=(await(await org.call('/api/auth/me',{cookie:await emailSession(org,'local-employee@example.com')})).json()).user.id;
 const localCase=await localPost('roles/recovery-case',{action:'open',personId:localEmployee,reason:'Employer-local recovery review'},201);
 const localOwnerId=(await(await org.call('/api/auth/me',{cookie:orgOwner.cookie})).json()).user.id;
 await localPost('followup/settings',{...settings,recipients:['help_desk'],escalationRecipients:[localOwnerId]});
 const localRecords=await(await org.call('/api/auth/followup',{cookie:orgOwner.cookie})).json(),localOb=localRecords.obligations.find(ob=>ob.case_id===localCase.caseId);assert.ok(localOb);
 const localCount=(await org.mails()).length;await localPost('followup/send',{id:localOb.id});
 const localMail=(await org.mails()).slice(localCount);assert.equal(localMail.length,1);assert.ok(localMail[0].text.includes('/org/'+isolated.id+'/app/activity'));
 await localPost('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const erase=await localPost('erasure/preview',{kind:'person',target:localEmployee});
 await localPost('erasure/confirm',{previewId:erase.id,confirmation:'ERASE',confirmRemoteDeletion:false,destinations:[]});
 const retained=await(await org.call('/api/auth/followup',{cookie:orgOwner.cookie})).json();
 assert.ok(!JSON.stringify(retained).includes(localEmployee)&&!JSON.stringify(retained).includes(localCase.caseId),'erasure removes subject and case binding while keeping anonymous history');
 assert.ok(retained.history.some(event=>event.obligation_id===localOb.id&&event.event==='reminder_accepted'));
 // Revoking the custom role ends the installation policy write.
 await change({kind:'revoke',grantId:grant.plan.id});
 await refused(manager,'followup/settings',settings,'role_permission_required');
}
