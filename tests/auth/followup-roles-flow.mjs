import assert from 'node:assert/strict';
import {openRuntime,emailSession} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';

export async function followupRolesFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-02T08:00:00Z');r.realOutbox=true;
 let owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 const manager=await passkeyPerson(r,'manager','manager@example.com','member');
 const desk=await passkeyPerson(r,'desk','desk@example.com','member');
 const post=async(who,path,data,status=200)=>{const response=await r.call('/api/auth/'+path,{method:'POST',cookie:who.cookie??who,data});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 await post(owner,'people/invite',{email:'employee@example.com',name:'Employee'},201);
 const employee=await emailSession(r,'employee@example.com'),employeeId=(await(await r.call('/api/auth/me',{cookie:employee})).json()).user.id;
 const read=async(who)=>{const response=await r.call('/api/auth/followup',{cookie:who.cookie??who});assert.equal(response.status,200,await response.clone().text());return response.json();};
 const change=async data=>{const preview=await post(owner,'roles/preview',data);return post(owner,'roles/apply',{previewId:preview.previewId});};
 const definition={id:'followup-manager',name:'Follow-up manager',rank:15,permissions:['roles.view','followup.manage']};
 await change({kind:'role',role:definition});
 const grant=await change({kind:'grant',personId:'manager',roleId:definition.id,resources:{view:{},edit:{}}});
 const catalogue=await(await r.call('/api/auth/roles',{cookie:manager.cookie})).json();assert.equal(catalogue.permissions['followup.manage'],'Manage follow-up');
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
 await post(manager,'followup/send',{id:caseOb.id},403);
 await post(employee,'followup/send',{id:caseOb.id},403);
 await r.restart();await post(desk,'followup/send',{id:caseOb.id});assert.equal((await r.mails()).length,before+1,'early occurrence attempts survive a process restart');
 const earlyHistory=(await read(desk)).history;assert.ok(earlyHistory.some(h=>h.event==='early_send_requested'&&h.actor_id==='desk'));
 owner=await signInAgain(r,owner,'owner@example.com');
 await post(owner,'followup/schedule',{id:caseOb.id,ownerId:'owner',dueBusinessDays:2,deadlineBusinessDays:5});
 await change({kind:'revoke',grantId:caseGrant.plan.id});
 await post(desk,'followup/send',{id:caseOb.id},403);
 const count=(await r.mails()).length;await post(owner,'followup/send',{id:caseOb.id});
 sent=(await r.mails()).slice(count);assert.equal(sent.length,1);assert.deepEqual(sent[0].to,['owner@example.com']);assert.equal(sent[0].subject,'Auth follow-up recipient unavailable');
 assert.ok((await read(owner)).history.some(h=>h.obligation_id===caseOb.id&&h.event==='recipient_recheck_failed'&&h.recipient_id==='desk'));
 // A registered employee's recovery reminder targets that employee, even
 // when the follow-up is assigned to an administrator.
 let recovering=await passkeyPerson(r,'recovering','recovering@example.com','member');
 const recovery=await post(recovering,'recovery/start',{},201);
 const recoveryOb=(await read(recovering)).obligations.find(ob=>ob.source_id===recovery.id);assert.ok(recoveryOb);
 await post(owner,'followup/schedule',{id:recoveryOb.id,ownerId:'owner',dueBusinessDays:1,deadlineBusinessDays:5});
 const pendingCount=(await r.mails()).length;await post(recovering,'followup/send',{id:recoveryOb.id});
 assert.deepEqual((await r.mails()).slice(pendingCount).map(m=>m.to),[['recovering@example.com']]);
 await change({kind:'revoke',grantId:grant.plan.id});
 await post(manager,'followup/settings',settings,403);
 // Due cron resolves invited and active employees through the same role
 // dispatch as early-send, rechecks revoked cases and never resends early mail.
 r.now=Date.parse('2026-03-03T09:00:00Z');const dueCount=(await r.mails()).length;
 await r.call('/',{action:'maintain'});
 sent=(await r.mails()).slice(dueCount);
 assert.ok(sent.some(m=>m.to.includes('invited@example.com')));
 assert.ok(sent.some(m=>m.to.includes('employee@example.com')));
 assert.ok(!sent.some(m=>m.to.includes('desk@example.com')));
 assert.ok(!sent.some(m=>m.to.includes('recovering@example.com')),'the due occurrence sent early is not sent again by cron');
 recovering=await signInAgain(r,recovering,'recovering@example.com');
 await post(recovering,'recovery/cancel',{id:recovery.id});
 const afterCancel=(await read(recovering)).obligations.find(ob=>ob.id===recoveryOb.id);assert.equal(afterCancel.state,'cancelled');
 await post(recovering,'followup/send',{id:recoveryOb.id},404);
 assert.ok((await read(recovering)).obligations.every(ob=>ob.person_id==='recovering'));
 // An existing installation membership does not become an employer role.
 owner=await signInAgain(r,owner,'owner@example.com');
 const isolated=await post(owner,'organizations/create',{name:'Isolated follow-up employer'},201);
 const forbidden=await r.call('/org/'+isolated.id+'/api/auth/followup/settings',{method:'POST',cookie:manager.cookie,data:settings});assert.ok([401,403].includes(forbidden.status));
}
