import assert from 'node:assert/strict';
import {expect} from '@playwright/test';

// All setup uses human public doors; mail is inspected at the gated outbox edge.
export async function followupRolesJourney(options) {
 for(const [width,fixtureBase] of [[1440,200],[390,300]]) {
  const capture=async(name,target,prepare)=>{
   await options.shoot(`${name}-actions-${width}`,target,prepare);
   await target.setViewportSize({width,height:1000});
  };
  await followupRolesAtWidth({...options,shoot:capture,width,fixtureBase});
 }
}

async function followupRolesAtWidth({app,browser,owner,page,shoot,width,fixtureBase}) {
 const contexts=[];
 const post=(context,path,data)=>context.request.post(app.origin+'/api/auth/'+path,{data,headers:{origin:app.origin}});
 const body=async(response,status=200)=>{
  assert.equal(response.status(),status,`public response status ${response.status()} expected ${status}`);
  return response.json();
 };
 const email=async(context,address)=>{
  assert.equal((await context.request.post(app.origin+'/auth/identity/email/request',{data:{email:address},headers:{origin:app.origin}})).status(),202);
  assert.equal((await context.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:(await app.link()).searchParams.get('token')},headers:{origin:app.origin}})).status(),200);
 };
 const person=async(n,hardware=true)=>{
  const address=`synthetic-auth-${fixtureBase+n}@example.com`;
  await body(await post(owner,'people/invite',{email:address,name:({1:'Jordan Rivera',2:'Morgan Chen',3:'Taylor Kim',5:'Casey Patel'})[n] ?? 'Northwind employee'}),201);
  const context=await browser.newContext({viewport:{width,height:1000}});contexts.push(context);
  const mine=await context.newPage();mine.on('dialog',dialog=>dialog.accept());
  await email(context,address);
  if(hardware) {
   const cdp=await context.newCDPSession(mine);await cdp.send('WebAuthn.enable');
   await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
   await mine.goto(app.origin+'/app/methods');
   const registered=mine.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify')),reloaded=mine.waitForEvent('load');
   await mine.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);
   await reloaded;
  }
  const me=await body(await context.request.get(app.origin+'/api/auth/me'));
  return {context,page:mine,id:me.user.id,address};
 };
 const change=async data=>{
  const preview=await body(await post(owner,'roles/preview',data));
  return body(await post(owner,'roles/apply',{previewId:preview.previewId}));
 };
 const read=async context=>body(await context.request.get(app.origin+'/api/auth/followup'));
 const outbox=async()=>{
  const response=await app.get('/__dev/outbox',{'x-rer-dev-key':app.vars.RER_DEV_KEY});assert.equal(response.status,200);
  const html=await response.text();return [...html.matchAll(/href="(\/__dev\/outbox\?message=[^"]+)"/g)].map(match=>match[1].replaceAll('&amp;','&'));
 };
 const mailSince=async(before,{address,reference})=>{
  const paths=(await outbox()).filter(path=>!before.has(path));assert.ok(paths.length,'early send creates an outbox message');
  const details=await Promise.all(paths.map(async path=>{
   const response=await app.get(path,{'x-rer-dev-key':app.vars.RER_DEV_KEY});assert.equal(response.status,200);return response.text();
  }));
  assert.ok(details.some(html=>html.includes(`<p>To: ${address}</p>`)&&html.includes(reference)),'intended recipient receives this obligation reference');
  return details;
 };
 const early=async(who,id)=>{
  await who.page.goto(app.origin+'/app/account');
  const card=who.page.locator(`[data-followup-id="${id}"]`);
  await expect(card).toBeVisible();await expect(card.getByRole('button',{name:'Send reminder early',exact:true})).toBeVisible();
  const before=new Set(await outbox()),sent=who.page.waitForResponse(response=>response.url().endsWith('/api/auth/followup/send'));
  await card.getByRole('button',{name:'Send reminder early',exact:true}).click();assert.equal((await sent).status(),200);
  return before;
 };
 try {
  await page.setViewportSize({width,height:1000});
  await email(owner,app.vars.OWNER_EMAIL);
  const ownerId=(await body(await owner.request.get(app.origin+'/api/auth/me'))).user.id;
  const manager=await person(1),helpdesk=await person(2),employee=await person(3,false);
  const roleId=`synthetic-auth-${fixtureBase+4}`;
  await change({kind:'role',role:{id:roleId,name:'Follow-up coordinator',rank:15,permissions:['roles.view','followup.manage']}});
  await change({kind:'grant',personId:manager.id,roleId,resources:{view:{},edit:{}}});
  const catalogue=await body(await manager.context.request.get(app.origin+'/api/auth/roles'));
  assert.ok(Object.hasOwn(catalogue.permissions,'followup.manage'));
  assert.equal((await read(manager.context)).canManage,true);
  assert.equal((await read(employee.context)).canManage,false);
  await manager.page.goto(app.origin+'/app/account');
  const showSettings=async target=>{if(!await target.locator('[data-followup-settings]').isVisible())await target.getByText('Reminder settings and approved recipients',{exact:true}).click();};
  await showSettings(manager.page);
  const settings=manager.page.locator('[data-followup-settings]');
  await settings.getByLabel('Enable email reminders',{exact:true}).check();
  for(const input of await settings.locator('input[name=recipients]').all())await input.uncheck();
  await settings.locator('input[name=recipients][value=employee]').check();
  await settings.locator('input[name=recipients][value=help_desk]').check();
  await settings.locator(`input[name=escalationRecipients][value="${ownerId}"]`).check();
  await settings.getByLabel('I authorize this reminder policy and these recipients.',{exact:true}).check();
  const saved=manager.page.waitForResponse(response=>response.url().endsWith('/api/auth/followup/settings'));
  await settings.getByRole('button',{name:'Save follow-up settings'}).click();assert.equal((await saved).status(),200);
  await shoot('followup-custom-manager-settings',manager.page,showSettings);

  const enrollment=(await read(employee.context)).obligations.find(ob=>ob.kind==='enrollment'&&ob.person_id===employee.id&&ob.state==='open');assert.ok(enrollment);
  const employeeRecords=await read(employee.context);
  assert.ok(employeeRecords.obligations.every(ob=>ob.person_id===employee.id||ob.owner_id===employee.id),'employee sees only personal or held follow-up');
  const beforeEmployee=await early(employee,enrollment.id);
  await mailSince(beforeEmployee,{address:employee.address,reference:enrollment.id});
  await expect(employee.page.locator('[data-followup-settings]')).toHaveCount(0);
  await shoot('followup-employee-early',employee.page);
  assert.equal((await post(manager.context,'followup/send',{id:enrollment.id})).status(),403,'management permission does not make its holder the employee');

  // A hardware holder's own recovery is a separate personal source. The
  // normal early button sends to its role-derived employee recipient.
  const recovery=await body(await post(helpdesk.context,'recovery/start',{}),201);
  const ownRecovery=(await read(helpdesk.context)).obligations.find(ob=>ob.kind==='recovery'&&!ob.case_id&&ob.source_id===recovery.id);
  assert.ok(ownRecovery,'own recovery creates a personal reminder');
  const beforeRecovery=await early(helpdesk,ownRecovery.id);
  await mailSince(beforeRecovery,{address:helpdesk.address,reference:ownRecovery.id});
  await shoot('followup-own-recovery-early',helpdesk.page);
  // A public reschedule creates a fresh occurrence. Extra caller-supplied
  // recipients and addresses cannot widen the consented role-derived target.
  await body(await post(owner,'followup/schedule',{id:ownRecovery.id,ownerId,dueBusinessDays:3,deadlineBusinessDays:5}));
  const injectedAddress=`synthetic-auth-${fixtureBase+9}@example.com`,beforeInjection=new Set(await outbox());
  await body(await post(helpdesk.context,'followup/send',{id:ownRecovery.id,recipients:[employee.id,injectedAddress],to:injectedAddress,email:injectedAddress}));
  const injectedMail=await mailSince(beforeInjection,{address:helpdesk.address,reference:ownRecovery.id});
  assert.ok(injectedMail.every(html=>html.includes(`<p>To: ${helpdesk.address}</p>`)&&!html.includes(injectedAddress)),'injected addresses cannot change the recipient');
  await body(await post(helpdesk.context,'recovery/cancel',{id:recovery.id}));
  assert.equal((await read(helpdesk.context)).obligations.find(ob=>ob.id===ownRecovery.id).state,'cancelled');

  // Opening uses person scope; subsequent review uses only the exact case grant.
  await change({kind:'grant',personId:helpdesk.id,roleId:'help-desk',resources:{view:{people:[employee.id]},edit:{people:[employee.id]}}});
  const opened=await body(await post(helpdesk.context,'roles/recovery-case',{action:'open',personId:employee.id,reason:'Synthetic employee recovery follow-up'}),201);
  const exactGrant=await change({kind:'grant',personId:helpdesk.id,roleId:'help-desk',resources:{view:{cases:[opened.caseId]},edit:{cases:[opened.caseId]}}});
  const caseOb=(await read(helpdesk.context)).obligations.find(ob=>ob.case_id===opened.caseId&&ob.state==='open');assert.ok(caseOb,'scoped recovery case creates held follow-up');
  assert.equal(caseOb.owner_id,helpdesk.id);
  const otherCase=await body(await post(owner,'roles/recovery-case',{action:'open',personId:employee.id,reason:'Synthetic unassigned recovery follow-up'}),201);
  assert.ok(!(await read(helpdesk.context)).obligations.some(ob=>ob.case_id===otherCase.caseId),'help desk cannot read another case outside its exact scope');
  const beforeHelpdesk=await early(helpdesk,caseOb.id);
  await mailSince(beforeHelpdesk,{address:helpdesk.address,reference:caseOb.id});
  await shoot('followup-helpdesk-holder',helpdesk.page);

  // A new scheduled occurrence allows another authorized early send, without a clock or database shortcut.
  await body(await post(owner,'followup/schedule',{id:caseOb.id,ownerId,dueBusinessDays:2,deadlineBusinessDays:5}));
  await change({kind:'revoke',grantId:exactGrant.plan.id});
  assert.equal((await post(helpdesk.context,'followup/send',{id:caseOb.id})).status(),403,'lost exact case authority ends early send');
  const beforeEscalation=await early({page,context:owner},caseOb.id);
  const escalated=await mailSince(beforeEscalation,{address:app.vars.OWNER_EMAIL,reference:caseOb.id});
  assert.ok(escalated.every(html=>!html.includes(`To: ${helpdesk.address}`)),'former case holder receives no reminder');
  const history=(await read(owner)).history.filter(event=>event.obligation_id===caseOb.id);
  assert.ok(history.some(event=>event.event==='recipient_recheck_failed'),'failed live case recipient check is visible');
  await shoot('followup-helpdesk-authority-escalation',page);

  // Installation sessions retain their own cookies. They are refused at an
  // isolated employer's policy door, whose owner signs in independently.
  const installationAdmin=await person(5);
  await body(await post(owner,'people/role',{personId:installationAdmin.id,role:'admin'}));
  await email(installationAdmin.context,installationAdmin.address);
  const organization=await body(await post(owner,'organizations/create',{name:`Northwind Support ${width}`}),201);
  const prefix=`/org/${organization.id}`,orgContext=await browser.newContext({viewport:{width,height:1000}});contexts.push(orgContext);
  const orgPage=await orgContext.newPage();
  const orgCdp=await orgContext.newCDPSession(orgPage);await orgCdp.send('WebAuthn.enable');
  await orgCdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  const orgPost=(path,data)=>orgContext.request.post(app.origin+prefix+path,{data,headers:{origin:app.origin}});
  assert.equal((await orgPost('/auth/identity/email/request',{email:app.vars.OWNER_EMAIL})).status(),202);
  assert.equal((await orgPost('/auth/identity/email/confirm',{token:(await app.link(prefix)).searchParams.get('token')})).status(),200);
  await orgPage.goto(app.origin+prefix+'/app/methods');
  const orgRegistered=orgPage.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify')),orgReloaded=orgPage.waitForEvent('load');
  await orgPage.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await orgRegistered).status(),200);
  await orgReloaded;
  const orgPolicy=await body(await orgContext.request.get(app.origin+prefix+'/api/auth/followup'));
  const rootPolicy=(await read(owner)).policy;
  for(const rootActor of [{context:owner,page},installationAdmin,manager]) {
   await rootActor.page.setViewportSize({width,height:1000});
   const refused=await rootActor.context.request.post(app.origin+prefix+'/api/auth/followup/settings',{data:{...rootPolicy,confirm:true},headers:{origin:app.origin}});
   assert.equal(refused.status(),401,`an installation session is not an employer session at ${width}px`);
  }
  // The installation's follow-up coordinator joins this employer as an
  // ordinary member. A local passkey and fresh email proof still carry no
  // installation role into the employer's policy door.
  await body(await orgPost('/api/auth/organizations/invite',{email:manager.address,name:'Jordan Rivera'}),201);
  const memberPost=(path,data)=>manager.context.request.post(app.origin+prefix+path,{data,headers:{origin:app.origin}});
  assert.equal((await memberPost('/auth/identity/email/request',{email:manager.address})).status(),202);
  assert.equal((await memberPost('/auth/identity/email/confirm',{token:(await app.link(prefix)).searchParams.get('token')})).status(),200);
  await manager.page.goto(app.origin+prefix+'/app/methods');
  const memberRegistered=manager.page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify')),memberReloaded=manager.page.waitForEvent('load');
  await manager.page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await memberRegistered).status(),200);
  await memberReloaded;
  const memberWrite=await memberPost('/api/auth/followup/settings',{...rootPolicy,confirm:true});
  assert.equal(memberWrite.status(),403);assert.equal((await memberWrite.json()).error,'role_permission_required','an installation role is not an employer role');
  assert.equal((await body(await manager.context.request.get(app.origin+prefix+'/api/auth/followup'))).canManage,false);
  await manager.page.goto(app.origin+prefix+'/app/account');
  await expect(manager.page.locator('[data-followup-panel]')).toBeVisible();
  await expect(manager.page.locator('[data-followup-settings]')).toHaveCount(0);
  await shoot('followup-installation-role-member',manager.page);
  const unchanged=await body(await orgContext.request.get(app.origin+prefix+'/api/auth/followup'));
  assert.deepEqual(unchanged.policy,orgPolicy.policy,'isolated employer policy remains unchanged');
  await orgPage.goto(app.origin+prefix+'/app/account');
  await shoot('followup-isolated-employer-policy',orgPage);

 } finally {await Promise.all(contexts.map(context=>context.close()));}
}
