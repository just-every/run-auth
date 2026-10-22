import assert from 'node:assert/strict';
import {expect} from '@playwright/test';

export async function followupJourney({app,browser,owner,page,shoot}) {
 const post=(context,path,data)=>context.request.post(app.origin+path,{data,headers:{origin:app.origin}});
 // A reminder contains only an Activity link; it cannot carry sign-in proof.
 const anonymous=await browser.newContext();
 try {
  const response=await anonymous.request.get(app.origin+'/app/activity',{maxRedirects:0});
  assert.equal(response.status(),303);assert.equal(response.headers().location,'/signin?returnTo=%2Fapp%2Factivity');
 }finally{await anonymous.close();}
 // A real recovery cannot self-approve. Its next action survives restarting
 // the emitted Worker, and the normal cancellation door stops its reminders.
 const started=await post(owner,'/api/auth/recovery/start',{});assert.equal(started.status(),201);const recovery=await started.json();
 assert.equal((await post(owner,'/api/auth/recovery/approve',{id:recovery.id})).status(),403);
 assert.equal((await post(owner,'/api/auth/recovery/complete',{id:recovery.id})).status(),403);
 await page.goto(app.origin+'/app/activity');
 const recoveryCard=page.locator('[data-followup-panel] article',{hasText:'wait or request distinct admin approval'});
 await expect(recoveryCard).toHaveCount(1);await expect(recoveryCard.locator('[data-followup-state]')).toHaveText('open');
 await shoot('followup-recovery-approval',page);
 await app.pause();await app.resume();await page.reload();
 await expect(recoveryCard).toHaveCount(1);await expect(recoveryCard.locator('[data-followup-state]')).toHaveText('open');
 await shoot('followup-recovery-restarted',page);
 assert.equal((await post(owner,'/api/auth/recovery/cancel',{id:recovery.id})).status(),200);
 await page.reload();await expect(page.locator('[data-followup-panel] article',{hasText:'Recovery'}).locator('[data-followup-state]')).toHaveText('cancelled');
 await shoot('followup-recovery-cancelled',page);
 const address='taylor@northwind.example.com';
 assert.equal((await post(owner,'/api/auth/people/invite',{email:address,name:'Taylor Kim'})).status(),201);
 await page.goto(app.origin+'/app/activity');
 const followup=page.locator('[data-followup-panel]');
 const record=followup.locator('article',{hasText:address});
 await expect(record).toHaveCount(1);await expect(record.locator('[data-followup-state]')).toHaveText('open');
 await shoot('followup-open',page);
 await shoot('followup-settings',page,async target=>{
  if(!await target.locator('[data-followup-settings]').isVisible())await target.getByText('Reminder settings and approved recipients',{exact:true}).click();
 });
 const settings=followup.locator('[data-followup-settings]');
 await settings.getByLabel('Employer timezone',{exact:true}).fill('America/New_York');
 await settings.getByLabel('Local reminder time',{exact:true}).fill('09:30');
 await settings.getByLabel('Enable email reminders',{exact:true}).check();
 await settings.locator('input[name=recipients]').first().check();
 await settings.locator('input[name=escalationRecipients]').first().check();
 await settings.getByLabel('I authorize this reminder policy and these recipients.',{exact:true}).check();
 const saved=page.waitForResponse(response=>response.url().endsWith('/api/auth/followup/settings'));
 await settings.getByRole('button',{name:'Save follow-up settings'}).click();assert.equal((await saved).status(),200);
 await expect(followup).toContainText('Email reminders enabled');
 await record.getByText('Reschedule or assign a follow-up owner',{exact:true}).click();
 const schedule=record.locator('[data-followup-schedule]');
 await schedule.getByLabel('Next due in business days',{exact:true}).fill('2');
 await schedule.getByLabel('Deadline in business days',{exact:true}).fill('5');
 const rescheduled=page.waitForResponse(response=>response.url().endsWith('/api/auth/followup/schedule'));
 await schedule.getByRole('button',{name:'Reschedule follow-up'}).click();assert.equal((await rescheduled).status(),200);
 await shoot('followup-scheduled',page);
 const person=await browser.newContext(),mine=await person.newPage();
 try {
  const cdp=await person.newCDPSession(mine);await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  assert.equal((await post(person,'/auth/identity/email/request',{email:address})).status(),202);
  assert.equal((await post(person,'/auth/identity/email/confirm',{token:(await app.link()).searchParams.get('token')})).status(),200);
  await mine.goto(app.origin+'/app/methods');
  const enrolled=mine.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
  await mine.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await enrolled).status(),200);
  await page.goto(app.origin+'/app/activity');
  await expect(record.locator('[data-followup-state]')).toHaveText('completed');
  await record.getByText('Recorded follow-up history',{exact:true}).click();
  await shoot('followup-completed',page);
  const records=await(await owner.request.get(app.origin+'/api/auth/followup')).json();
  const item=records.obligations.find(item=>item.kind==='enrollment'&&item.state==='completed'&&item.person_id!==null&&records.history.some(event=>event.obligation_id===item.id&&event.event==='schedule_changed'));
  assert.ok(item,'completed enrollment preserves its rescheduling history');
  assert.ok(records.history.some(event=>event.obligation_id===item.id&&event.event==='completed'));
 } finally {await person.close();}
}
