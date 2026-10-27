import assert from 'node:assert/strict';
import {join} from 'node:path';
import {expect} from '@playwright/test';

export async function temporaryPassJourney({app,browser,page,directory}) {
 const owner=page.context(),headers={origin:app.origin};
 const post=async(path,data,context=owner,status=200)=>{const response=await context.request.post(app.origin+path,{data,headers});assert.equal(response.status(),status,await response.text());return response.json();};
 const proof=async(target,name)=>{
  for(const width of [1440,390])for(const theme of ['light','dark']) {
   await target.setViewportSize({width,height:1000});await target.emulateMedia({colorScheme:theme});
   assert.ok(await target.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits '+width);
   await target.screenshot({path:join(directory,`temporary-pass-${name}-${width}-${theme}.png`),fullPage:true});
  }
  await target.setViewportSize({width:1440,height:1000});await target.emulateMedia({colorScheme:'light'});
 };
 const hardware=async(context,target)=>{const cdp=await context.newCDPSession(target);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});};
 const hireAddress='synthetic-auth-zero@example.com';
 await page.goto(app.origin+'/app/people');await page.getByRole('button',{name:'Invite person',exact:true}).click();
 const dialog=page.locator('#invite-dialog');
 await dialog.getByLabel('Name',{exact:true}).fill('Synthetic day-one hire');await dialog.getByLabel('Email',{exact:true}).fill(hireAddress);
 await dialog.getByLabel('Personal contact',{exact:true}).fill('synthetic-auth-zero-personal@example.net');
 await dialog.getByLabel('Employer-local start time').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));await dialog.getByLabel('Employer time zone').fill('UTC');await dialog.getByLabel('Invitation lead days').fill('0');
 await dialog.getByRole('checkbox').check();
 const created=page.waitForResponse(r=>r.url().endsWith('/api/auth/people/invite')).then(async r=>{assert.equal(r.status(),201);return r.json();});
 await dialog.getByRole('button',{name:'Invite person',exact:true}).click();const hire=await created;
 await page.waitForTimeout(600);await page.reload();
 const hirePanel=page.locator('details.panel').filter({hasText:hireAddress});await hirePanel.locator('summary').click();
 await expect(hirePanel.getByText('A temporary access pass is required',{exact:false})).toBeVisible();
 await proof(page,'zero-lead');
 const me=await(await owner.request.get(app.origin+'/api/auth/me')).json();
 await post('/api/auth/directory/edit',{personId:hire.personId,set:{manager:me.user.id}});
 const helper=await post('/api/auth/directory/onboard',{name:'Synthetic scoped helper',email:'synthetic-auth-helper@example.com',kind:'employee',set:{}},owner,201);
 const group=await post('/api/auth/groups/create',{name:'Day-one onboarding'},owner,201);await post('/api/auth/groups/add',{groupId:group.id,personId:hire.personId});
 const helperContext=await browser.newContext(),helperPage=await helperContext.newPage(),hireContext=await browser.newContext(),hirePage=await hireContext.newPage();
 try {
  await hardware(helperContext,helperPage);await helperPage.goto(app.origin+'/signin');
  await helperPage.getByLabel('Email address',{exact:true}).fill('synthetic-auth-helper@example.com');await helperPage.getByRole('button',{name:'Email me a sign-in link'}).click();
  await expect(helperPage.locator('[data-auth-status]')).toContainText('link has been sent');
  await helperPage.goto((await app.link()).href);await helperPage.getByRole('button',{name:'Continue to Auth'}).click();
  await helperPage.goto(app.origin+'/app/methods');const helperEnrolled=helperPage.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify'));await helperPage.getByRole('button',{name:'Register a passkey',exact:true}).click();assert.equal((await helperEnrolled).status(),200);
  const scope={view:{groups:[group.id]},edit:{groups:[group.id]}};
  const preview=await post('/api/auth/roles/preview',{kind:'grant',personId:helper.id,roleId:'help-desk',resources:scope});await post('/api/auth/roles/apply',{previewId:preview.previewId});
  await page.goto(app.origin+'/app/account#temporary-passes');const managerPanel=page.locator('#temporary-passes');
  await managerPanel.getByLabel('Manager verification').fill('Verified the new hire in person against the employer record');
  const requested=page.waitForResponse(r=>r.url().endsWith('/temporary-passes/request'));await managerPanel.getByRole('button',{name:'Verify and request pass'}).click();assert.equal((await requested).status(),201);
  await page.waitForTimeout(600);await page.reload();await proof(page,'manager-requested');
  await helperPage.goto(app.origin+'/app/account#temporary-passes');
  const helpPanel=helperPage.locator('#temporary-passes');await expect(helpPanel.getByRole('button',{name:'Issue temporary pass'})).toBeVisible();await proof(helperPage,'scoped-issuance');
  const issuance=helperPage.waitForResponse(r=>r.url().endsWith('/temporary-passes/issue'));await helpPanel.getByRole('button',{name:'Issue temporary pass'}).click();assert.equal((await issuance).status(),201);
  const displayed=helpPanel.locator('[data-temporary-pass-value]');await expect(displayed).not.toHaveValue('');const pass=await displayed.inputValue();await proof(helperPage,'issued-once');
  await hardware(hireContext,hirePage);await hirePage.goto(app.origin+'/signin');await hirePage.getByText('Use a temporary access pass',{exact:true}).click();await hirePage.getByLabel('Temporary access pass',{exact:true}).fill(pass);await proof(hirePage,'hosted-signin');
  await hirePage.getByRole('button',{name:'Continue to enrollment'}).click();await expect(hirePage).toHaveURL(app.origin+'/app/methods');await expect(hirePage.getByRole('button',{name:'Register a passkey',exact:true})).toHaveCount(0);await proof(hirePage,'work-proof-required');
  assert.equal((await hireContext.request.get(app.origin+'/api/auth/organizations')).status(),403);
  const workRequested=hirePage.waitForResponse(r=>r.url().endsWith('/auth/identity/email/request'));await hirePage.getByRole('button',{name:'Confirm my email',exact:true}).click();assert.equal((await workRequested).status(),202);
  await hirePage.goto((await app.link()).href);await hirePage.getByRole('button',{name:'Continue to Auth'}).click();await expect(hirePage).toHaveURL(app.origin+'/app/methods');
  await expect(hirePage.getByRole('button',{name:'Register a passkey',exact:true})).toBeVisible();await proof(hirePage,'verified-enrollment');
  const enrolling=hirePage.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify'));await hirePage.getByRole('button',{name:'Register a passkey',exact:true}).click();assert.equal((await enrolling).status(),200);
  await hirePage.waitForTimeout(600);await expect(hirePage.getByText('1 registered',{exact:true})).toBeVisible();await proof(hirePage,'complete');
  assert.equal((await hireContext.request.post(app.origin+'/auth/identity/temporary-pass',{data:{pass},headers})).status(),403,'enrollment cannot reuse the pass');
  await helperPage.reload();await expect(helperPage.locator('#temporary-passes')).toHaveCount(0,'completed hire no longer needs issuance');
 }finally {await helperContext.close();await hireContext.close();}
 await page.goto(app.origin+'/app/methods');
 const refreshed=page.waitForResponse(r=>r.url().endsWith('/auth/identity/email/request'));await page.getByRole('button',{name:'Confirm my email',exact:true}).click();assert.equal((await refreshed).status(),202);
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();
}
