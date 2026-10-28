import {hrFileJourney} from './helpers/hr-file-journey.mjs';
import {identityPairsJourney} from './helpers/identity-pairs-journey.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';
import {captureViews} from './helpers/capture-views.mjs';

const views=[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']];

test('directory journey: an administrator onboards a worker, edits and bulk-moves people with a preview, sets a group rule, terminates and rehires, at desktop/mobile in both themes',{timeout:180000},async t=>{
 const app=await openApp();let browser;t.after(async()=>{await browser?.close();await app.close();});await app.claim();
 browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic','--no-sandbox'],executablePath:process.env.AUTH_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),primary=page;
 page.setDefaultTimeout(30000);page.setDefaultNavigationTimeout(30000);
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const shoot=async (name,page=primary)=>captureViews({page,views,errors,capture:async(page,width,theme)=>{
  await expect(page.locator('h1')).toBeVisible();
  const results=await new AxeBuilder({page}).analyze();
  assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],`${width} ${theme} ${name}`);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
  for(const control of await page.locator('[data-tooltip]:visible').all()){await page.mouse.move(0,0);await control.blur();await expect(page.getByRole('tooltip')).toBeHidden();await control.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();await page.waitForTimeout(200);await expect(page.getByRole('tooltip')).toBeVisible();await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true);await page.keyboard.press('Escape');await control.blur();}
  await page.screenshot({path:join(directory,`directory-${name}-${width}-${theme}.png`),fullPage:true});
 }});
 const row=name=>page.locator('[data-person-row]',{hasText:name});
 const saved=async action=>{const loaded=page.waitForEvent('load');await action();await loaded;};

 // Owner: browser email link, setup, hardware passkey.
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);await page.waitForTimeout(500);

 // Onboard a W-2 employee and a contractor through the dialog.
 await page.goto(app.origin+'/app/people');
 const onboard=async(name,email,kind,employment,department,location)=>{
  await page.locator('[data-open-dialog="onboard-dialog"]').click();
  const dialog=page.locator('#onboard-dialog');
  await dialog.getByLabel('Name',{exact:true}).fill(name);await dialog.getByLabel('Work email').fill(email);await dialog.getByLabel('Worker type').selectOption(kind);await dialog.getByLabel('Employment').selectOption(employment);
  await dialog.getByLabel('Department').fill(department);await dialog.getByLabel('Location').fill(location);
  await saved(()=>dialog.getByRole('button',{name:'Onboard worker'}).click());
 };
 await onboard('Erin Park','erin@northwind.example.com','employee','w2','Engineering','US');
 await onboard('Cole Reed','cole@contractors.example.com','contractor','1099','Engineering','UK');
 await expect(row('Erin Park')).toContainText('Employee · Engineering · US');await expect(row('Cole Reed')).toContainText('Contractor · Engineering · UK');
 // Erin accepts her invitation: the same member, now active.
 const employee=await browser.newContext();
 assert.equal((await employee.request.post(app.origin+'/auth/identity/email/request',{data:{email:'erin@northwind.example.com'},headers:{origin:app.origin}})).status(),202);
 const invitation=await app.link();assert.equal((await employee.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:invitation.searchParams.get('token')},headers:{origin:app.origin}})).status(),200);
 await page.reload();await expect(row('Erin Park')).toContainText('Active');
 // A group and its rule, previewed before it is set.
 assert.equal((await context.request.post(app.origin+'/api/auth/groups/create',{data:{name:'Engineering staff'},headers:{origin:app.origin}})).status(),201);
 await page.reload();
 const rule=page.locator('[data-group-rule]');
 await rule.getByLabel('Where').selectOption({label:'Department'});await rule.getByLabel('Value').fill('Engineering');
 await rule.getByRole('button',{name:'Preview rule'}).click();
 await expect(rule.locator('[data-rule-result]')).toContainText('erin@northwind.example.com');await expect(page.locator('.group-row',{hasText:'Static group'})).toBeVisible();
 await saved(()=>rule.getByRole('button',{name:'Set rule'}).click());
 const groupRow=page.locator('.group-row',{hasText:'Engineering staff'});
 await expect(groupRow).toContainText('Matches the rule: department is Engineering');await expect(groupRow).toContainText('cole@contractors.example.com');
 // Rename and transfer one: same person, new name and location.
 await row('Cole Reed').getByRole('button',{name:'Edit Cole Reed'}).click();
 const edit=page.locator('#edit-dialog');
 await edit.getByLabel('Name',{exact:true}).fill('Colette Reed');await edit.getByLabel('Location').fill('US');
 await saved(()=>edit.getByRole('button',{name:'Save changes'}).click());
 await expect(row('Colette Reed')).toContainText('Contractor · Engineering · US');
 // A bulk edit previews who is affected and which groups they leave; applying it moves them.
 const bulk=page.locator('[data-directory-bulk]');
 await bulk.getByLabel('Department is').fill('Engineering');await bulk.getByLabel('Move to department').fill('Platform');
 await bulk.getByRole('button',{name:'Preview',exact:true}).click();
 const result=page.locator('[data-bulk-result]');await expect(result).toContainText('2 people');await expect(result).toContainText('leaves Engineering staff');
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`preview fits ${width}px`);await result.scrollIntoViewIfNeeded();await page.screenshot({path:join(directory,`directory-preview-${width}.png`)});}
 await page.setViewportSize({width:1440,height:1000});
 await saved(()=>bulk.getByRole('button',{name:'Apply preview'}).click());
 await expect(row('Erin Park')).toContainText('Employee · Platform · US');await expect(page.locator('.group-row',{hasText:'Engineering staff'})).toContainText('No members');
 // The employee's own profile: she edits her name; then the HR system takes it and the page says so.
 const mine=await employee.newPage();await mine.goto(app.origin+'/app/account');
 await mine.getByLabel('Name',{exact:true}).fill('Erin P. Park');
 const edited=mine.waitForEvent('load');await mine.getByRole('button',{name:'Save profile'}).click();await edited;
 await expect(mine.getByLabel('Name',{exact:true})).toHaveValue('Erin P. Park');await expect(mine.getByRole('heading',{name:'Erin P. Park'})).toBeVisible();
 const erinId=(await (await context.request.get(app.origin+'/api/auth/directory?q=erin@northwind')).json()).people[0].id;
 const fed=await context.request.post(app.origin+'/api/auth/directory/source',{data:{source:'hr',records:[{sourceId:'E-1',personId:erinId,fields:{name:'Erin Park-Lee'}}]},headers:{origin:app.origin}});assert.equal(fed.status(),200);
 await mine.reload();await expect(mine.getByText('Managed by your HR system')).toBeVisible();await expect(mine.getByLabel('Name',{exact:true})).toHaveCount(0);await expect(mine.getByRole('heading',{name:'Erin Park-Lee'})).toBeVisible();
 await shoot('account',mine);
 // Terminate and rehire the active employee: her session ends, the account and id stay.
 const status=async()=>(await employee.request.get(app.origin+'/api/auth/me')).status();assert.equal(await status(),200);
 await row('Erin Park').getByRole('button',{name:'Edit Erin Park'}).click();await edit.getByLabel('State').selectOption('terminated');
 await saved(()=>edit.getByRole('button',{name:'Save changes'}).click());
 await expect(row('Erin Park')).toContainText('Terminated');assert.equal(await status(),401);
 await row('Erin Park').getByRole('button',{name:'Edit Erin Park'}).click();await edit.getByLabel('State').selectOption('active');
 await saved(()=>edit.getByRole('button',{name:'Save changes'}).click());
 await expect(row('Erin Park')).not.toContainText('Terminated');await expect(row('Erin Park')).toContainText('Active');
 assert.equal(await page.locator('[data-person-row]',{hasText:'erin@northwind.example.com'}).count(),1);
 await shoot('people');
 // The edit dialog fits both widths.
 for(const width of [1440,390]){await page.setViewportSize({width,height:900});await row('Erin Park').getByRole('button',{name:'Edit Erin Park'}).click();await expect(edit).toBeVisible();
  const box=await edit.boundingBox();assert.ok(box.x>=0&&box.x+box.width<=width,`edit dialog fits ${width}px`);
  await page.screenshot({path:join(directory,`directory-edit-${width}.png`)});await edit.getByRole('button',{name:'Cancel'}).click();}
 await hrFileJourney({app,context,page,shoot});
 assert.deepEqual(errors,[]);
});

test('organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile',{timeout:300000},async t=>{
 const app=await openApp();let browser;t.after(async()=>{await browser?.close();await app.close();});await app.claim();
 browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic','--no-sandbox'],executablePath:process.env.AUTH_CHROMIUM||undefined});
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 page.setDefaultTimeout(30000);page.setDefaultNavigationTimeout(30000);
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const hardware=async(context,page)=>{const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});page.on('dialog',dialog=>dialog.accept());};
 await hardware(context,page);
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const saved=async(action,target=page)=>{const loaded=target.waitForEvent('load',{timeout:30000});await action();await loaded;};
 const post=async(path,data,status=200,client=context)=>{const response=await client.request.post(app.origin+path,{data,headers:{origin:app.origin}});assert.equal(response.status(),status,path+' '+await response.text());return response.json();};
 const signIn=async(target,email,prefix='',setup=false)=>{
  await target.goto(app.origin+prefix+'/signin?returnTo='+encodeURIComponent(setup?'/setup':'/app/methods'));
  await target.getByLabel('Email address',{exact:true}).fill(email);await target.getByRole('button',{name:'Email me a sign-in link'}).click();
  await target.goto((await app.link(prefix)).href);await target.getByRole('button',{name:'Continue to Auth'}).click();
  if(setup){await target.getByRole('checkbox').check();await target.getByRole('button',{name:'Finish setup'}).click();await target.goto(app.origin+'/app/methods');}
  await target.waitForURL(app.origin+prefix+'/app/methods');await target.waitForLoadState('load');
  const response=target.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify')),reloaded=target.waitForEvent('load');await target.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await response).status(),200);await reloaded;
 };
 const shoot=async(name,target=page)=>{
  for(const width of [1440,390]){await target.setViewportSize({width,height:1000});await target.emulateMedia({colorScheme:'light'});
   await expect(target.locator('h1')).toBeVisible();
   await target.screenshot({path:join(directory,`authority-${name}-${width}.png`),fullPage:true});
   const layout=await target.evaluate(()=>({fits:document.documentElement.scrollWidth<=innerWidth,width:document.documentElement.scrollWidth,overflow:[...document.querySelectorAll('main *')].filter(el=>el.scrollWidth>el.clientWidth+1&&getComputedStyle(el).overflowX==='visible').slice(-8).map(el=>({tag:el.tagName,classes:el.className,text:el.textContent.slice(0,60),width:el.clientWidth,scroll:el.scrollWidth}))}));
   assert.ok(layout.fits,name+' fits '+width+' '+JSON.stringify(layout));
   const axe=await new AxeBuilder({page:target}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],name+' '+width);
  }await target.setViewportSize({width:1440,height:1000});
 };
 await signIn(page,app.vars.OWNER_EMAIL,'',true);
 await page.goto(app.origin+'/app/organizations');await page.getByLabel('Organization name').fill('Northwind Manufacturing');await page.getByRole('button',{name:'Create organization',exact:true}).click();
 const newOrg=page.getByRole('link',{name:'Sign in to Northwind Manufacturing and enroll its passkey'});await expect(newOrg).toBeVisible();
 const prefix=new URL(await newOrg.getAttribute('href'),app.origin).pathname.replace('/signin','');
 await shoot('organization-created');await signIn(page,app.vars.OWNER_EMAIL,prefix);
 await page.goto(app.origin+prefix+'/app/organizations');await expect(page.getByText('owner · Active organization',{exact:true})).toBeVisible();await shoot('organization-memberships');
 // An isolated employer's legacy administrator can delegate within authority,
 // but only that employer's owner may design custom ranks.
 await post(prefix+'/api/auth/organizations/invite',{email:'avery@northwind.example.com',name:'Avery Brooks'},201);
 const isolatedAdmin=await browser.newContext(),isolatedPage=await isolatedAdmin.newPage();await hardware(isolatedAdmin,isolatedPage);
 await post(prefix+'/auth/identity/email/request',{email:'avery@northwind.example.com'},202,isolatedAdmin);
 await post(prefix+'/auth/identity/email/confirm',{token:(await app.link(prefix)).searchParams.get('token')},200,isolatedAdmin);
 const isolatedPerson=(await (await isolatedAdmin.request.get(app.origin+prefix+'/api/auth/me')).json()).user;
 await post(prefix+'/api/auth/people/role',{personId:isolatedPerson.id,role:'admin'});
 await signIn(isolatedPage,'avery@northwind.example.com',prefix);
 await isolatedPage.goto(app.origin+prefix+'/app/roles');
 await expect(isolatedPage.locator('[data-role-form=role]')).toHaveCount(0);
 await expect(isolatedPage.locator('[data-role-form=grant]')).toBeVisible();
 await shoot('isolated-administrator-roles',isolatedPage);await isolatedAdmin.close();
 await page.getByRole('button',{name:'Switch to Installation'}).click();await expect(page).toHaveURL(app.origin+'/app/account');
 await post('/api/auth/people/invite',{email:'synthetic-auth-30@example.com',name:'Historical Invitation'},201);
 const historicalPerson=(await (await context.request.get(app.origin+'/api/auth/people')).json()).find(p=>p.email==='synthetic-auth-30@example.com');assert.ok(historicalPerson);
 for(const email of ['synthetic-auth-31@example.com','synthetic-auth-32@example.com'])await post('/api/auth/directory/edit',{personId:historicalPerson.id,email});
 const worker=await post('/api/auth/directory/onboard',{name:'Erin Park',email:'erin@northwind.example.com',kind:'employee',set:{department:'Engineering',location:'US'}},201);
 const helper=await post('/api/auth/directory/onboard',{name:'Sam Rivera',email:'sam@northwind.example.com',kind:'employee',set:{department:'Support',location:'US'}},201);
 const workerContext=await browser.newContext(),workerPage=await workerContext.newPage();await hardware(workerContext,workerPage);await signIn(workerPage,'erin@northwind.example.com');
 const helperContext=await browser.newContext(),helperPage=await helperContext.newPage();await hardware(helperContext,helperPage);await signIn(helperPage,'sam@northwind.example.com');
 const group=await post('/api/auth/groups/create',{name:'US engineering staff'},201);await post('/api/auth/groups/add',{groupId:group.id,personId:worker.id});
 const appConfig=await post('/api/auth/company-apps/create',{name:'Engineering documents',entityId:'https://documents.example.com',acsUrl:'https://documents.example.com/acs'},201);
 // The existing custom-grant action must send mandatory mail even when
 // optional browser notices are off. Read it only through the gated outbox.
 const securityOwner=(await (await context.request.get(app.origin+'/api/auth/me')).json()).user.id;
 await post('/api/auth/notifications/settings',{confirm:true,emailEnabled:true,newDevice:false,factorEnrolled:true,securityOwnerId:securityOwner,slackEnabled:false,endSessionsOnReport:false});
 const roleNotices=async()=>{
  const listing=await(await app.get('/__dev/outbox',{'x-rer-dev-key':app.vars.RER_DEV_KEY})).text(),messages=[];
  for(const match of listing.matchAll(/href="(\/__dev\/outbox\?message=[^"]+)"/g)) {
   const detail=await(await app.get(match[1].replaceAll('&amp;','&'),{'x-rer-dev-key':app.vars.RER_DEV_KEY})).text();
   if(detail.includes('Auth administrator role granted'))messages.push(detail);
  }
  return messages;
 };
 const beforeGrantNotices=(await roleNotices()).length;
 await page.goto(app.origin+'/app/roles');
 const definition=page.locator('[data-role-form=role]');await definition.getByLabel('Role name').fill('Engineering support');await definition.getByText('Choose permissions',{exact:true}).click();
 for(const id of ['roles.view','people.view','people.factors.reset','cases.open','groups.view','apps.view','apps.assign','admin-api.manage','audit.view'])await definition.locator(`input[value="${id}"]`).check();
 await definition.getByRole('button',{name:'Preview role'}).click();await expect(definition.locator('[data-role-apply]')).toBeVisible();await shoot('role-preview');await saved(()=>definition.locator('[data-role-apply]').click());
 const grant=page.locator('[data-role-form=grant]');await grant.getByLabel('Role holder').selectOption(helper.id);await grant.locator('[name=roleId]').selectOption({label:'Engineering support'});
 await grant.locator('[name="view.groups"]').selectOption(group.id);await grant.locator('[name="edit.groups"]').selectOption(group.id);
 await grant.locator('[name="view.apps"]').selectOption(appConfig.id);await grant.locator('[name="edit.apps"]').selectOption(appConfig.id);
 await grant.getByRole('button',{name:'Preview delegation'}).click();await expect(grant.locator('[data-role-preview]')).toContainText('sam@northwind.example.com');await expect(grant.locator('[data-role-preview]')).toContainText('people.factors.reset');await expect(grant.locator('[data-role-preview]')).toContainText(group.id);await shoot('delegation-preview');assert.equal((await roleNotices()).length,beforeGrantNotices);await saved(()=>grant.locator('[data-role-apply]').click());
 const deliveredRoleNotices=await roleNotices();assert.equal(deliveredRoleNotices.length,beforeGrantNotices+1);
 const roleNotice=deliveredRoleNotices[0];assert.ok(roleNotice.includes('Engineering support'));
 const roleReport=roleNotice.match(/https?:\/\/[^\s<>"]+\/api\/auth\/notifications\/report\?token=[^\s<>"]+/)?.[0];assert.ok(roleReport);
 const publicNotice=await browser.newContext(),publicNoticePage=await publicNotice.newPage();t.after(()=>publicNotice.close());
 assert.equal((await publicNotice.request.get(app.origin+prefix+new URL(roleReport).pathname+new URL(roleReport).search)).status(),410);
 for(const [state,title] of [['reported','Suspicious activity reported'],['replayed','Report unavailable']]) {
  const response=await publicNoticePage.goto(roleReport.replaceAll('&amp;','&'));assert.equal(response.status(),state==='reported'?200:410);
  await expect(publicNoticePage.getByRole('heading',{name:title,exact:true})).toBeVisible();
  for(const theme of ['light','dark'])for(const width of [1440,390]) {
   await publicNoticePage.setViewportSize({width,height:1000});await publicNoticePage.emulateMedia({colorScheme:theme});
   await publicNoticePage.screenshot({path:join(directory,`role-notice-${state}-${width}-${theme}.png`),fullPage:true});
  }
 }
 await publicNotice.close();
 await page.goto(app.origin+'/app/account');
 await expect(page.locator('[data-notification-resolve]')).toHaveCount(1);
 for(const theme of ['light','dark'])for(const width of [1440,390]) {
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});
  await page.screenshot({path:join(directory,`role-notice-account-${width}-${theme}.png`),fullPage:true});
 }
 await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});
 await helperPage.goto(app.origin+'/app/roles');await expect(helperPage.getByRole('heading',{name:'Open an employee recovery case'})).toBeVisible();await shoot('scoped-help-desk',helperPage);
 const {generateKeyPair,exportJWK,SignJWT}=await import('jose'),pair=await generateKeyPair('ES256'),jwk={...await exportJWK(pair.publicKey),kid:'synthetic-auth-5',alg:'ES256',use:'sig'};
 const credential=helperPage.locator('[data-admin-service-create]');await credential.getByLabel('App name',{exact:true}).fill('Engineering assignment service');await credential.getByLabel('Purpose',{exact:true}).fill('Manage assignments only for the approved engineering app and workforce group');await expect(credential.getByLabel('Accountable owner',{exact:true})).toHaveValue(helper.id);
 await credential.getByLabel('Public signing keys (JWKS JSON)',{exact:true}).fill(JSON.stringify({keys:[jwk]}));await credential.locator('input[value="assignments.manage"]').check();await credential.getByLabel('Resource limits (JSON)',{exact:true}).fill(JSON.stringify({people:[worker.id],groups:[group.id],apps:[appConfig.id]}));
 const localExpiry=await helperPage.evaluate(()=>{const expiry=new Date(Date.now()+86400000);return new Date(expiry.getTime()-expiry.getTimezoneOffset()*60000).toISOString().slice(0,16);});await credential.getByLabel('Expires (your local time)',{exact:true}).fill(localExpiry);
 const createdCredential=helperPage.waitForResponse(response=>response.url().endsWith('/api/auth/admin-service-apps/create'));await saved(()=>credential.getByRole('button',{name:'Create service app',exact:true}).click(),helperPage);assert.equal((await createdCredential).status(),201);await expect(helperPage.getByRole('button',{name:'Revoke Engineering assignment service',exact:true})).toBeVisible();await shoot('scoped-credential',helperPage);
 const revokedCredential=helperPage.waitForResponse(response=>response.url().endsWith('/api/auth/admin-service-apps/revoke'));await saved(()=>helperPage.getByRole('button',{name:'Revoke Engineering assignment service',exact:true}).click(),helperPage);assert.equal((await revokedCredential).status(),200);await expect(helperPage.getByRole('button',{name:'Revoke Engineering assignment service',exact:true})).toHaveCount(0);await shoot('scoped-credential-revoked',helperPage);
 // Recover this same employee through an exact case, the manager's real
 // session, fresh employee email proof and native WebAuthn enrollment.
 const openedAt=Date.now(),ownerId=(await (await context.request.get(app.origin+'/api/auth/me')).json()).user.id;
 await post('/api/auth/directory/edit',{personId:worker.id,set:{manager:ownerId}});
 await helperPage.getByLabel('Case reason',{exact:true}).fill('Employee lost every factor');
 const opening=helperPage.waitForResponse(r=>r.url().endsWith('/roles/recovery-case')).then(async response=>{assert.equal(response.status(),201);return response.json();});
 await saved(()=>helperPage.getByRole('button',{name:'Open recovery case',exact:true}).click(),helperPage);
 const recovery=await opening;assert.ok(recovery.caseId);
 const scope={view:{groups:[group.id],cases:[recovery.caseId]},edit:{groups:[group.id],cases:[recovery.caseId]}};
 const helpdeskGrant=await post('/api/auth/roles/preview',{kind:'grant',personId:helper.id,roleId:'help-desk',resources:scope});await post('/api/auth/roles/apply',{previewId:helpdeskGrant.previewId});
 await page.goto(app.origin+'/app/account');
 await saved(()=>page.getByRole('button',{name:'Attest employee identity',exact:true}).click());
 const proof=async(name,target)=>{await target.setViewportSize({width:1440,height:1000});await expect(target.locator('h1')).toBeVisible();assert.ok(await target.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits desktop');for(const control of await target.locator('[data-tooltip]:visible').all()){await control.scrollIntoViewIfNeeded();await target.mouse.move(0,0);await control.blur();await target.keyboard.press('Escape');await expect(target.getByRole('tooltip')).toBeHidden();await control.evaluate(el=>{const tip=document.querySelector('[role=tooltip]');el.addEventListener('mouseenter',()=>{el.dataset.hoverStarted=String(performance.now());},{once:true});const observer=new MutationObserver(()=>{if(!tip.hidden){el.dataset.hoverDelay=String(performance.now()-Number(el.dataset.hoverStarted));observer.disconnect();}});observer.observe(tip,{attributes:true,attributeFilter:['hidden']});});await control.hover();await expect(target.getByRole('tooltip')).toBeVisible();assert.ok(Number(await control.getAttribute('data-hover-delay'))>=250,'tooltip waits about 300 ms after pointer entry');await target.mouse.move(0,0);await control.focus();assert.equal(await target.getByRole('tooltip').isVisible(),true);await target.keyboard.press('Escape');await control.blur();}for(const theme of ['light','dark']){await target.emulateMedia({colorScheme:theme});for(const width of [1440,390]){await target.setViewportSize({width,height:1000});await target.screenshot({path:join(directory,`recovery-${name}-${width}-${theme}.png`),fullPage:true});}}await target.setViewportSize({width:1440,height:1000});await target.emulateMedia({colorScheme:'light'});};
 await proof('manager-attested',page);
 await helperPage.reload();await helperPage.getByLabel('Reset reason',{exact:true}).fill('Current manager attested employee identity');
 await saved(()=>helperPage.getByRole('button',{name:'Reset verified factors',exact:true}).click(),helperPage);
 assert.equal((await workerContext.request.get(app.origin+'/api/auth/me')).status(),401);
 await proof('helpdesk-reset',helperPage);
 const headers={'x-rer-dev-key':app.vars.RER_DEV_KEY},listing=await(await app.get('/__dev/outbox',headers)).text();
 assert.equal((await app.get('/__dev/outbox')).status,404,'outbox refuses ungated access');
 const bodies=[];for(const match of listing.matchAll(/href="(\/__dev\/outbox\?message=[^"]+)"/g))bodies.push(await(await app.get(match[1].replaceAll('&amp;','&'),headers)).text());
 const notice=bodies.find(body=>body.includes('Auth recovery enrollment link')&&body.includes('erin@northwind.example.com'));assert.ok(notice,'employee enrollment notice reaches gated native outbox');
 assert.ok(bodies.some(body=>body.includes('Auth employee recovery reset')&&body.includes(app.vars.OWNER_EMAIL)&&body.includes(recovery.caseId)),'current manager receives reset notice');
 const href=notice.replaceAll('&amp;','&').match(/http:\/\/[^\s<"]+\/app\/account#caseId=[^\s<"]+/)?.[0];assert.ok(href,'notice has case-bound enrollment link');
 await post('/auth/identity/email/request',{email:'erin@northwind.example.com'},202,workerContext);
 await post('/auth/identity/email/confirm',{token:(await app.link()).searchParams.get('token')},200,workerContext);
 await workerPage.goto(href);await expect(workerPage.getByLabel('Recovery case',{exact:true})).toHaveValue(recovery.caseId);
 await proof('employee-link',workerPage);
 await workerPage.getByRole('button',{name:'Use enrollment link',exact:true}).click();await expect(workerPage).toHaveURL(app.origin+'/app/methods');
 const enrolled=workerPage.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify'));await saved(()=>workerPage.getByRole('button',{name:'Register a passkey',exact:true}).click(),workerPage);assert.equal((await enrolled).status(),200);
 assert.ok(Date.now()-openedAt<3600000,'opening through new passkey finishes within one hour');
 await proof('passkey-enrolled',workerPage);
 // Audit history uses the delegated scope and loses authority between pages.
 const auditScreens=async(name,target)=>{
  for(const width of [1440,390])for(const theme of ['light','dark']) {
   await target.setViewportSize({width,height:1000});await target.emulateMedia({colorScheme:theme});
   await target.evaluate(async()=>{document.body.getBoundingClientRect();await Promise.all(document.getAnimations().filter(a=>a.effect?.getTiming().iterations!==Infinity).map(a=>a.finished.catch(()=>{})));});
   if(width===1440) {
    assert.ok(await target.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits');
    const axe=await new AxeBuilder({page:target}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>({target:n.target,summary:n.failureSummary}))})),[]);
    for(const control of await target.locator('[data-tooltip]:visible').all()) {
     await target.mouse.move(0,0);await target.keyboard.press('Escape');await control.blur();await expect(target.getByRole('tooltip')).toBeHidden();
     await control.evaluate(el=>{
      const tip=document.querySelector('[role=tooltip]');delete el.dataset.auditHoverDelay;
      el.addEventListener('mouseenter',()=>{el.dataset.auditHoverStarted=String(performance.now());},{once:true});
      const observer=new MutationObserver(()=>{if(!tip.hidden){el.dataset.auditHoverDelay=String(performance.now()-Number(el.dataset.auditHoverStarted));observer.disconnect();}});
      observer.observe(tip,{attributes:true,attributeFilter:['hidden']});
     });
     await control.hover();await expect(target.getByRole('tooltip')).toBeVisible();assert.ok(Number(await control.getAttribute('data-audit-hover-delay'))>=250,'tooltip waits about 300 ms after actual pointer entry');
     await target.mouse.move(0,0);await control.focus();assert.equal(await target.getByRole('tooltip').isVisible(),true);await target.keyboard.press('Escape');await control.blur();
    }
   }
   await target.screenshot({path:join(directory,`audit-${name}-${width}-${theme}.png`),fullPage:true});
  }
  await target.setViewportSize({width:1440,height:1000});await target.emulateMedia({colorScheme:'light'});
 };
 const outside=await post('/api/auth/directory/onboard',{name:'Outside Audit Scope',email:'synthetic-auth-33@example.com',kind:'employee'},201);
 await post('/api/auth/groups/add',{groupId:group.id,personId:outside.id});await post('/api/auth/groups/remove',{groupId:group.id,personId:outside.id});
 const scopedMembership=await (await helperContext.request.get(app.origin+'/api/auth/audit?event=group_member_added')).json();assert.equal(scopedMembership.total,1);assert.equal(scopedMembership.events.length,1);
 await helperPage.goto(app.origin+'/app/activity?event=group_member_added');await expect(helperPage.locator('.activity-row')).toHaveCount(1);await expect(helperPage.locator('.table-footer')).toContainText('1 of 1 events');
 await auditScreens('related-target-excluded',helperPage);
 await helperPage.goto(app.origin+'/app/activity?limit=1&person='+worker.id);
 await expect(helperPage.locator('.activity-row')).toHaveCount(1);await expect(helperPage.getByRole('link',{name:'Older events'})).toBeVisible();
 const auditRow=await helperPage.locator('.activity-row').innerText(),older=await helperPage.getByRole('link',{name:'Older events'}).getAttribute('href');
 await auditScreens('scoped-first-page',helperPage);
 const malformed=await helperPage.goto(app.origin+'/app/activity?from='+Date.UTC(2025,9,1,12,30)+'&to=2099-10-27T12:30&event=bad%20event&person='+worker.id);assert.equal(malformed.status(),400);
 await expect(helperPage.getByRole('form',{name:'Filter activity'})).toBeVisible();await expect(helperPage.getByLabel('Event type',{exact:true})).toHaveValue('bad event');await expect(helperPage.getByLabel('Person reference',{exact:true})).toHaveValue(worker.id);await expect(helperPage.getByRole('alert')).toContainText('Check');await expect(helperPage.getByLabel('From (UTC)',{exact:true})).toHaveValue('2025-10-01T12:30');await expect(helperPage.getByLabel('Until (UTC)',{exact:true})).toHaveValue('2099-10-27T12:30');
 await auditScreens('invalid-filter',helperPage);
 await helperPage.getByLabel('Event type',{exact:true}).fill('');await helperPage.getByRole('button',{name:'Filter activity',exact:true}).click();await expect(helperPage.locator('.activity-row').first()).toBeVisible();
 const {createHmac}=await import('node:crypto'),cursor=new URL(older,app.origin).searchParams.get('cursor'),expired=JSON.parse(Buffer.from(cursor.split('.')[0],'base64url').toString());expired.expiresAt=Date.now()-1;
 const body=Buffer.from(JSON.stringify(expired)).toString('base64url'),signature=createHmac('sha256',app.vars.AUTH_ENCRYPTION_KEY).update('auth-audit-v1:'+body).digest('base64url'),expiredUrl=new URL(older,app.origin);expiredUrl.searchParams.set('cursor',body+'.'+signature);
 const ended=await helperPage.goto(expiredUrl.href);assert.equal(ended.status(),410);await expect(helperPage.getByRole('form',{name:'Filter activity'})).toBeVisible();await expect(helperPage.getByRole('alert')).toContainText('expired');await expect(helperPage.getByRole('link',{name:'Newest events',exact:true})).toBeVisible();
 await auditScreens('expired-cursor',helperPage);
 await helperPage.goto(app.origin+'/app/activity?limit=1&person='+worker.id);

 await helperPage.getByRole('link',{name:'Older events'}).click();await expect(helperPage.locator('.activity-row')).toHaveCount(1);assert.notEqual(await helperPage.locator('.activity-row').innerText(),auditRow);
 const roleInventory=await (await context.request.get(app.origin+'/api/auth/roles')).json(),supportGrant=roleInventory.grants.find(g=>g.person_id===helper.id&&g.role_id!=='help-desk'&&g.revoked_at===null);
 const revoke=await post('/api/auth/roles/preview',{kind:'revoke',grantId:supportGrant.id});await post('/api/auth/roles/apply',{previewId:revoke.previewId});
 assert.equal((await helperContext.request.get(app.origin+older)).status(),403);const deniedAudit=await helperPage.reload();assert.equal(deniedAudit.status(),403);await expect(helperPage.locator('.activity-row')).toHaveCount(0);await auditScreens('authority-ended',helperPage);
 await page.goto(app.origin+'/app/permissions');
 const apiForm=page.locator('[data-resource-form=register]');await apiForm.getByLabel('Company app').selectOption(appConfig.id);await apiForm.getByLabel('API name').fill('Documents API');await apiForm.getByLabel('Audience').fill('https://documents.example.com/api');await apiForm.getByLabel('Resource ID',{exact:true}).fill('document:budget');await saved(()=>apiForm.getByRole('button',{name:'Register API'}).click());
 const assignment=page.locator('[data-resource-form=assign]');await assignment.getByLabel('Group').selectOption(group.id);await saved(()=>assignment.getByRole('button',{name:'Assign role to group'}).click());
 const serviceForm=page.locator('[data-resource-form=service-create]');await serviceForm.getByLabel('Service name').fill('Engineering search indexer');await serviceForm.getByLabel('Purpose').fill('Index the approved engineering document catalogue');await serviceForm.getByLabel('Accountable owner').selectOption(worker.id);await serviceForm.getByLabel('Resource IDs, separated by spaces').fill('document:budget');await serviceForm.getByLabel('Expires at').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));await serviceForm.getByLabel('Public signing JWKS').fill(JSON.stringify({keys:[jwk]}));await saved(()=>serviceForm.getByRole('button',{name:'Register service'}).click());await shoot('resource-service');
 const resources=await (await context.request.get(app.origin+'/api/auth/resource-apis')).json(),service=resources.services[0],api=resources.apis[0],now=Math.floor(Date.now()/1000);
 const assertion=await new SignJWT({jti:crypto.randomUUID()}).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(service.clientId).setSubject(service.clientId).setAudience(app.origin+'/oidc/token').setIssuedAt(now).setExpirationTime(now+120).sign(pair.privateKey);
 const issued=await context.request.post(app.origin+'/oidc/token',{form:{grant_type:'client_credentials',client_id:service.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,scope:'read'}});assert.equal(issued.status(),200);const token=(await issued.json()).access_token;
 const decision=await context.request.post(app.origin+'/api/auth/resource-apis/check',{data:{apiId:api.id,action:'read',resource:'document:budget'},headers:{authorization:'Bearer '+token}});assert.equal((await decision.json()).allowed,true);
 await saved(()=>page.getByRole('button',{name:'Revoke service'}).click());await shoot('service-revoked');
 assert.equal((await context.request.post(app.origin+'/api/auth/resource-apis/check',{data:{apiId:api.id,action:'read',resource:'document:budget'},headers:{authorization:'Bearer '+token}})).status(),401);
 await page.goto(app.origin+'/app/erasure');await page.locator('[data-erasure-policy] input').check();await saved(()=>page.getByRole('button',{name:'Confirm erasure policy'}).click());
 const hold=page.locator('[data-erasure-hold]');await hold.locator('[name=target]').selectOption(worker.id);await hold.getByLabel('Reason').fill('Awaiting employment records authorization');await saved(()=>hold.getByRole('button',{name:'Place legal hold'}).click());await shoot('legal-hold');await saved(()=>page.getByRole('button',{name:'Release hold'}).click());
 const erase=page.locator('[data-erasure-preview]:not([data-erasure-kind])');await erase.locator('[name=target]').selectOption(worker.id);await erase.getByRole('button',{name:'Preview erasure'}).click();await expect(erase.locator('[data-erasure-confirm]')).toBeVisible();await shoot('erasure-preview');await erase.getByLabel('Type the confirmation phrase').fill('ERASE');await erase.locator('[name=destinations]').check();await saved(()=>erase.getByRole('button',{name:'Confirm erasure'}).click());
 await expect(page.getByRole('heading',{name:'person erasure · remote_unfinished'})).toBeVisible();await page.getByText('Per-store completion and remote removal').click();await shoot('erasure-receipt');
 const receipt=(await (await context.request.get(app.origin+'/api/auth/erasure/receipts')).json()).receipts.find(r=>r.kind==='person');
 await page.goto(app.origin+'/app/activity?event=person_onboarded');
 await expect(page.locator('.activity-row',{hasText:receipt.reference})).toBeVisible();
 const erasedActivity=await page.locator('.activity-table').innerText();assert.ok(!erasedActivity.includes('Erin Park'));assert.ok(!erasedActivity.includes('erin@northwind.example.com'));
 await auditScreens('erased-subject',page);
 const historicalPreview=await post('/api/auth/erasure/preview',{kind:'person',target:historicalPerson.id});
 const historicalReceipt=await post('/api/auth/erasure/confirm',{previewId:historicalPreview.id,confirmation:'ERASE',destinations:[]});
 await app.pause();await app.resume();
 const historicalAudit=await (await context.request.get(app.origin+'/api/auth/audit?event=person_invited')).json();assert.equal(historicalAudit.total,1);assert.equal(historicalAudit.events[0].subject_id,historicalReceipt.reference);
 for(const personal of ['Historical Invitation','synthetic-auth-30@example.com','synthetic-auth-31@example.com','synthetic-auth-32@example.com',historicalPerson.id])assert.ok(!JSON.stringify(historicalAudit).includes(personal));
 await page.goto(app.origin+'/app/activity?event=person_invited');await expect(page.locator('.activity-row')).toHaveCount(1);await expect(page.locator('.activity-row')).toContainText(historicalReceipt.reference);
 await auditScreens('erased-historical-invitation',page);

 await page.goto(app.origin+'/app/erasure');
 const retry=page.locator('[data-erasure-retry]');await retry.locator('[name=destinations]').check();await saved(()=>retry.getByRole('button',{name:'Retry remote removal'}).click());await expect(page.getByRole('heading',{name:'person erasure · remote_unfinished'})).toBeVisible();
 const subsidiaryApp=await post(prefix+'/api/auth/company-apps/create',{name:'Subsidiary records',entityId:'https://subsidiary-records.example.com',acsUrl:'https://subsidiary-records.example.com/acs'},201);assert.ok(subsidiaryApp.id);
 await post(prefix+'/api/auth/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 // The employer owner authorizes downstream deletion before the separate
 // installation-owner reset. Only this employer door shows the destination.
 await page.goto(app.origin+prefix+'/app/erasure');
 const consent=page.locator('[data-reset-consent]');await consent.getByRole('button',{name:'Preview deletion consent'}).click();
 await expect(consent.locator('[data-erasure-confirm]')).toBeVisible();await expect(consent.locator('[data-erasure-destinations]')).toContainText('https://subsidiary-records.example.com');await shoot('consent-preview');
 await consent.locator('[name=destinations]').check();await consent.getByLabel('Type the confirmation phrase').fill('AUTHORIZE DELETION');await saved(()=>consent.getByRole('button',{name:'Authorize selected deletion'}).click());
 await page.goto(app.origin+'/app/erasure');
 const reset=page.locator('[data-erasure-preview][data-erasure-kind=organization]:not([data-reset-consent])');await expect(reset).toBeVisible();await shoot('reset-ready');await reset.locator('[name=target]').selectOption(prefix.split('/')[2]);const rootPreviewResponse=page.waitForResponse(response=>response.url().endsWith('/api/auth/erasure/preview'));await reset.getByRole('button',{name:'Preview organization reset'}).click();
 const rootPreview=await rootPreviewResponse;assert.equal(rootPreview.status(),200);const resetPlan=await rootPreview.json();assert.ok(resetPlan.remote.every(task=>!Object.hasOwn(task,'partner')));assert.ok(resetPlan.remote.some(task=>task.app==='Subsidiary records'&&task.deletionPreauthorized===true));
 await expect(reset.locator('[data-erasure-confirm]')).toBeVisible();await expect(reset.locator('[data-erasure-summary]')).toContainText('RESET '+app.origin+prefix);
 await expect(reset.locator('[data-erasure-destinations]')).toContainText('Subsidiary records');await expect(reset.locator('[data-erasure-destinations]')).not.toContainText('https://subsidiary-records.example.com');await expect(reset.locator('[name=destinations]')).toHaveCount(0);await shoot('reset-preview');
 await reset.getByLabel('Type the confirmation phrase').fill('RESET '+app.origin+prefix);await saved(()=>reset.getByRole('button',{name:'Confirm organization reset'}).click());
 assert.equal((await context.request.get(app.origin+prefix+'/.well-known/openid-configuration')).status(),404);
 await page.goto(app.origin+'/app/erasure');const retained=page.locator('article').filter({has:page.getByRole('heading',{name:'organization erasure · remote_unfinished'})});await expect(retained.getByText('Retained after organization reset')).toBeVisible();await retained.getByText('Per-store completion and remote removal').click();await shoot('erased-organization-receipt');
 await expect(retained).toContainText('Subsidiary records');await expect(retained).not.toContainText('https://subsidiary-records.example.com');await expect(retained.locator('[name=organizationId]')).toHaveCount(0);
 const retainedModel=(await (await context.request.get(app.origin+'/api/auth/erasure/receipts')).json()).receipts.find(receipt=>receipt.retained&&receipt.kind==='organization');assert.ok(retainedModel);assert.ok(!Object.hasOwn(retainedModel,'organizationId'));assert.ok(retainedModel.remote.every(work=>!Object.hasOwn(work,'partner')));
 const retainedRetry=retained.locator('[data-erasure-retry]');await expect(retainedRetry).toHaveCount(1);await expect(retainedRetry.locator('[name=destinations]')).toHaveCount(0);const workId=await retainedRetry.locator('[name=workId]').inputValue();await retainedRetry.locator('[name=confirmRetry]').check();await saved(()=>retainedRetry.getByRole('button',{name:'Retry remote removal'}).click());
 const retried=(await (await context.request.get(app.origin+'/api/auth/erasure/receipts')).json()).receipts.find(receipt=>receipt.id===retainedModel.id).remote.find(work=>work.id===workId);assert.equal(retried.kind,'partner-delete');assert.equal(retried.state,'blocked');
 const abandoned=page.locator('article').filter({has:page.getByRole('heading',{name:'organization erasure · remote_unfinished'})});await abandoned.getByText('Abandon unfinished remote work',{exact:true}).click();const abandon=abandoned.locator('[data-erasure-abandon]');await abandon.locator('[name=workIds]').check();await abandon.getByLabel('Type ABANDON').fill('ABANDON');await saved(()=>abandon.getByRole('button',{name:'Abandon selected remote work'}).click());await expect(page.getByRole('heading',{name:'organization erasure · remote_abandoned'})).toBeVisible();await shoot('remote-abandoned');
 assert.ok(!(await (await context.request.get(app.origin+'/api/auth/people')).json()).some(p=>p.email==='erin@northwind.example.com'));assert.deepEqual(errors,[]);
});

import {accessReviewJourney} from './helpers/access-review-journey.mjs';
test('access decision and review journey: ordinary manager proof, request approval, immutable certification and unfinished removal, and retention controls at 1440 and 390',{timeout:180000},accessReviewJourney);

test('identity release journey: two independent passkeys, private administration, opaque employer follow-up and erasure contact at 1440 and 390',{timeout:420000},identityPairsJourney);
