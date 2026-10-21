import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';

const views=[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']];

test('directory journey: an administrator onboards a worker, edits and bulk-moves people with a preview, sets a group rule, terminates and rehires, at desktop/mobile in both themes',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),primary=page;
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const shoot=async (name,page=primary)=>{for(const [width,theme] of views){
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await page.reload();
  await expect(page.locator('h1')).toBeVisible();
  const results=await new AxeBuilder({page}).analyze();
  assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],`${width} ${theme} ${name}`);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
  await page.screenshot({path:join(directory,`directory-${name}-${width}-${theme}.png`),fullPage:true});
 }await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});};
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
 assert.deepEqual(errors,[]);
});

test('organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const hardware=async(context,page)=>{const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});page.on('dialog',dialog=>dialog.accept());};
 await hardware(context,page);
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const saved=async(action,target=page)=>{const loaded=target.waitForEvent('load');await action();await loaded;};
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
   assert.ok(await target.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits '+width);
   const axe=await new AxeBuilder({page:target}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],name+' '+width);
   await target.screenshot({path:join(directory,`authority-${name}-${width}.png`),fullPage:true});
  }await target.setViewportSize({width:1440,height:1000});
 };
 await signIn(page,app.vars.OWNER_EMAIL,'',true);
 await page.goto(app.origin+'/app/organizations');await page.getByLabel('Organization name').fill('Northwind Manufacturing');await page.getByRole('button',{name:'Create organization',exact:true}).click();
 const newOrg=page.getByRole('link',{name:'Sign in to Northwind Manufacturing and enroll its passkey'});await expect(newOrg).toBeVisible();
 const prefix=new URL(await newOrg.getAttribute('href'),app.origin).pathname.replace('/signin','');
 await shoot('organization-created');await signIn(page,app.vars.OWNER_EMAIL,prefix);
 await page.goto(app.origin+prefix+'/app/organizations');await expect(page.getByText('owner · Active organization',{exact:true})).toBeVisible();await shoot('organization-memberships');
 await page.getByRole('button',{name:'Switch to Installation'}).click();await expect(page).toHaveURL(app.origin+'/app/account');
 const worker=await post('/api/auth/directory/onboard',{name:'Erin Park',email:'erin@northwind.example.com',kind:'employee',set:{department:'Engineering',location:'US'}},201);
 const helper=await post('/api/auth/directory/onboard',{name:'Sam Rivera',email:'sam@northwind.example.com',kind:'employee',set:{department:'Support',location:'US'}},201);
 const workerContext=await browser.newContext(),workerPage=await workerContext.newPage();await hardware(workerContext,workerPage);await signIn(workerPage,'erin@northwind.example.com');
 const helperContext=await browser.newContext(),helperPage=await helperContext.newPage();await hardware(helperContext,helperPage);await signIn(helperPage,'sam@northwind.example.com');
 const group=await post('/api/auth/groups/create',{name:'US engineering staff'},201);await post('/api/auth/groups/add',{groupId:group.id,personId:worker.id});
 const appConfig=await post('/api/auth/company-apps/create',{name:'Engineering documents',entityId:'https://documents.example.com',acsUrl:'https://documents.example.com/acs'},201);
 await page.goto(app.origin+'/app/roles');
 const definition=page.locator('[data-role-form=role]');await definition.getByLabel('Role name').fill('Engineering support');
 for(const id of ['roles.view','people.view','people.factors.reset','groups.view'])await definition.locator(`input[value="${id}"]`).check();
 await definition.getByRole('button',{name:'Preview role'}).click();await expect(definition.locator('[data-role-apply]')).toBeVisible();await shoot('role-preview');await saved(()=>definition.locator('[data-role-apply]').click());
 const grant=page.locator('[data-role-form=grant]');await grant.getByLabel('Role holder').selectOption(helper.id);await grant.getByLabel('Role',{exact:true}).selectOption({label:'Engineering support'});
 await grant.locator('[name="view.groups"]').selectOption(group.id);await grant.locator('[name="edit.groups"]').selectOption(group.id);
 await grant.getByRole('button',{name:'Preview delegation'}).click();await expect(grant.locator('[data-role-preview]')).toContainText('sam@northwind.example.com');await shoot('delegation-preview');await saved(()=>grant.locator('[data-role-apply]').click());
 await helperPage.goto(app.origin+'/app/roles');await expect(helperPage.getByRole('heading',{name:'Scoped factor resets'})).toBeVisible();await shoot('scoped-help-desk',helperPage);
 await helperPage.getByLabel('Verification and reason').fill('Employee confirmed the request with the support desk');await saved(()=>helperPage.getByRole('button',{name:'Reset factors'}).click(),helperPage);assert.equal((await workerContext.request.get(app.origin+'/api/auth/me')).status(),401);
 await page.goto(app.origin+'/app/permissions');
 const apiForm=page.locator('[data-resource-form=register]');await apiForm.getByLabel('Company app').selectOption(appConfig.id);await apiForm.getByLabel('API name').fill('Documents API');await apiForm.getByLabel('Audience').fill('https://documents.example.com/api');await apiForm.getByLabel('Resource ID',{exact:true}).fill('document:budget');await saved(()=>apiForm.getByRole('button',{name:'Register API'}).click());
 const assignment=page.locator('[data-resource-form=assign]');await assignment.getByLabel('Group').selectOption(group.id);await saved(()=>assignment.getByRole('button',{name:'Assign role to group'}).click());
 const {generateKeyPair,exportJWK,SignJWT}=await import('jose'),pair=await generateKeyPair('ES256'),jwk={...await exportJWK(pair.publicKey),kid:'synthetic-auth-5',alg:'ES256',use:'sig'};
 const serviceForm=page.locator('[data-resource-form=service-create]');await serviceForm.getByLabel('Service name').fill('Engineering search indexer');await serviceForm.getByLabel('Purpose').fill('Index the approved engineering document catalogue');await serviceForm.getByLabel('Accountable owner').selectOption(worker.id);await serviceForm.getByLabel('Resource IDs, separated by spaces').fill('document:budget');await serviceForm.getByLabel('Expires at').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));await serviceForm.getByLabel('Public signing JWKS').fill(JSON.stringify({keys:[jwk]}));await saved(()=>serviceForm.getByRole('button',{name:'Register service'}).click());await shoot('resource-service');
 const resources=await (await context.request.get(app.origin+'/api/auth/resource-apis')).json(),service=resources.services[0],api=resources.apis[0],now=Math.floor(Date.now()/1000);
 const assertion=await new SignJWT({jti:crypto.randomUUID()}).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(service.clientId).setSubject(service.clientId).setAudience(app.origin+'/oidc/token').setIssuedAt(now).setExpirationTime(now+120).sign(pair.privateKey);
 const issued=await context.request.post(app.origin+'/oidc/token',{form:{grant_type:'client_credentials',client_id:service.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion,scope:'read'}});assert.equal(issued.status(),200);const token=(await issued.json()).access_token;
 const decision=await context.request.post(app.origin+'/api/auth/resource-apis/check',{data:{apiId:api.id,action:'read',resource:'document:budget'},headers:{authorization:'Bearer '+token}});assert.equal((await decision.json()).allowed,true);
 await saved(()=>page.getByRole('button',{name:'Revoke service'}).click());await shoot('service-revoked');
 assert.equal((await context.request.post(app.origin+'/api/auth/resource-apis/check',{data:{apiId:api.id,action:'read',resource:'document:budget'},headers:{authorization:'Bearer '+token}})).status(),401);
 await page.goto(app.origin+'/app/erasure');await page.locator('[data-erasure-policy] input').check();await saved(()=>page.getByRole('button',{name:'Confirm erasure policy'}).click());
 const hold=page.locator('[data-erasure-hold]');await hold.getByLabel('Person',{exact:true}).selectOption(worker.id);await hold.getByLabel('Reason').fill('Awaiting employment records authorization');await saved(()=>hold.getByRole('button',{name:'Place legal hold'}).click());await shoot('legal-hold');await saved(()=>page.getByRole('button',{name:'Release hold'}).click());
 const erase=page.locator('[data-erasure-preview]');await erase.getByLabel('Person',{exact:true}).selectOption(worker.id);await erase.getByRole('button',{name:'Preview erasure'}).click();await expect(erase.locator('[data-erasure-confirm]')).toBeVisible();await shoot('erasure-preview');await erase.getByLabel('Type the confirmation phrase').fill('ERASE');await erase.getByLabel('Authorize the listed remote deletion and revocation calls.').check();await saved(()=>erase.getByRole('button',{name:'Confirm erasure'}).click());
 await expect(page.getByRole('heading',{name:'person erasure · remote_unfinished'})).toBeVisible();await page.getByText('Per-store completion and remote removal').click();await shoot('erasure-receipt');
 assert.ok(!(await (await context.request.get(app.origin+'/api/auth/people')).json()).some(p=>p.email==='erin@northwind.example.com'));assert.deepEqual(errors,[]);
});
