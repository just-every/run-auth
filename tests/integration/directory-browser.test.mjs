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
