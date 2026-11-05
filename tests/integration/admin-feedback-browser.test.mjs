import {test} from 'node:test';
import assert from 'node:assert/strict';
import {chromium,expect} from '@playwright/test';
import {openApp} from './runtime.mjs';

// One administration flow, through the emitted application and real D1/outbox.
// Assert at phone width: long member addresses must fit the actual controls.
test('administration saves refresh lists, decisions name resources, identifiers stay secondary and times name their zone',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,executablePath:process.env.AUTH_CHROMIUM||undefined,args:['--no-sandbox']});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:390,height:1000},timezoneId:'Australia/Brisbane'}),page=await context.newPage();
 const errors=[];page.on('pageerror',error=>errors.push(error.message));page.on('dialog',dialog=>dialog.accept());
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const post=async(path,data,status=200)=>{const response=await context.request.post(app.origin+'/api/auth/'+path,{data,headers:{origin:app.origin}});assert.equal(response.status(),status);return response.json();};
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);
 await expect(page.locator('.data-row').filter({hasText:'Passkey 1'}).locator('.data-meta').first()).toContainText('UTC');

 const address='dispatch.operations.supervisor@northwind.example.com';
 await post('people/invite',{email:address,name:'Grace Hopper'},201);
 const employee=await browser.newContext();t.after(()=>employee.close());
 await employee.request.post(app.origin+'/auth/identity/email/request',{data:{email:address},headers:{origin:app.origin}});
 await employee.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:(await app.link()).searchParams.get('token')},headers:{origin:app.origin}});
 const people=await(await context.request.get(app.origin+'/api/auth/people')).json(),grace=people.find(person=>person.email===address);
 const group=await post('groups/create',{name:'Dispatch team'},201);await post('groups/add',{groupId:group.id,email:address});
 await page.goto(app.origin+'/app/apps');
 let loads=0;page.on('load',()=>loads++);
 await page.getByLabel('App name',{exact:true}).fill('Kestrel Dispatch');await page.getByLabel('Redirect URIs (one per line)',{exact:true}).fill('https://dispatch.example.com/callback');
 await page.locator('form[action="/api/auth/oidc-apps/create"]').getByRole('button',{name:'Add app',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Kestrel Dispatch',exact:true})).toBeVisible();
 await expect(page.locator('[data-auth-status]').first()).toContainText('Client secret, shown once');assert.equal(loads,0,'creation refreshes the list without losing the one-time secret');
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),390);
 const remove=page.getByRole('button',{name:'Remove '+address,exact:true});await expect(remove).toBeVisible();
 assert.ok(await remove.evaluate(button=>button.scrollWidth<=button.clientWidth),'the member removal label fits its button');
 for(const [address,reason] of [['https://example.com','not allowed for app linking'],['http://localhost:1','could not read the app’s link document']]){
  await page.locator('#app-origin').fill(address);const checked=page.waitForResponse(response=>response.url().endsWith('/api/auth/apps/request'));await page.getByRole('button',{name:'Check app',exact:true}).click();assert.ok([400,502].includes((await checked).status()));
  await expect(page.locator('[data-auth-status]').first()).toContainText(reason);
 }

 await page.goto(app.origin+'/app/roles');const role=page.locator('[data-role-form=role]');
 await role.getByLabel('Role name').fill('Dispatch supervisor');await role.getByText('Choose permissions',{exact:true}).click();
 for(const permission of ['roles.view','people.view','groups.edit'])await role.locator(`[name=permissions][value="${permission}"]`).check();
 await role.getByRole('button',{name:'Preview role',exact:true}).click();await expect(role.locator('[data-role-apply]')).toBeVisible();
 await role.locator('[data-role-apply]').click();const grant=page.locator('[data-role-form=grant]');
 await expect(grant.locator('[name=roleId] option').filter({hasText:'Dispatch supervisor'})).toHaveCount(1);
 await expect(page.locator('[data-auth-status]').first()).toContainText('Custom role saved');
 await grant.locator('[name=personId]').selectOption(grace.id);await grant.locator('[name=roleId]').selectOption({label:'Dispatch supervisor'});
 await grant.locator('[name="view.people"]').selectOption(grace.id);await grant.locator('[name="view.groups"]').selectOption(group.id);await grant.locator('[name="edit.groups"]').selectOption(group.id);
 await grant.getByRole('button',{name:'Preview delegation',exact:true}).click();await expect(grant.locator('[data-role-apply]')).toBeVisible();
 const preview=grant.locator('[data-role-preview]');await expect(preview).toContainText('Grace Hopper');await expect(preview).toContainText('Add or remove group members within edit resources · Dispatch team');
 for(const internal of [grace.id,group.id,'Person ID','groups.edit'])await expect(preview).not.toContainText(internal);
 await grant.locator('[data-role-apply]').click();await expect(page.locator('[data-auth-status]').first()).toContainText('Role delegated');
 await expect(page.getByRole('heading',{name:'Role grants',exact:true}).locator('xpath=ancestor::section[1]')).toContainText('Dispatch supervisor');

 await page.goto(app.origin+'/app/agents');await page.getByLabel('Key label').fill('Dispatch preparer');await page.getByRole('button',{name:'Mint a key',exact:true}).click();
 await expect(page.locator('[data-agent-key="Dispatch preparer"]')).toBeVisible();await expect(page.locator('[data-agent-secret-value]')).toHaveValue(/^authprep_/);
 await expect(page.locator('[data-auth-status]').first()).toContainText('Copy it now');await expect(page.locator('[data-auth-status]').first()).not.toContainText('Reload');
 const minted=await page.locator('[data-agent-secret-value]').inputValue();await page.reload();assert.ok(!(await page.content()).includes(minted),'refresh never re-exposes a preparer key');

 await page.goto(app.origin+'/app/move-in');const sourceId=crypto.randomUUID();
 await page.getByLabel('Export file').setInputFiles({name:'entra.csv',mimeType:'text/csv',buffer:Buffer.from(`objectId,displayName,userPrincipalName,accountEnabled\n${sourceId},Entra Person,entra@northwind.example.com,true`)});
 await page.getByRole('button',{name:'Stage file',exact:true}).click();await expect(page).toHaveURL(/batch=/);
 const row=page.locator('[data-move-in-row]').first();await expect(row).toContainText('Entra Person');assert.ok(!(await row.innerText()).includes(sourceId));
 await row.getByText('Source identifier',{exact:true}).click();await expect(row.locator('details')).toContainText(sourceId);await row.getByText('Source identifier',{exact:true}).click();

 await page.goto(app.origin+'/app/activity');const table=page.locator('.activity-table');
 await expect(table).toContainText('App: Kestrel Dispatch');await expect(table).toContainText('Group: Dispatch team');await expect(table).toContainText('Grace Hopper');await expect(table).toContainText('Preparer key: Dispatch preparer');await expect(table).toContainText('Move-in export: entra.csv');
 assert.ok(!(await table.innerText()).includes('root:activity:'),'event references stay outside the primary history');
 for(const time of await table.locator('time').all())await expect(time).toContainText('UTC');
 await table.getByText('Technical details',{exact:true}).first().click();await expect(table.locator('details').first()).toContainText('root:activity:');
 assert.deepEqual(errors,[]);
});
