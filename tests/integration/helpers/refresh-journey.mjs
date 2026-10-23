import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from '../runtime.mjs';
import {createSessionClient} from '../../../packages/session-sdk/index.mjs';

export async function refreshJourney(t) {
 const app=await openApp();let browser;t.after(async()=>{await browser?.close();await app.close();});await app.claim();
 browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});
 const root=await browser.newContext({viewport:{width:1440,height:1000}}),owner=await root.newPage(),directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const errors=[];owner.on('pageerror',e=>errors.push(e.message));owner.on('dialog',dialog=>dialog.accept());
 const cdp=await root.newCDPSession(owner);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const post=async(context,path,data,status=200)=>{const response=await context.request.post(app.origin+'/api/auth/'+path,{data,headers:{origin:app.origin}});assert.equal(response.status(),status,path+' '+await response.text());return response.json();};
 const saved=async(page,action)=>{const loaded=page.waitForEvent('load');await action();await loaded;};
 const shoot=async(name,page,prepare=async()=>{})=>{for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});await page.reload();await prepare();
  await expect(page.locator('h1')).toBeVisible();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits '+width);
  const axe=await new AxeBuilder({page}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],name+' '+width);
  await page.screenshot({path:join(directory,`refresh-${name}-${width}.png`),fullPage:true});
  await page.locator('#offline-grants').screenshot({path:join(directory,`refresh-${name}-panel-${width}.png`)});
 }await page.setViewportSize({width:1440,height:1000});};
 await owner.goto(app.origin+'/signin?returnTo=%2Fsetup');await owner.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await owner.getByRole('button',{name:'Email me a sign-in link'}).click();
 await owner.goto((await app.link()).href);await owner.getByRole('button',{name:'Continue to Auth'}).click();await expect(owner).toHaveURL(app.origin+'/setup');await owner.getByRole('checkbox').check();await owner.getByRole('button',{name:'Finish setup'}).click();
 await owner.goto(app.origin+'/app/methods');const enrolled=owner.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify'));await saved(owner,()=>owner.getByRole('button',{name:'Register a passkey'}).click());assert.equal((await enrolled).status(),200);
 const signing=await post(root,'keys/stage',{alg:'ES256'},201);
 const employee=await post(root,'directory/onboard',{email:'erin@northwind.example.com',name:'Erin Park',kind:'employee',set:{department:'Field engineering'}},201);
 const native=await post(root,'oidc-apps/create',{name:'Northwind field documents',authMethod:'none',idTokenAlg:'ES256',redirectUris:'https://field.example.com/callback'},201);
 const api=await post(root,'resource-apis/register',{appId:native.id,name:'Field documents API',audience:'https://field.example.com/documents',scopes:['read','write'],roles:[{role:'reader',scopes:['read'],resources:['document:*']}],resources:[{id:'document:budget'}]},201);
 await post(root,'resource-apis/assign',{apiId:api.id,principalType:'person',principalId:employee.id,role:'reader'});
 await owner.goto(app.origin+'/app/account');await owner.getByText('Manage offline profiles',{exact:true}).click();
 const settings=owner.locator('form[action="/api/auth/refresh/profile"]');await settings.getByLabel('Registered OIDC app').selectOption(native.clientId);await settings.getByLabel('Resource API').selectOption(api.id);await settings.getByLabel('Allowed API scopes').fill('read');await settings.getByLabel('Idle lifetime (hours)',{exact:true}).fill('8');await settings.getByLabel('Absolute lifetime (hours)',{exact:true}).fill('168');
 await saved(owner,()=>settings.getByRole('button',{name:'Publish offline profile'}).click());
 await shoot('profile-published',owner,async()=>owner.getByText('Manage offline profiles',{exact:true}).click());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();page.on('dialog',dialog=>dialog.accept());page.on('pageerror',e=>errors.push(e.message));
 await page.goto(app.origin+'/signin?returnTo=%2Fapp%2Faccount');await page.getByLabel('Email address',{exact:true}).fill('erin@northwind.example.com');await page.getByRole('button',{name:'Email me a sign-in link'}).click();await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/app/account');
 const sdk=await createSessionClient({issuer:app.origin,clientId:native.clientId,redirectUri:'https://field.example.com/callback'});
 const authorization=await sdk.authorization({resource:'https://field.example.com/documents',scopes:['read'],deviceName:'Erin’s managed iPad · Field engineering'});
 await page.goto(authorization.url);await expect(page.getByRole('heading',{name:'Allow Northwind field documents offline access?'})).toBeVisible();await shoot('consent',page);
 // A fresh install must publish its signing key for a full cache lifetime.
 // Use the public staging deadline, without editing clocks or private storage.
 const remaining=signing.useAfter-Date.now()+25;if(remaining>0){console.log('Waiting for the fresh signing key publication deadline');await new Promise(done=>setTimeout(done,remaining));}
 await page.route('https://field.example.com/callback*',route=>route.fulfill({contentType:'text/html',body:'<!doctype html><title>Field documents</title><p>Return received</p>'}));
 const callback=page.waitForURL('https://field.example.com/callback*');await page.getByRole('button',{name:'Allow offline access'}).click();await callback;
 const tokens=await sdk.complete(page.url());assert.equal((await sdk.resourceRequest('/api/auth/resource-apis/check',{apiId:api.id,action:'read',resource:'document:budget'})).allowed,true);
 await page.goto(app.origin+'/app/account');await expect(page.getByRole('button',{name:'Revoke Erin’s managed iPad · Field engineering',exact:true})).toBeVisible();await shoot('active-device',page);
 // Every icon-only control on this screen has a short tooltip. Hover waits;
 // keyboard focus exposes it immediately, at both supported widths.
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});await page.reload();
  const icon=page.locator('[data-theme-toggle]:visible').first();await icon.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();await page.waitForTimeout(200);await expect(page.getByRole('tooltip')).toHaveText('Color theme');
  await page.mouse.move(0,0);await icon.focus();await expect(page.getByRole('tooltip')).toHaveText('Color theme');await page.screenshot({path:join(directory,`refresh-keyboard-tooltip-${width}.png`)});
  await page.keyboard.press('Escape');await expect(page.getByRole('tooltip')).toBeHidden();
 }
 await owner.goto(app.origin+'/app/account?refreshAdmin=1');await expect(owner.getByRole('button',{name:'Revoke Erin’s managed iPad · Field engineering',exact:true})).toBeVisible();await shoot('administrator-inventory',owner);
 await saved(page,()=>page.getByRole('button',{name:'Revoke Erin’s managed iPad · Field engineering',exact:true}).click());await expect(page.getByRole('button',{name:'Revoke Erin’s managed iPad · Field engineering',exact:true})).toHaveCount(0);await shoot('employee-revoked',page);
 await assert.rejects(sdk.refresh());assert.equal(sdk.getTokens(),null);
 await owner.goto(app.origin+'/app/account');await owner.getByText('Manage offline profiles',{exact:true}).click();await saved(owner,()=>owner.getByRole('button',{name:'Disable Northwind field documents',exact:true}).click());await shoot('profile-disabled',owner,async()=>owner.getByText('Manage offline profiles',{exact:true}).click());
 assert.ok(tokens.grant_id);assert.deepEqual(errors,[]);
}
