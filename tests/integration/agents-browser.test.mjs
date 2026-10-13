import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';

const views=[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']];
const LEAVER='leaver@northwind.example.com';

test('agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const accessible=async label=>{const results=await new AxeBuilder({page}).analyze();assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],label);};
 const shoot=async name=>{for(const [width,theme] of views){
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await page.reload();
  await expect(page.locator('h1')).toBeVisible();await accessible(`${width} ${theme} ${name}`);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
  await page.screenshot({path:join(directory,`agents-${name}-${width}-${theme}.png`),fullPage:true});
 }await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});};

 // First owner: browser email link, setup, hardware passkey.
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);await page.waitForTimeout(500);

 // A person who has since left, signed in from their own browser.
 assert.equal((await context.request.post(app.origin+'/api/auth/people/invite',{data:{email:LEAVER,name:'Lee Leaver'},headers:{origin:app.origin}})).status(),201);
 const leaver=await browser.newContext();
 assert.equal((await leaver.request.post(app.origin+'/auth/identity/email/request',{data:{email:LEAVER},headers:{origin:app.origin}})).status(),202);
 const link=await app.link();assert.equal((await leaver.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:link.searchParams.get('token')},headers:{origin:app.origin}})).status(),200);
 assert.equal((await leaver.request.get(app.origin+'/api/auth/me')).status(),200);

 // Mint a key on the Agents page; it is shown once.
 await page.goto(app.origin+'/app/people');await page.getByRole('link',{name:'Agents'}).click();await expect(page).toHaveURL(app.origin+'/app/agents');
 await shoot('empty');
 await page.getByLabel('Key label').fill('Directory review agent');await page.getByRole('button',{name:'Mint a key'}).click();
 const secret=page.locator('[data-agent-secret-value]');await expect(secret).toBeVisible();
 const key=await secret.inputValue();assert.match(key,/^authprep_/);
 await page.reload();await expect(page.locator('[data-agent-secret]')).toBeHidden();
 assert.ok(!(await page.content()).includes(key),'the page never shows the key again');
 await expect(page.locator('[data-agent-key="Directory review agent"]')).toBeVisible();

 // The agent: inventory, then a suspension for the person who left.
 const agent=(method,data)=>fetch(app.origin+'/api/auth/preparer',{method,headers:{authorization:'Preparer '+key,...(data?{'content-type':'application/json'}:{})},body:data&&JSON.stringify(data)});
 const inventory=await(await agent('GET')).json();assert.equal(inventory.people.find(p=>p.email===LEAVER).state,'active');
 const filed=await agent('POST',{kind:'suspend_person',target:LEAVER,reason:'Left Northwind on 10 October'});assert.equal(filed.status,201);
 const {id}=await filed.json();
 assert.equal((await leaver.request.get(app.origin+'/api/auth/me')).status(),200,'filing changes nothing');

 // A person reviews the stored and current effect, then approves with a passkey.
 await page.reload();await expect(page.locator(`[data-proposal-row="${id}"] [data-proposal-status=pending]`)).toBeVisible();
 await shoot('pending');
 await page.locator(`[data-proposal-row="${id}"]`).getByRole('link',{name:/Review/}).click();await expect(page).toHaveURL(`${app.origin}/app/agents?proposal=${id}`);
 await expect(page.getByRole('heading',{name:'When filed'})).toBeVisible();await expect(page.getByRole('heading',{name:'Now'})).toBeVisible();
 await expect(page.locator('.agent-reason',{hasText:'Left Northwind on 10 October'})).toBeVisible();
 await shoot('review');
 const approved=page.waitForResponse(response=>response.url().endsWith('/api/auth/agents/approve'));
 await page.getByRole('button',{name:'Approve with passkey'}).click();assert.equal((await approved).status(),200);
 await expect(page.locator('[data-proposal-outcome] [data-proposal-status=done]')).toBeVisible();
 await shoot('approved');
 assert.equal((await leaver.request.get(app.origin+'/api/auth/me')).status(),401,'the person who left is signed out');
 const decided=(await(await agent('GET')).json()).proposals.find(p=>p.id===id);assert.equal(decided.status,'done');
 await leaver.close();

 await page.goto(app.origin+'/app/activity');
 await expect(page.locator('[data-activity-detail]',{hasText:'Directory review agent'}).first()).toBeVisible();
 await expect(page.getByText('Agent Proposal Done')).toBeVisible();
 await shoot('activity');
 assert.ok(!(await page.content()).includes(key),'Activity never shows the key');
 assert.deepEqual(errors,[],'no browser runtime errors');
});
