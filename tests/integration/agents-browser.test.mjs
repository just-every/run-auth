import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';
import {followupJourney} from './helpers/followup-journey.mjs';
import {followupRolesJourney} from './helpers/followup-roles-journey.mjs';
import {delegatedAssignmentJourney} from './helpers/delegation-journey.mjs';
import {captureViews} from './helpers/capture-views.mjs';

import {diagnosticJourney} from './helpers/diagnostic-journey.mjs';
test('sign-in repair journey: owner snapshot consent, cited exact diff, passkey approval, employee callback and uncertainty at 1440 and 390',diagnosticJourney);

const views=[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']];
const LEAVER='leaver@northwind.example.com';

test('agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),primary=page;
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const accessible=async (label,target=primary)=>{const results=await new AxeBuilder({page:target}).analyze();assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],label);};
 const shoot=async (name,page=primary,prepare=async()=>{})=>captureViews({page,views,errors,prepare,capture:async(page,width,theme)=>{
  await expect(page.locator('h1')).toBeVisible();await accessible(`${width} ${theme} ${name}`,page);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
  await page.screenshot({path:join(directory,`agents-${name}-${width}-${theme}.png`),fullPage:true});
  if(name.startsWith('followup'))await page.locator('[data-followup-panel]').screenshot({path:join(directory,`agents-${name}-${width}-${theme}-panel.png`)});
 }});

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

 // A separate machine credential is created on the same page. The service
 // owns its private key; the browser sends only the public verification key.
 const serviceKeys=await generateKeyPair('ES256'),serviceJwk={...await exportJWK(serviceKeys.publicKey),kid:'reconciler',alg:'ES256',use:'sig'};
 await page.getByLabel('App name',{exact:true}).fill('Northwind access reconciler');
 await page.getByLabel('Purpose',{exact:true}).fill('Maintain approved company groups and application assignments');
 await page.getByLabel('Public signing keys (JWKS JSON)').fill(JSON.stringify({keys:[serviceJwk]}));
 await page.locator('[data-admin-service-create] input[value="groups.manage"]').check();
 await page.getByLabel('Expires (your local time)').fill(new Date(Date.now()+7*86400000).toISOString().slice(0,16));
 const createdService=page.waitForResponse(response=>response.url().endsWith('/api/auth/admin-service-apps/create'));
 await page.getByRole('button',{name:'Create service app',exact:true}).click();
 const serviceResponse=await createdService;assert.equal(serviceResponse.status(),201,await serviceResponse.text());const service=await serviceResponse.json();
 const serviceCard=page.locator(`[data-admin-service="${service.id}"]`);await expect(serviceCard).toContainText('Active');await expect(serviceCard).toContainText(service.clientId);
 await shoot('service-active');
 const now=Math.floor(Date.now()/1000),clientAssertion=await new SignJWT({}).setProtectedHeader({alg:'ES256',kid:'reconciler'}).setIssuer(service.clientId).setSubject(service.clientId).setAudience(app.origin+'/oidc/token').setIssuedAt(now).setExpirationTime(now+60).setJti(crypto.randomUUID()).sign(serviceKeys.privateKey);
 const tokenResponse=await fetch(app.origin+'/oidc/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:service.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:clientAssertion})});
 assert.equal(tokenResponse.status,200,await tokenResponse.clone().text());const machine=await tokenResponse.json();
 const groupResponse=await fetch(app.origin+'/api/auth/admin/v1/groups',{method:'POST',headers:{authorization:'Bearer '+machine.access_token,'content-type':'application/json'},body:JSON.stringify({name:'Company app operators'})});assert.equal(groupResponse.status,201,await groupResponse.clone().text());
 await serviceCard.getByRole('button',{name:'Revoke Northwind access reconciler',exact:true}).click();
 await expect(serviceCard).toContainText('Revoked');await shoot('service-revoked');
 assert.equal((await fetch(app.origin+'/api/auth/admin/v1/groups',{headers:{authorization:'Bearer '+machine.access_token}})).status,401,'revocation ends an already-issued machine token');
 assert.ok(!(await page.content()).includes(machine.access_token)&&!(await page.content()).includes(clientAssertion),'machine tokens and assertions never appear on the page');

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
 await expect(page.getByText('Service app Northwind access reconciler · Accountable: owner@example.com').first()).toBeVisible();
 await shoot('activity');
 assert.ok(!(await page.content()).includes(key),'Activity never shows the key');
 await delegatedAssignmentJourney({app,browser,owner:context,page,shoot});
 await followupJourney({app,browser,owner:context,page,shoot});
 await followupRolesJourney({app,browser,owner:context,page,shoot});
 assert.deepEqual(errors,[],'no browser runtime errors');
});
