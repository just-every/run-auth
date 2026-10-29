import {deliveryBrowser} from './helpers/delivery-journey.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';

const domain='employer.example.invalid',employee=`erin.park@${domain}`;

async function successfulAction(page,path,button,status=200) {
 const response=page.waitForResponse(answer=>new URL(answer.url()).pathname===path&&answer.request().method()==='POST');
 const navigation=page.waitForNavigation({waitUntil:'domcontentloaded'});
 await button.click();
 const answer=await response;
 assert.equal(answer.status(),status,await answer.text());
 await navigation;
 return answer;
}

async function ownerSetup(app,page) {
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);
 const requested=page.waitForResponse(answer=>answer.url().endsWith('/auth/identity/email/request'));
 await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 assert.equal((await requested).status(),202);
 await page.goto((await app.link()).href);
 await page.getByRole('button',{name:'Continue to Auth'}).click();
 await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();
 await page.getByRole('button',{name:'Finish setup'}).click();
 await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 await successfulAction(page,'/auth/identity/passkeys/register/verify',page.getByRole('button',{name:'Register a passkey'}));
}

async function tooltipAudit(page,directory,name,width) {
 const controls=page.locator('[data-tooltip]:visible');
 assert.ok(await controls.count(),'shared shell exposes its icon control tooltips');
 for(const control of await controls.all()) {
  const label=await control.getAttribute('data-tooltip');
  await expect(control).toHaveAccessibleName(/\S/);
  await page.locator('h1').click();await page.mouse.move(0,0);
  await control.hover();await page.waitForTimeout(300);
  const tooltip=page.getByRole('tooltip');
  await expect(tooltip).toHaveText(label);
  const key=label.toLowerCase().replace(/\W+/g,'-');
  await page.screenshot({path:join(directory,`security-${name}-${width}-${key}-hover.png`),fullPage:true});
  await page.mouse.move(0,0);await control.focus();
  await expect(tooltip).toHaveText(label);
  await page.screenshot({path:join(directory,`security-${name}-${width}-${key}-focus.png`),fullPage:true});
  await page.keyboard.press('Escape');
  await expect(tooltip).toBeHidden();
 }
 await page.locator('h1').click();await page.mouse.move(0,0);
}

test('security settings: prove and revoke employer ownership, preview affected workers, and authorize persistent notification preferences at desktop and mobile',async t=>{
 // Only the external DNS transport is substituted. The emitted Worker owns
 // challenges, authorization, policy, sessions, persistence and rendering.
 const records=new Map(),queries=[];
 const app=await openApp({outboundService:async request=>{
  const url=new URL(request.url);
  if(url.origin==='https://cloudflare-dns.com'&&url.pathname==='/dns-query') {
   assert.equal(url.searchParams.get('type'),'TXT');
   const name=url.searchParams.get('name');queries.push(name);
   return Response.json({Status:0,Answer:records.has(name)?[{name:name+'.',type:16,TTL:60,data:JSON.stringify(records.get(name))}]:[]});
  }
  return fetch(request);
 }});
 t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});
 t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const directory=process.env.AUTH_SCREENSHOTS||join(tmpdir(),'auth-security-settings-journey');await mkdir(directory,{recursive:true});
 const ownership=()=>page.getByRole('region',{name:'Verified employer domains'});
 const card=()=>ownership().getByRole('article').filter({has:page.getByRole('heading',{name:domain,exact:true})});
 const snapshot=async(name,prepare=async()=>{},auditTooltips=false)=>{
  for(const width of [1440,390]) {
   await page.setViewportSize({width,height:1000});await page.reload();await prepare();
   await expect(page.locator('h1')).toBeVisible();
   const accessibility=await new AxeBuilder({page}).analyze();
   assert.deepEqual(accessibility.violations.filter(item=>['serious','critical'].includes(item.impact)).map(item=>({id:item.id,nodes:item.nodes.map(node=>node.target)})),[],`${name} accessibility at ${width}`);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
   await page.screenshot({path:join(directory,`security-${name}-${width}.png`),fullPage:true});
   if(auditTooltips)await tooltipAudit(page,directory,name,width);
  }
  await page.setViewportSize({width:1440,height:1000});
 };
 const domainSnapshots=async state=>{
  for(const section of ['methods','people']) {
   await page.goto(app.origin+'/app/'+section);
   await snapshot(`domains-${state}-${section}`,async()=>{
    await expect(card().getByText(new RegExp(`^${state} ·`))).toBeVisible();
    await card().getByText('Preview affected people',{exact:true}).click();
    await expect(card().getByRole('list')).toContainText(employee);
   },state==='verified');
  }
 };

 await ownerSetup(app,page);

 const invited=await context.request.post(app.origin+'/api/auth/people/invite',{headers:{origin:app.origin},data:{name:'Erin Park',email:employee}});
 assert.equal(invited.status(),201,await invited.text());
 await ownership().getByLabel('Employer domain',{exact:true}).fill(domain);
 const challenge=await successfulAction(page,'/api/auth/domains/challenge',ownership().getByRole('button',{name:'Start ownership challenge'}),201);
 const model=await challenge.json();
 await page.screenshot({path:join(directory,'security-challenge-created.png'),fullPage:true});
 assert.equal(await card().count(),1,await ownership().innerText());
 const label=await card().getByLabel('TXT name',{exact:true}).inputValue(),value=await card().getByLabel('TXT value',{exact:true}).inputValue();
 assert.equal(label,model.label);assert.equal(value,model.value);
 await expect(card().getByLabel('TXT name',{exact:true})).toHaveAttribute('readonly','');
 await expect(card().getByLabel('TXT value',{exact:true})).toHaveAttribute('readonly','');
 await domainSnapshots('pending');

 // A real verification attempt before publishing TXT remains pending.
 const missingTXT=page.waitForResponse(answer=>answer.url().endsWith('/api/auth/domains/verify'));
 await card().getByRole('button',{name:'Verify ownership'}).click();
 assert.equal((await missingTXT).status(),409);
 await expect(page.locator('[data-auth-status][role="alert"]')).toBeVisible();
 await expect(card().getByRole('button',{name:'Verify ownership'})).toBeEnabled();
 records.set(label,value);
 await successfulAction(page,'/api/auth/domains/verify',card().getByRole('button',{name:'Verify ownership'}));
 assert.ok(queries.length&&queries.every(name=>name===label),'the Worker verifies the exact challenge through its DNS endpoint');
 await page.getByRole('button',{name:'Allow a domain',exact:true}).click();
 const allow=page.getByRole('dialog',{name:'Allow a domain'});
 await allow.getByLabel('Domain',{exact:true}).fill(domain);
 await successfulAction(page,'/api/auth/people/domain',allow.getByRole('button',{name:'Allow a domain',exact:true}),201);
 await expect(page.getByRole('region',{name:'Allowed domains'})).toContainText(domain);

 const worker=await browser.newContext();t.after(()=>worker.close());
 assert.equal((await worker.request.post(app.origin+'/auth/identity/email/request',{headers:{origin:app.origin},data:{email:employee}})).status(),202);
 const workerLink=await app.link();
 assert.equal((await worker.request.post(app.origin+'/auth/identity/email/confirm',{headers:{origin:app.origin},data:{token:workerLink.searchParams.get('token')}})).status(),200);
 assert.equal((await worker.request.get(app.origin+'/app',{maxRedirects:0})).status(),200);
 await page.reload();
 await expect(page.getByRole('row').filter({hasText:employee})).toContainText('Erin Park');
 await domainSnapshots('verified');
 page.once('dialog',dialog=>dialog.accept());
 await successfulAction(page,'/api/auth/domains/revoke',card().getByRole('button',{name:'Revoke ownership'}));
 await domainSnapshots('revoked');
 assert.equal((await worker.request.get(app.origin+'/app',{maxRedirects:0})).status(),303,'revoked ownership blocks an affected worker session');
 assert.equal((await context.request.get(app.origin+'/api/auth/people')).status(),200,'the owner retains administration while the affected worker is blocked');

 await page.goto(app.origin+'/app/account');
 const preferences=()=>page.locator('details').filter({has:page.getByText('Security notification preferences',{exact:true})});
 const openPreferences=async()=>{
  await preferences().getByText('Security notification preferences',{exact:true}).click();
  await expect(preferences().getByRole('button',{name:'Save notification preferences'})).toBeVisible();
 };
 await snapshot('notifications-before-consent',openPreferences);
 const email=()=>preferences().getByRole('checkbox',{name:/^Authorize security email/});
 const newBrowser=()=>preferences().getByRole('checkbox',{name:'Send new browser notices'});
 const endSessions=()=>preferences().getByRole('checkbox',{name:/^End all Auth sessions/});
 const consent=()=>preferences().getByRole('checkbox',{name:'I authorize these notifications, recipients and report responses.'});
 await expect(email()).not.toBeChecked();
 await email().check();await endSessions().check();await newBrowser().check();
 const ownerOption=preferences().getByRole('option',{name:new RegExp(app.vars.OWNER_EMAIL.replaceAll('.','\\.'))});
 const ownerId=await ownerOption.getAttribute('value');assert.ok(ownerId);
 await preferences().getByLabel('Security owner',{exact:true}).selectOption(ownerId);
 await expect(preferences().getByText(/Recovery started, factor reset or removal, and administrator role notices are mandatory/)).toBeVisible();
 await consent().check();
 await successfulAction(page,'/api/auth/notifications/settings',preferences().getByRole('button',{name:'Save notification preferences'}));
 const savedPreferences=async enabled=>{
  await openPreferences();
  await expect(email()).toBeChecked();await expect(newBrowser()).toBeChecked({checked:enabled});
  await expect(endSessions()).toBeChecked();
  await expect(preferences().getByLabel('Security owner',{exact:true})).toHaveValue(ownerId);
  await expect(consent()).not.toBeChecked();
 };
 await snapshot('notifications-new-browser-on',()=>savedPreferences(true),true);
 await newBrowser().uncheck();await consent().check();
 await successfulAction(page,'/api/auth/notifications/settings',preferences().getByRole('button',{name:'Save notification preferences'}));
 await snapshot('notifications-new-browser-off',()=>savedPreferences(false));
 // Read the new-device action from the real private development mailbox.
 const signedOut=await browser.newContext();t.after(()=>signedOut.close());
 assert.equal((await signedOut.request.post(app.origin+'/auth/identity/email/request',{headers:{origin:app.origin},data:{email:app.vars.OWNER_EMAIL}})).status(),202);
 const loginLink=await app.link();
 // Notices are enabled again through their public administration door.
 const notificationState=await(await context.request.get(app.origin+'/api/auth/notifications')).json();
 const restored=await context.request.post(app.origin+'/api/auth/notifications/settings',{headers:{origin:app.origin},data:{...notificationState.policy,newDevice:true,confirm:true}});assert.equal(restored.status(),200);
 assert.equal((await signedOut.request.post(app.origin+'/auth/identity/email/confirm',{headers:{origin:app.origin},data:{token:loginLink.searchParams.get('token')}})).status(),200);
 const mailbox=await(await app.get('/__dev/outbox',{'x-rer-dev-key':app.vars.RER_DEV_KEY})).text();
 const messagePath=mailbox.match(/href="(\/__dev\/outbox\?message=[^"]+)"/)?.[1];assert.ok(messagePath);
 const detail=await(await app.get(messagePath.replaceAll('&amp;','&'),{'x-rer-dev-key':app.vars.RER_DEV_KEY})).text();
 const reportUrl=detail.match(/https?:\/\/[^\s<>"]+\/api\/auth\/notifications\/report\?token=[^\s<>"]+/)?.[0];assert.ok(reportUrl,'new-device email has its report action');
 const publicContext=await browser.newContext(),reportPage=await publicContext.newPage();t.after(()=>publicContext.close());
 await reportPage.goto(reportUrl.replaceAll('&amp;','&'));
 for(const [state,title] of [['reported','Suspicious activity reported'],['unavailable','Report unavailable']]) {
  if(state==='unavailable')await reportPage.goto(reportUrl.replaceAll('&amp;','&'));
  for(const width of [1440,390]) {
   await reportPage.setViewportSize({width,height:1000});await expect(reportPage.getByRole('heading',{name:title,exact:true})).toBeVisible();
   assert.ok(await reportPage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
   await reportPage.screenshot({path:join(directory,`security-report-${state}-${width}.png`),fullPage:true});
  }
 }
 assert.equal((await signedOut.request.get(app.origin+'/api/auth/me')).status(),401);
 // Sign in again with the existing browser-bound hardware key to review it.
 await page.goto(app.origin+'/signin?returnTo=%2Fapp%2Faccount');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);
 await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();
 await page.goto(app.origin+'/app/methods');
 await page.getByRole('button',{name:'Continue with a passkey'}).click();await expect(page.getByRole('button',{name:'Register a passkey'})).toBeVisible();
 await page.goto(app.origin+'/app/account');
 await snapshot('notifications-report-open',async()=>{await expect(page.getByRole('button',{name:'Mark reviewed'})).toBeVisible();});
 await successfulAction(page,'/api/auth/notifications/resolve',page.getByRole('button',{name:'Mark reviewed'}));
 await snapshot('notifications-report-reviewed',async()=>{await expect(page.getByText('Reviewed',{exact:true})).toBeVisible();});
 assert.deepEqual(errors,[],'no browser runtime errors');

});


test('mail delivery diagnostics distinguish private outbox and signed provider outcomes at desktop and mobile',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),cdp=await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||join(tmpdir(),'auth-delivery-journey');await mkdir(directory,{recursive:true});
 await ownerSetup(app,page);
 for(const width of [1440,390]) {
  await page.setViewportSize({width,height:1000});await page.goto(app.origin+'/app/methods');
  const panel=page.getByRole('region',{name:'Mail delivery'});await expect(panel).toContainText('Private local outbox');
  await panel.getByText('Recent delivery attempts',{exact:true}).click();await expect(panel).toContainText('local outbox');
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'private outbox fits '+width);
  await page.screenshot({path:join(directory,`security-mail-local-${width}.png`),fullPage:true});await panel.screenshot({path:join(directory,`security-mail-local-${width}-panel.png`)});
  await tooltipAudit(page,directory,'mail-delivery',width);
 }
 await app.pause();await deliveryBrowser(t,browser,directory);
});

test('attack protection settings persist, explain refusal and preserve proved recovery at desktop and mobile',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--no-sandbox','--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),cdp=await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||join(tmpdir(),'auth-abuse-journey');await mkdir(directory,{recursive:true});
 await ownerSetup(app,page);
 const panel=()=>page.getByRole('region',{name:'Attack protection'});
 await panel().getByLabel('Attempts per source',{exact:true}).fill('2');
 await panel().getByLabel('Combined attempts',{exact:true}).fill('4');
 await panel().getByLabel('Cooldown seconds',{exact:true}).fill('30');
 await expect(panel().getByRole('status')).toHaveText('Changes saved.');
 await page.reload();
 await expect(panel().getByLabel('Attempts per source',{exact:true})).toHaveValue('2');
 await expect(panel().getByLabel('Combined attempts',{exact:true})).toHaveValue('4');
 await expect(panel().getByLabel('Cooldown seconds',{exact:true})).toHaveValue('30');
 const snapshot=async state=>{
  for(const width of [1440,390]) {
   await page.setViewportSize({width,height:1000});
   if(width===1440)assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),state+' fits '+width);
   await page.screenshot({path:join(directory,`abuse-${state}-${width}.png`),fullPage:true});
   if(state==='configured'&&width===390)for(const control of await page.locator('[data-tooltip]:visible').all()) {
    const name=(await control.getAttribute('data-tooltip')).toLowerCase().replace(/\W+/g,'-');
    await control.hover();await page.waitForTimeout(350);
    await page.screenshot({path:join(directory,`abuse-${width}-${name}-hover.png`),fullPage:true});
    await page.mouse.move(0,0);await control.focus();
    await page.screenshot({path:join(directory,`abuse-${width}-${name}-focus.png`),fullPage:true});
    await page.keyboard.press('Escape');await page.locator('h1').click();
   }
  }
  await page.setViewportSize({width:1440,height:1000});
 };
 await snapshot('configured');
 const refused=page.waitForResponse(answer=>answer.url().endsWith('/auth/identity/passkeys/register/options'));
 await page.getByRole('button',{name:'Register a passkey'}).click();
 assert.equal((await refused).status(),429,'the configured source budget is enforced by the emitted Worker');
 await expect(page.locator('[data-auth-status][role="alert"]')).toContainText('Too many attempts');
 await snapshot('refused');
 await page.reload();await panel().getByText('Recent attack refusals',{exact:true}).click();
 await expect(panel()).toContainText('source_limit');
 await tooltipAudit(page,directory,'attack-protection',1440);
 // Anonymous traffic cannot exhaust the authenticated recovery session.
 const outsider=await browser.newContext();t.after(()=>outsider.close());
 for(let i=0;i<5;i++)await outsider.request.post(app.origin+'/api/auth/recovery/start',{headers:{origin:app.origin},data:{}});
 await page.goto(app.origin+'/app/account');page.once('dialog',dialog=>dialog.accept());
 await successfulAction(page,'/api/auth/recovery/start',page.getByRole('button',{name:'Request passkey recovery'}),201);
 await expect(page.getByText('Your recovery request',{exact:true})).toBeVisible();
 await snapshot('proved-recovery');
 await successfulAction(page,'/api/auth/recovery/cancel',page.getByRole('button',{name:'Cancel request'}));
 await expect(page.getByText('No passkey recovery requests are pending.',{exact:true})).toBeVisible();
 await snapshot('recovery-cancelled');
 await page.goto(app.origin+'/app/methods');
 const ended=await context.request.post(app.origin+'/api/auth/signout',{headers:{origin:app.origin},data:{}});assert.equal(ended.status(),200);
 const unsaved=page.waitForResponse(answer=>answer.url().endsWith('/api/auth/abuse/configure'));
 await panel().getByLabel('Attempts per source',{exact:true}).fill('3');
 assert.equal((await unsaved).status(),401,'autosave preserves the session authority check');
 await expect(panel().getByRole('status')).toContainText('Changes have not been saved.');
 await snapshot('unsaved');
});

import {factorsJourney} from './helpers/factors-journey.mjs';
test('native multifactor settings enroll TOTP, publish app assurance and end sessions on factor loss or code rotation',factorsJourney);
