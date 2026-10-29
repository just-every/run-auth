import {onboardingJourney} from './helpers/onboarding-journey.mjs';
import {docsJourney} from './helpers/docs-journey.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';
import {readTheme} from '@runeditrun/rer/internal/onboarding/theme.mjs';

test('real Auth pages: browser email, first setup, hardware passkey, people and account at desktop/mobile in both themes',async t=>{
 const dnsRecords=new Map();
 const app=await openApp({outboundService:async request=>{
  const url=new URL(request.url);
  if(url.origin==='https://cloudflare-dns.com'&&url.pathname==='/dns-query'){
   const name=url.searchParams.get('name');
   return Response.json({Status:0,Answer:dnsRecords.has(name)?[{name:name+'.',type:16,data:JSON.stringify(dnsRecords.get(name))}]:[]});
  }
  return fetch(request);
 },upstreamProviders:[{id:'company',label:'Company',preset:'google',clientId:'browser-fixture',tokenAuthMethod:'client_secret_basic',clientSecret:'edge-only'},{id:'backup',label:'Backup',preset:'google',clientId:'browser-fixture',tokenAuthMethod:'client_secret_basic',clientSecret:'edge-only'}]});t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--no-sandbox','--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const accessible=async label=>{const results=await new AxeBuilder({page}).analyze();assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],label);};
 const theme=await context.request.get(app.origin+'/rer-theme.css');assert.equal(theme.status(),200);
 readTheme(await theme.text(),'/rer-theme.css');
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');await accessible('sign-in');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);
 const requested=page.waitForResponse(response=>response.url().endsWith('/auth/identity/email/request'));
 await page.getByRole('button',{name:'Email me a sign-in link'}).click();assert.equal((await requested).status(),202);
 const link=await app.link();
 const stranger=await browser.newContext(),strangerPage=await stranger.newPage();
 for(const width of [1440,390]) {
  await strangerPage.setViewportSize({width,height:1000});await strangerPage.goto(link.href);
  await strangerPage.getByRole('button',{name:'Continue to Auth'}).click();
  await expect(strangerPage.getByRole('heading',{name:'Email link could not continue'})).toBeVisible();
  await expect(strangerPage.getByRole('link',{name:'Request a fresh link'})).toHaveAttribute('href','/signin');
  assert.ok(await strangerPage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await strangerPage.screenshot({path:join(directory,`email-wrong-browser-${width}.png`),fullPage:true});
 }
 await stranger.close();await page.goto(link.href);
 await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 const replayPage=await context.newPage();
 for(const width of [1440,390]) {
  await replayPage.setViewportSize({width,height:1000});await replayPage.goto(link.href);
  await replayPage.getByRole('button',{name:'Continue to Auth'}).click();
  await expect(replayPage.getByRole('alert')).toContainText('already used');
  await replayPage.screenshot({path:join(directory,`email-reused-${width}.png`),fullPage:true});
 }
 await replayPage.close();
 assert.equal((await context.request.get(app.origin+'/api/auth/people')).status(),403);
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();
 const result=await registered.catch(async()=>{throw new Error('Passkey registration failed: '+await page.locator('[data-auth-status]').allTextContents()+JSON.stringify(errors));});assert.equal(result.status(),200);
 await page.waitForTimeout(500);
 await page.goto(app.origin+'/app/account');await page.getByRole('button',{name:'Sign out',exact:true}).click();await expect(page).toHaveURL(app.origin+'/signin');
 await page.getByRole('button',{name:'Continue with a passkey'}).click();await expect(page).toHaveURL(app.origin+'/app');
 assert.equal((await context.request.get(app.origin+'/api/auth/people')).status(),200);
 assert.equal((await context.request.post(app.origin+'/api/auth/keys/stage',{data:{},headers:{origin:app.origin}})).status(),403,'passkey sign-in alone carries no fresh local email proof');
 await page.goto(app.origin+'/app/people');
 const rules=page.getByRole('region',{name:'Required providers'});
 await rules.getByLabel('Email domain',{exact:true}).fill('company.example');await rules.locator('#required-provider').selectOption('company');
 const missingProof=page.waitForResponse(response=>response.url().endsWith('/api/auth/people/domain-rule'));
 await rules.getByRole('button',{name:'Require provider',exact:true}).click();assert.equal((await missingProof).status(),403);
 await expect(page.locator('[data-auth-status][role="alert"]')).toBeVisible();
 await expect(rules.locator('.domain-rule')).toHaveCount(0);
 await rules.getByRole('link',{name:'Sign-in methods',exact:true}).click();
 const confirmationRequested=page.waitForResponse(response=>response.url().endsWith('/auth/identity/email/request'));
 await page.getByRole('button',{name:'Confirm my email',exact:true}).click();assert.equal((await confirmationRequested).status(),202);
 const confirmationLink=await app.link();await page.goto(confirmationLink.href);
 await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/app/methods');
 assert.equal((await context.request.get(app.origin+'/api/auth/people')).status(),200,'local confirmation retains active passkey administration');
 const staged=await context.request.post(app.origin+'/api/auth/keys/stage',{data:{},headers:{origin:app.origin}});assert.equal(staged.status(),201);const stagedKey=await staged.json();
 const publicKeys=await(await context.request.get(app.origin+'/oidc/jwks')).json();assert.ok(publicKeys.keys.some(key=>key.kid===stagedKey.kid));assert.ok(publicKeys.keys.every(key=>!key.d),'admin key stage publishes only public material');
 await onboardingJourney({app,browser,page,directory});
 const member=await browser.newContext();
 const invited=await context.request.post(app.origin+'/api/auth/people/invite',{data:{email:'restricted@company.example'},headers:{origin:app.origin}});assert.equal(invited.status(),201);
 assert.equal((await member.request.post(app.origin+'/auth/identity/email/request',{data:{email:'restricted@company.example'},headers:{origin:app.origin}})).status(),202);
 const memberLink=await app.link();assert.equal((await member.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:memberLink.searchParams.get('token')},headers:{origin:app.origin}})).status(),200);
 assert.equal((await member.request.get(app.origin+'/app',{maxRedirects:0})).status(),200);
 const proveDomain=async domain=>{
  const ownershipChallenge=await context.request.post(app.origin+'/api/auth/domains/challenge',{data:{domain},headers:{origin:app.origin}});
  assert.equal(ownershipChallenge.status(),201);
  const ownership=await ownershipChallenge.json();dnsRecords.set(ownership.label,ownership.value);
  const ownershipVerified=await context.request.post(app.origin+'/api/auth/domains/verify',{data:{domain,id:ownership.id},headers:{origin:app.origin}});
  assert.equal(ownershipVerified.status(),200);
 };
 await proveDomain('company.example');
 await page.goto(app.origin+'/app/people');
 await rules.getByLabel('Email domain',{exact:true}).fill('company.example');await rules.locator('#required-provider').selectOption('company');
 await rules.getByRole('button',{name:'Require provider',exact:true}).click();await expect(rules.locator('.domain-rule')).toHaveCount(1);
 assert.equal((await member.request.get(app.origin+'/app',{maxRedirects:0})).status(),303);await member.close();
 for(const width of [1440,390])for(const theme of ['light','dark']){
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});
  for(const section of ['people','apps','methods','activity','account']){
   await page.goto(app.origin+'/app/'+section);await expect(page.locator('h1')).toBeVisible();await accessible(`${width} ${theme} ${section}`);
   if(section==='people'){
    await expect(page.locator('[data-search-empty]')).toBeHidden();
    const search=page.getByRole('searchbox');await search.fill('no-such-person-in-this-install');await expect(page.locator('[data-search-empty]')).toBeVisible();await expect(page.locator('[data-person-row]:visible')).toHaveCount(0);await search.fill('');
    await expect(page.locator('[data-search-empty]')).toBeHidden();
    if(width===390){
     assert.ok(await page.locator('.table-scroll').evaluate(element=>element.scrollWidth<=element.clientWidth),'People fits the mobile viewport');
     for(const cell of await page.locator('[data-person-row] td').all()){const bounds=await cell.boundingBox();assert.ok(bounds && bounds.x>=0 && bounds.x+bounds.width<=width,'every People field remains in the viewport');}
    }
   }

   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${section} fits ${width}px`);
   // Apps with nothing linked shows its empty state (the door, message and hint) instead of a table.
   if(section==='apps' && !await page.locator('.table-scroll').count())await expect(page.locator('.empty-state.featured')).toBeVisible();
   else if(width===390 && ['people','apps','activity'].includes(section)){
    const region=page.locator('.table-scroll');
    const overflowing=await region.evaluate(element=>element.scrollWidth>element.clientWidth);
    {
     await page.locator('body').click({position:{x:2,y:2}});
     // Review/retention controls precede Activity history. Its public skip link
     // keeps the history reachable without traversing every settings field.
     const destination=section==='activity'?page.getByRole('link',{name:'Skip to activity history'}):region;
     let focused=false;for(let tabs=0;tabs<30&&!focused;tabs++){await page.keyboard.press('Tab');focused=await destination.evaluate(element=>element===document.activeElement);}
     assert.ok(focused,`${section} history or scroll region reachable by Tab`);
     if(section==='activity'){await page.keyboard.press('Enter');assert.ok(await region.evaluate(element=>element===document.activeElement),'Activity skip link focuses its scroll region');}
     if(overflowing){await page.keyboard.press('ArrowRight');await page.waitForTimeout(150);
      assert.ok(await region.evaluate(element=>element.scrollLeft>0),`${section} scrolls horizontally from keyboard`);}
     await region.evaluate(element=>element.scrollLeft=0);
    }
   }

   await page.screenshot({path:join(directory,`${width}-${theme}-${section}.png`),fullPage:true});
  }
  await page.goto(app.origin+'/app/people');
  await page.getByRole('button',{name:'Invite person',exact:true}).click();
  const dialog=page.getByRole('dialog',{name:'Invite person'}),address=`person-${width}-${theme}@example.com`;
  await dialog.getByLabel('Name',{exact:true}).fill(`Person ${width} ${theme}`);await dialog.getByLabel('Email',{exact:true}).fill(address);
  await dialog.getByRole('button',{name:'Invite person',exact:true}).click();await expect(page.getByText(address,{exact:true})).toBeVisible();
  let awaiting;
  if(width===1440&&theme==='light') {
   awaiting=await browser.newContext();
   assert.equal((await awaiting.request.post(app.origin+'/auth/identity/email/request',{data:{email:address},headers:{origin:app.origin}})).status(),202);
  }
  const pendingLink=awaiting?await app.link():null;
  const row=page.getByRole('row').filter({hasText:address});await row.getByRole('button',{name:'Suspend',exact:true}).click();await expect(row.locator('.status-pill')).toHaveText('Suspended');
  if(awaiting) {
   const stopped=await awaiting.newPage();await stopped.goto(pendingLink.href);
   await stopped.getByRole('button',{name:'Continue to Auth'}).click();
   await expect(stopped.getByRole('alert')).toContainText('contact your administrator');
   for(const stoppedWidth of [1440,390]) {
    await stopped.setViewportSize({width:stoppedWidth,height:1000});
    await expect(stopped.getByRole('heading',{name:'Email link could not continue'})).toBeVisible();
    await expect(stopped.getByRole('link',{name:'Request a fresh link'})).toBeVisible();
    assert.ok(await stopped.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await stopped.screenshot({path:join(directory,`email-suspended-${stoppedWidth}.png`),fullPage:true});
   }
   await awaiting.close();
   await page.getByRole('button',{name:'Invite person',exact:true}).click();
   await dialog.getByLabel('Name',{exact:true}).fill('Already suspended');await dialog.getByLabel('Email',{exact:true}).fill(address);
   await dialog.getByRole('button',{name:'Invite person',exact:true}).click();
   await expect(dialog).toBeHidden();
   for(const duplicateWidth of [1440,390]) {
    await page.setViewportSize({width:duplicateWidth,height:1000});
    await expect(page.locator('[data-auth-status]')).toContainText('Restore person proposal');
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await page.screenshot({path:join(directory,`people-reinvite-${duplicateWidth}.png`),fullPage:true});
   }
   await page.setViewportSize({width,height:1000});
  }
  await proveDomain(`team-${width}-${theme}.example.com`);
  await page.getByRole('button',{name:'Allow a domain',exact:true}).click();
  const domain=page.getByRole('dialog',{name:'Allow a domain'});await domain.getByLabel('Domain',{exact:true}).fill(`team-${width}-${theme}.example.com`);
  await domain.getByRole('button',{name:'Allow a domain',exact:true}).click();await expect(page.getByRole('region',{name:'Allowed domains',exact:true}).getByText(`team-${width}-${theme}.example.com`,{exact:true})).toBeVisible();
 }
 await page.goto(app.origin+'/app/methods');
 const rule=page.locator('.domain-rule');await rule.locator('select').selectOption('backup');await rule.getByRole('button',{name:'Save rule'}).click();await expect(rule.locator('select')).toHaveValue('backup');
 await page.reload();await expect(rule.locator('select')).toHaveValue('backup');
 await rule.locator('select').selectOption('');await rule.getByRole('button',{name:'Save rule'}).click();await expect(page.locator('.domain-rule')).toHaveCount(0);
 for(const width of [1440,390]) {
  await page.setViewportSize({width,height:1000});await page.goto(app.origin+'/app/account');
  await page.getByRole('button',{name:'Request passkey recovery'}).click();await expect(page.getByText('Your recovery request',{exact:true})).toBeVisible();
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'pending recovery fits '+width);await accessible('pending recovery '+width);
  await page.screenshot({path:join(directory,`continuity-recovery-pending-${width}.png`),fullPage:true});
  await page.getByRole('button',{name:'Cancel request'}).click();await expect(page.getByText('Your recovery request',{exact:true})).toHaveCount(0);
  await page.screenshot({path:join(directory,`continuity-recovery-cancelled-${width}.png`),fullPage:true});
 }
 await page.goto(app.origin+'/app/methods');
 let throttled;
 for(let attempt=0;attempt<6;attempt++) {
  const answer=page.waitForResponse(response=>response.url().endsWith('/auth/identity/email/request'));
  await page.getByRole('button',{name:'Confirm my email',exact:true}).click();
  const response=await answer;if(response.status()===429){throttled=response;break;}
 }
 assert.ok(throttled,'authenticated own-address request reaches the public throttle');
 assert.ok(Number(throttled.headers()['retry-after'])>0);
 for(const width of [1440,390]) {
  await page.setViewportSize({width,height:1000});
  await expect(page.locator('[data-auth-status][role="alert"]')).toContainText('Try again in');
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await accessible('email retry '+width);
  await page.screenshot({path:join(directory,`email-retry-${width}.png`),fullPage:true});
  const themeControl=page.locator('[data-theme-toggle]:visible').first();
  await page.locator('h1').click();await page.mouse.move(0,0);await themeControl.hover();
  await expect(page.getByRole('tooltip')).toHaveText('Color theme');
  await page.screenshot({path:join(directory,`email-methods-tooltip-hover-${width}.png`),fullPage:true});
  await page.mouse.move(0,0);await themeControl.focus();
  await expect(page.getByRole('tooltip')).toBeVisible();
  await page.screenshot({path:join(directory,`email-methods-tooltip-focus-${width}.png`),fullPage:true});
 }
 assert.deepEqual(errors,[],'no browser runtime errors');
 console.log('Auth journey: 20 real private-page screenshots; 1440/390 light/dark; axe serious/critical 0; browser email, setup, virtual hardware passkey, people, recovery cancellation');
});

test('docs pages support keyboard code scrolling and remain readable at desktop and mobile',docsJourney);
