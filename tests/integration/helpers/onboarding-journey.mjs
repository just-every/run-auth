import {temporaryPassJourney} from './temporary-pass-journey.mjs';
import assert from 'node:assert/strict';
import {join} from 'node:path';
import {expect} from '@playwright/test';

// Extend the existing real-Worker journey without creating another server.
export async function onboardingJourney({app,browser,page,directory}) {
 await page.goto(app.origin+'/app/people');
 await page.getByRole('button',{name:'Invite person',exact:true}).click();
 const dialog=page.locator('#invite-dialog');
 await dialog.getByLabel('Name',{exact:true}).fill('Synthetic future worker');
 await dialog.getByLabel('Email',{exact:true}).fill('synthetic-hire@example.com');
 await dialog.getByLabel('Personal contact',{exact:true}).fill('synthetic-personal@example.net');
 await dialog.getByLabel('Employer-local start time').fill(new Date(Date.now()+10*86400000).toISOString().slice(0,16));
 await dialog.getByLabel('Employer time zone').fill('UTC');await dialog.getByLabel('Invitation lead days').fill('30');
 await dialog.getByRole('checkbox').check();
 await expect(dialog.getByText('Personal contact starts unverified',{exact:false})).toBeVisible();
 for(const width of [1440,390])for(const theme of ['light','dark']) {
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});
  await page.screenshot({path:join(directory,`onboarding-create-${width}-${theme}.png`),fullPage:true});
 }
 await page.setViewportSize({width:1440,height:1000});
 const created=page.waitForResponse(response=>response.url().endsWith('/api/auth/people/invite'));
 await dialog.getByRole('button',{name:'Invite person',exact:true}).click();assert.equal((await created).status(),201);
 await page.waitForTimeout(600);await page.reload();
 await expect(page.getByText('Unverified personal contact',{exact:false})).toBeVisible();
 const link=await app.link('','onboarding');
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),hire=await context.newPage();
 try {
  const cdp=await context.newCDPSession(hire);await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await hire.goto(link.href);
  await expect(hire.getByRole('heading',{name:'Activate your enrollment'})).toBeVisible();
  for(const width of [1440,390])for(const theme of ['light','dark']) {
   await hire.setViewportSize({width,height:1000});await hire.emulateMedia({colorScheme:theme});
   await hire.screenshot({path:join(directory,`onboarding-activate-${width}-${theme}.png`),fullPage:true});
  }
  await hire.setViewportSize({width:1440,height:1000});
  const activated=hire.waitForResponse(response=>response.request().method()==='POST'&&response.url().includes('/auth/identity/onboarding?'));
  await hire.getByRole('button',{name:'Activate enrollment',exact:true}).click();assert.equal((await activated).status(),303);
  await expect(hire).toHaveURL(app.origin+'/app/methods');
  const registered=hire.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
  await hire.getByRole('button',{name:'Register a passkey',exact:true}).click();assert.equal((await registered).status(),200);
  assert.equal((await context.request.get(app.origin+'/api/auth/organizations')).status(),403,'personal activation remains enrollment only after registering a passkey');
  await hire.waitForTimeout(600);
  for(const width of [1440,390])for(const theme of ['light','dark']) {
   await hire.setViewportSize({width,height:1000});await hire.emulateMedia({colorScheme:theme});
   await hire.screenshot({path:join(directory,`onboarding-enrolled-${width}-${theme}.png`),fullPage:true});
  }
  await page.reload();await expect(page.getByText('Personal contact proved',{exact:false})).toBeVisible();
  // The existing icon-only shell controls retain the shared delayed tooltip.
  const theme=page.locator('[data-theme-toggle]:visible').first();await theme.focus();await expect(page.getByRole('tooltip')).toHaveText('Color theme');
  await page.keyboard.press('Tab');await theme.hover();await page.waitForTimeout(350);await expect(page.getByRole('tooltip')).toHaveText('Color theme');
 }finally {await context.close();}
 await temporaryPassJourney({app,browser,page,directory});
}
