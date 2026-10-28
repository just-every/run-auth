import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from '../runtime.mjs';
import {authenticatorCode} from '../../auth/factors-flow.mjs';

export async function factorsJourney(t) {
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,executablePath:process.env.AUTH_CHROMIUM||undefined,args:['--no-sandbox','--use-mock-keychain','--password-store=basic']});t.after(()=>browser.close());
 let context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),email=app.vars.OWNER_EMAIL;
 const cdp=await context.newCDPSession(page);
 page.on('dialog',dialog=>dialog.accept());
 await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||join(tmpdir(),'auth-factor-journey');await mkdir(directory,{recursive:true});
 const post=async(path,data,status=200)=>{const response=await context.request.post(app.origin+path,{headers:{origin:app.origin},data});assert.equal(response.status(),status,await response.text());return response.json();};
 const action=async(path,button,navigate=false)=>{const response=page.waitForResponse(r=>r.url().endsWith(path)&&r.request().method()==='POST');const loaded=navigate?page.waitForNavigation({waitUntil:'domcontentloaded'}):null;await button.click();const result=await response;if(result.status()!==200)assert.fail(await result.text());const body=navigate?null:await result.json();if(loaded)await loaded;return body;};
 const confirmEmail=async()=>{await post('/auth/identity/email/request',{email},202);await post('/auth/identity/email/confirm',{token:(await app.link()).searchParams.get('token')});};
 await confirmEmail();await page.goto(app.origin+'/setup');await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();
 await page.goto(app.origin+'/app/methods');await action('/passkeys/register/verify',page.getByRole('button',{name:'Register a passkey'}),true);
 const panel=()=>page.getByRole('region',{name:'Additional factors and recovery'});
 const capture=async(name,prepare=async()=>{})=>{
  for(const width of [1440,390])for(const theme of ['light','dark']) {
   await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await prepare();
   // Functional assertions run at the desktop width. Phone captures preserve
   // the same state for release inspection without duplicating every assertion.
   if(width===1440){assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits');await page.screenshot({path:join(directory,`factors-${name}-${width}-${theme}-page.png`),fullPage:true});const axe=await new AxeBuilder({page}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>({html:n.html,summary:n.failureSummary}))})),[]);}
   await panel().screenshot({path:join(directory,`factors-${name}-${width}-${theme}.png`)});
  }
  await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});
 };
 const appInfo=await post('/api/auth/oidc-apps/create',{name:'Payroll',authMethod:'none',redirectUris:'https://payroll.example.test/callback',requirePkce:true},201);
 await page.reload();await capture('inventory');
 await panel().getByText('Settings: app assurance',{exact:true}).click();
 await panel().getByLabel('App',{exact:true}).selectOption(appInfo.id);await panel().getByLabel('Required assurance').selectOption('passkey');
 await panel().getByLabel('Maximum proof age in seconds').fill('300');await action('/factors/policy',panel().getByRole('button',{name:'Save app assurance'}),true);
 await expect(panel()).toContainText('Passkey required');await capture('policy',async()=>{const details=panel().locator('details');if(!await details.evaluate(el=>el.open))await details.locator('summary').click();});
 // Employee recovery uses an ordinary invited member, preserving the
 // separate protected recovery process for administrators.
 email='synthetic-auth-20'+'@'+'example.test';
 await post('/api/auth/people/invite',{email,name:'Synthetic employee'},201);
 context=await browser.newContext({viewport:{width:1440,height:1000}});page=await context.newPage();page.on('dialog',dialog=>dialog.accept());
 const employeeCdp=await context.newCDPSession(page);await employeeCdp.send('WebAuthn.enable');await employeeCdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 await confirmEmail();await page.goto(app.origin+'/app/methods');await action('/passkeys/register/verify',page.getByRole('button',{name:'Register a passkey'}),true);
 const enrolled=await action('/factors/totp/begin',panel().getByRole('button',{name:'Set up TOTP'}));
 await expect(panel().locator('[data-factor-secret]')).toHaveText(enrolled.secret);
 // Secret enrollment screens are exercised but never captured as fleet evidence.
 await panel().getByLabel('Authenticator confirmation code').fill(authenticatorCode(enrolled.secret,Date.now()));
 await action('/factors/totp/confirm',panel().getByRole('button',{name:'Confirm TOTP enrollment'}),true);
 await expect(panel()).toContainText('TOTP authenticator');await capture('totp-enrolled');
 const generated=await action('/factors/recovery/rotate',panel().getByRole('button',{name:'Replace recovery codes'}));
 assert.equal(generated.codes.length,8);await expect(panel().locator('[data-factor-code-list]')).toContainText(generated.codes[0]);
 assert.equal((await context.request.get(app.origin+'/api/auth/me')).status(),401,'code rotation ends the browser session');
 await page.goto(app.origin+'/signin');await action('/passkeys/authenticate/verify',page.getByRole('button',{name:'Continue with a passkey'}),true);await confirmEmail();await page.goto(app.origin+'/app/methods');
 await expect(panel()).toContainText('8 unused recovery codes');await capture('codes-stored');
 await action('/factors/remove',panel().getByRole('button',{name:'Remove TOTP'}),true);await expect(page).toHaveURL(app.origin+'/signin');
 await confirmEmail();await page.goto(app.origin+'/app/methods');
 await expect(panel()).toContainText('No TOTP authenticator enrolled.');await capture('recovery-ready');
 await panel().getByLabel('Single-use recovery code').fill(generated.codes[0]);
 await action('/factors/recovery/redeem',panel().getByRole('button',{name:'Recover my passkey'}),true);
 await capture('replacement-enrollment');
 await action('/passkeys/register/verify',page.getByRole('button',{name:'Register a passkey'}),true);
 await expect(panel()).toContainText('7 unused recovery codes');
 await post('/api/auth/factors/recovery/redeem',{code:generated.codes[0]},403);
 await capture('factor-removed');
 for(const control of await page.locator('[data-tooltip]:visible').all()) {
  await control.hover();await page.waitForTimeout(350);await expect(page.getByRole('tooltip')).not.toBeEmpty();await page.mouse.move(0,0);await control.focus();await expect(page.getByRole('tooltip')).toBeVisible();await page.keyboard.press('Escape');await control.blur();
 }
}
