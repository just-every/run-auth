import {hookServer} from '../auth/hooks-server.mjs';
import {migrationJourney} from './helpers/migration-journey.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from './runtime.mjs';

const exportFile=fileURLToPath(new URL('../fixtures/move-in/google-30.json',import.meta.url));
const views=[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']];

test('move-in journey: stage a 30-person Google export, review, admit, invite and undo at desktop/mobile in both themes',async t=>{
 const edge=await hookServer(t),app=await openApp({outboundService:edge.fetch});t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const accessible=async label=>{const results=await new AxeBuilder({page}).analyze();assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],label);};
 const confirmEmail=async()=>{
  await page.goto(app.origin+'/app/methods');
  const requested=page.waitForResponse(response=>response.url().endsWith('/auth/identity/email/request'));
  await page.getByRole('button',{name:'Confirm my email',exact:true}).click();assert.equal((await requested).status(),202);
  await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();
 };
 const shoot=async(name,check)=>{for(const [width,theme] of views){
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await page.reload();
  await expect(page.locator('h1')).toBeVisible();await accessible(`${width} ${theme} ${name}`);if(check)await check(width);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
  for(const control of await page.locator('[data-tooltip]:visible').all()){await control.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();await page.waitForTimeout(200);await expect(page.getByRole('tooltip')).toBeVisible();await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true);await page.keyboard.press('Escape');await control.blur();}
  await page.screenshot({path:join(directory,`move-in-${name}-${width}-${theme}.png`),fullPage:true});
 }await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});};

 // First owner: browser email link, setup, hardware passkey (as the main journey).
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);await page.waitForTimeout(500);
 // One person already in Auth, so the review shows that class.
 assert.equal((await context.request.post(app.origin+'/api/auth/people/invite',{data:{email:'existing@northwind.example.com',name:'Esme Existing'},headers:{origin:app.origin}})).status(),201);
 const outbox=async()=>(await(await app.get('/__dev/outbox',{'x-rer-dev-key':app.vars.RER_DEV_KEY})).text()).match(/href="\/__dev\/outbox\?message=/g)?.length??0;

 // Owner actions are counted from the People page, as an owner would start.
 const actions=[],screens=new Set();const act=label=>actions.push(label);
 await page.goto(app.origin+'/app/people');screens.add('People');
 await page.getByRole('link',{name:'Move people in'}).click();act('Open Move people in');await expect(page).toHaveURL(app.origin+'/app/move-in');screens.add('Move people in');
 await shoot('empty');
 await page.getByLabel('Export file').setInputFiles(exportFile);act('Choose the export file');
 await page.getByRole('button',{name:'Stage file'}).click();act('Stage file');
 await expect(page).toHaveURL(/\/app\/move-in\?batch=/);screens.add('Review');
 const review=page.getByRole('region',{name:'Staged people table'});
 await expect(review.locator('[data-move-in-row]')).toHaveCount(30);
 for(const reason of ['owner_address','existing_person','duplicate_in_file','disabled_at_source','refused_domain','invalid_email'])await expect(review.locator(`[data-move-in-row][data-reasons~="${reason}"]`).first()).toBeVisible();
 await expect(review.locator('input[name=rows]:checked')).toHaveCount(22);
 await expect(page.locator('[data-batch-proof-notice]')).toHaveCount(1);
 const mailBefore=await outbox();
 await shoot('review',async width=>{if(width===390)for(const cell of await page.locator('[data-move-in-row] td').all()){const box=await cell.boundingBox();assert.ok(box&&box.x>=0&&box.x+box.width<=width,'every review field stays in the mobile viewport');}});

 await page.getByRole('button',{name:'Admit selected'}).click();act('Admit selected');
 await expect(review.locator('[data-row-status=admitted]')).toHaveCount(22);
 assert.equal(await outbox(),mailBefore,'admission sends no mail');
 await page.getByRole('button',{name:'Send invitations'}).click();act('Send invitations');
 await expect(review.locator('[data-row-status=invited]')).toHaveCount(22);
 assert.equal(await outbox(),mailBefore+22,'one ordinary invitation per admitted person');
 const people=await(await context.request.get(app.origin+'/api/auth/people')).json();
 assert.equal(people.filter(p=>p.status==='invited'&&p.role==='member').length,23);assert.equal(people.filter(p=>p.role!=='member').length,1);
 const batchUrl=page.url();
 await shoot('admitted');
 await page.goto(app.origin+'/app/people');await shoot('people');

 // One admitted person signs in from their own browser; undo keeps them and says why.
 const member=await browser.newContext();
 assert.equal((await member.request.post(app.origin+'/auth/identity/email/request',{data:{email:'amara.okafor@northwind.example.com'},headers:{origin:app.origin}})).status(),202);
 const memberLink=await app.link();assert.equal((await member.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:memberLink.searchParams.get('token')},headers:{origin:app.origin}})).status(),200);await member.close();
 await confirmEmail();
 await page.goto(batchUrl);await page.getByRole('button',{name:'Undo this batch'}).click();
 await expect(page.locator('[data-undone]')).toBeVisible();
 await expect(page.locator('[data-kept]')).toHaveCount(1);
 assert.equal(await page.locator('[data-kept]').getAttribute('data-kept'),'amara.okafor@northwind.example.com');
 assert.deepEqual((await page.locator('[data-kept]').getAttribute('data-kept-reasons')).split(' '),['signed_in','status_changed','later_activity']);
 await expect(page.locator('[data-row-status=undone]')).toHaveCount(21);
 await shoot('undone');
 await page.goto(app.origin+'/app/activity');await expect(page.locator('[data-activity-detail]').first()).toBeVisible();await shoot('activity');
 await confirmEmail();await migrationJourney({app,edge,browser,owner:context,page,shoot});
 assert.deepEqual(errors,[],'no browser runtime errors');
 const measured={owner_actions:actions,owner_action_count:actions.length,screens:[...screens],people_admitted:22,invitations_sent:22};
 await writeFile(join(directory,'move-in-measurement.json'),JSON.stringify(measured,null,1)+'\n');
 console.log('Move-in journey:',JSON.stringify(measured));
});
