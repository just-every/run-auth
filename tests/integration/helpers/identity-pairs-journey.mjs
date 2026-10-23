import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from '../runtime.mjs';

export async function identityPairsJourney(t) {
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const json=async(response,status=200)=>{assert.equal(response.status(),status,await response.text());return response.json();};
 const post=(context,path,data)=>context.request.post(app.origin+path,{data,headers:{origin:app.origin}});
 const email=async(context,prefix,address)=>{await json(await post(context,prefix+'/auth/identity/email/request',{email:address}),202);const link=await app.link(prefix);await json(await post(context,prefix+'/auth/identity/email/confirm',{token:link.searchParams.get('token')}));};
 const context=async()=>{
  const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),cdp=await context.newCDPSession(page);page.on('dialog',dialog=>dialog.accept());
  await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  return {context,page};
 };
 const owner=await context();await email(owner.context,'','owner@example.com');await owner.page.goto(app.origin+'/setup');await owner.page.getByRole('checkbox').check();await owner.page.getByRole('button',{name:'Finish setup'}).click();
 const enroll=async(subject,prefix)=>{await subject.page.goto(app.origin+prefix+'/app/methods');const registered=subject.page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));await subject.page.getByRole('button',{name:'Register a passkey'}).click();await json(await registered);};
 await enroll(owner,'');
 await json(await post(owner.context,'/api/auth/people/invite',{email:'personal@example.com',name:'Alex Morgan'}),201);
 const person=await context();await email(person.context,'','personal@example.com');await enroll(person,'');
 const personId=(await json(await person.context.request.get(app.origin+'/api/auth/me'))).user.id;
 const organizations=[];
 for(const name of ['Linked employer A','Unproved employer B','Unlinked employer C']) {
  const org=await json(await post(owner.context,'/api/auth/organizations/create',{name}),201),prefix='/org/'+org.id;
  await email(owner.context,prefix,'owner@example.com');await enroll(owner,prefix);
  await json(await post(owner.context,prefix+'/api/auth/organizations/invite',{email:'personal@example.com',name:'Alex Morgan'}),201);
  organizations.push({...org,prefix});
 }
 const [a,b,c]=organizations;
 for(const org of [a,c]){await email(person.context,org.prefix,'personal@example.com');await enroll(person,org.prefix);}
 assert.equal((await post(person.context,'/api/auth/identity-pairs/options',{organizationId:b.id})).status(),401,'root proof supplies no unproved B membership');
 const offered=await json(await post(person.context,'/api/auth/identity-pairs/options',{organizationId:a.id}));
 await person.page.goto(app.origin+'/app/account');
 const sign=options=>person.page.evaluate(async value=>{
  const decode=text=>Uint8Array.from(atob(text.replace(/-/g,'+').replace(/_/g,'/')),character=>character.charCodeAt(0));
  value.challenge=decode(value.challenge);value.allowCredentials=value.allowCredentials.map(item=>({...item,id:decode(item.id)}));
  return (await navigator.credentials.get({publicKey:value})).toJSON();
 },options);
 const paired=await json(await post(person.context,'/api/auth/identity-pairs/confirm',{transaction:offered.transaction,rootResponse:await sign(offered.rootOptions),memberResponse:await sign(offered.memberOptions),confirm:true}),201);
 const own=await json(await person.context.request.get(app.origin+'/api/auth/identity-pairs/export'));assert.equal(own.links[0].handle,paired.handle);
 assert.deepEqual((await json(await owner.context.request.get(app.origin+'/api/auth/identity-pairs'))).links,[]);
 const shoot=async(name,page)=>{for(const width of [1440,390])for(const theme of ['light','dark']){
  await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await page.reload();await expect(page.locator('h1')).toBeVisible();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  const results=await new AxeBuilder({page}).analyze();assert.deepEqual(results.violations.filter(item=>['serious','critical'].includes(item.impact)).map(item=>item.id),[]);
  for(const control of await page.locator('[data-tooltip]:visible').all()){await control.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();await page.waitForTimeout(200);await expect(page.getByRole('tooltip')).toBeVisible();await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true);await page.keyboard.press('Escape');await control.blur();}
  await page.screenshot({path:join(directory,`identity-pairs-${name}-${width}-${theme}.png`),fullPage:true});
 }};
 await owner.page.goto(app.origin+'/app/people');await shoot('private-administration',owner.page);assert.ok(!(await owner.page.content()).includes(paired.handle));
 const key=(await json(await post(person.context,'/api/auth/identity-pairs/receipt-key',{confirm:true}),201)).receiptKey;
 await json(await post(owner.context,'/api/auth/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true}));
 const preview=await json(await post(owner.context,'/api/auth/erasure/preview',{kind:'person',target:personId}));
 const erased=await json(await post(owner.context,'/api/auth/erasure/confirm',{previewId:preview.id,confirmation:'ERASE',destinations:[]}));
 for(const org of organizations){assert.ok(!JSON.stringify(preview).includes(org.name));assert.ok(!JSON.stringify(erased).includes(org.name));}
 const notice=(await json(await owner.context.request.get(app.origin+a.prefix+'/api/auth/identity-release-notices'))).notices[0];assert.equal(notice.handle,paired.handle);
 for(const org of [b,c])assert.deepEqual((await json(await owner.context.request.get(app.origin+org.prefix+'/api/auth/identity-release-notices'))).notices,[]);
 await owner.page.goto(app.origin+a.prefix+'/app/activity');await expect(owner.page.locator('[data-followup-panel]')).toContainText('Identity release');await shoot('release-followup',owner.page);
 const receipt=await json(await post(person.context,'/api/auth/identity-pairs/receipt',{receiptKey:key}));assert.equal(receipt.notices.length,1);assert.equal(receipt.notices[0].organization,a.name);assert.equal(receipt.notices[0].state,'pending');assert.ok(receipt.message.includes('Memberships you did not link'));
 const anonymous=await browser.newContext(),signin=await anonymous.newPage();await signin.goto(app.origin+a.prefix+'/signin');await expect(signin.getByText('To ask for erasure of an employer membership',{exact:false})).toBeVisible();await shoot('employer-signin',signin);
 await anonymous.close();await person.context.close();await owner.context.close();
}
