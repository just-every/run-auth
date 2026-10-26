import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {join} from 'node:path';
import {expect} from '@playwright/test';
import {openApp} from '../runtime.mjs';

export async function deliveryBrowser(t,browser,directory) {
 const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),sent=[];
 let providerStatus=202;
 const app=await openApp({mail:{provider:'sendgrid',key:'synthetic-auth-1',verificationKey:keys.publicKey.export({type:'spki',format:'der'}).toString('base64')},outboundService:async request=>{
  if(new URL(request.url).origin==='https://api.sendgrid.com') {
   sent.push(await request.json());return new Response(null,{status:providerStatus});
  }
  return fetch(request);
 }});t.after(()=>app.close());await app.claim();
 const context=await browser.newContext({viewport:{width:1440,height:1000}});t.after(()=>context.close());
 const page=await context.newPage(),cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);
 const requested=page.waitForResponse(answer=>answer.url().endsWith('/auth/identity/email/request'));
 await page.getByRole('button',{name:'Email me a sign-in link'}).click();assert.equal((await requested).status(),202);
 await expect.poll(()=>sent.length).toBeGreaterThan(0);
 await page.goto(sent[0].content.find(item=>item.type==='text/plain').value.match(/https?:\/\/\S+$/)[0]);
 await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(answer=>answer.url().endsWith('/auth/identity/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);
 await expect(page.getByRole('button',{name:'Register a passkey'})).toBeVisible();
 const panel=()=>page.getByRole('region',{name:'Mail delivery'});
 const snapshot=async(name,state)=>{
  for(const width of [1440,390]) {
   await page.setViewportSize({width,height:1000});await page.goto(app.origin+'/app/methods');
   await panel().getByText('Recent delivery attempts',{exact:true}).click();await expect(panel()).toContainText(state);
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits '+width);
   await page.screenshot({path:join(directory,`security-mail-${name}-${width}.png`),fullPage:true});
  }
 };
 await snapshot('accepted','accepted');
 // Exercise the actual production adapter's 429 and 503 classifications.
 for(const [status,name] of [[429,'rate limited'],[503,'uncertain']]) {
  providerStatus=status;
  const response=await context.request.post(app.origin+'/api/auth/organizations/invite',{headers:{origin:app.origin},data:{email:`delivery-${status}@example.com`,name:status===429?'Avery Collins':'Jordan Rivera'}});
  assert.equal(response.status(),503);await snapshot(status===429?'throttled':'unavailable',name);
 }
 const message=sent[0],timestamp=String(Math.floor(Date.now()/1000)),body=JSON.stringify([{event:'bounce',email:app.vars.OWNER_EMAIL,sg_event_id:'synthetic-auth-browser-1',timestamp:Number(timestamp),...message.custom_args}]);
 const signature=sign('sha256',Buffer.from(timestamp+body),keys.privateKey).toString('base64');
 const reconciled=await context.request.post(app.origin+'/api/auth/delivery/sendgrid',{headers:{'content-type':'application/json','x-twilio-email-event-webhook-timestamp':timestamp,'x-twilio-email-event-webhook-signature':signature},data:body});assert.equal(reconciled.status(),200);
 await snapshot('bounced','bounced');await expect(panel()).toContainText('1 suppressed recipient');
 const before=sent.length;
 const refused=await context.request.post(app.origin+'/auth/identity/email/request',{headers:{origin:app.origin},data:{email:app.vars.OWNER_EMAIL}});assert.equal(refused.status(),503);
 assert.equal(sent.length,before);await snapshot('suppressed','suppressed');
}
