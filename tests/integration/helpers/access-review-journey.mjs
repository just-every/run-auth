import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from '../runtime.mjs';

export async function accessReviewJourney(t) {
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const root=await browser.newContext({viewport:{width:1440,height:1000}}),owner=await root.newPage(),directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const errors=[];
 const hardware=async(context,page)=>{page.on('pageerror',e=>errors.push(e.message));const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});};
 await hardware(root,owner);
 const post=async(context,path,data,status=200)=>{const response=await context.request.post(app.origin+'/api/auth/'+path,{data,headers:{origin:app.origin}});assert.equal(response.status(),status,path+' '+await response.text());return response.json();};
 const signin=async(context,page,email,setup=false)=>{
  await page.goto(app.origin+'/signin?returnTo='+encodeURIComponent(setup?'/setup':'/app/methods'));
  await page.getByLabel('Email address',{exact:true}).fill(email);await page.getByRole('button',{name:'Email me a sign-in link'}).click();
  await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();
  if(setup){await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await page.goto(app.origin+'/app/methods');}
  await page.waitForURL(app.origin+'/app/methods');await page.waitForLoadState('load');
  const response=page.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify')),loaded=page.waitForEvent('load');await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await response).status(),200);await loaded;
 };
 const shoot=async(name,page,panels,prepare=async()=>{})=>{for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});await page.reload();await prepare();await expect(page.locator('h1')).toBeVisible();
  await page.screenshot({path:join(directory,`access-${name}-${width}.png`),fullPage:true});
  const layout=await page.evaluate(()=>({fits:document.documentElement.scrollWidth<=innerWidth,overflow:[...document.querySelectorAll('main *')].filter(e=>e.scrollWidth>e.clientWidth+1&&getComputedStyle(e).overflowX==='visible').slice(-6).map(e=>({tag:e.tagName,classes:e.className,text:e.textContent.slice(0,100),width:e.clientWidth,scroll:e.scrollWidth}))}));
  assert.ok(layout.fits,name+' fits '+width+' '+JSON.stringify(layout));
  const axe=await new AxeBuilder({page}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],name+' '+width);
  await page.screenshot({path:join(directory,`access-${name}-${width}.png`),fullPage:true});
  for(const selector of panels){const panel=page.locator(selector).first();if(await panel.count())await panel.screenshot({path:join(directory,`access-${name}-${selector.replace(/[^a-z-]/g,'')}-${width}.png`)});}
 }await page.setViewportSize({width:1440,height:1000});};
 const saved=async(page,action)=>{const loaded=page.waitForEvent('load');await action();await loaded;};
 await signin(root,owner,app.vars.OWNER_EMAIL,true);
 const managerData=await post(root,'directory/onboard',{email:'morgan@northwind.example.com',name:'Morgan Ellis',kind:'employee',set:{department:'Product operations'}},201);
 const workerData=await post(root,'directory/onboard',{email:'casey@contractors.example.com',name:'Casey Jordan',kind:'contractor',set:{department:'Product operations'}},201);
 const serviceData=await post(root,'directory/onboard',{email:'pipeline@northwind.example.com',name:'Release pipeline',kind:'service',invite:false},201);
 const managers=await browser.newContext(),manager=await managers.newPage();await hardware(managers,manager);await signin(managers,manager,'morgan@northwind.example.com');
 // A fresh ordinary passkey sign-in carries no local email confirmation.
 await post(managers,'signout',{});await manager.goto(app.origin+'/signin');
 await manager.getByRole('button',{name:'Continue with a passkey'}).click();await manager.waitForURL(app.origin+'/app');
 const me=await(await managers.request.get(app.origin+'/api/auth/me')).json();assert.equal(me.localEmailConfirmed,false);
 const workers=await browser.newContext(),worker=await workers.newPage();await hardware(workers,worker);await signin(workers,worker,'casey@contractors.example.com');
 const group=await post(root,'groups/create',{name:'Quarterly customer migration team'},201);await post(root,'groups/owners/add',{groupId:group.id,personId:managerData.id});
 await manager.goto(app.origin+'/app/account');
 const membership=manager.locator('[data-access-decision="group"]');await membership.getByLabel("Person's exact email or ID").fill('casey@contractors.example.com');await membership.getByLabel('Reason',{exact:true}).fill('Customer migration handover');
 await saved(manager,()=>membership.getByRole('button',{name:'Confirm membership with passkey'}).click());
 await expect(manager.locator('[data-access-decisions]')).toContainText('Casey Jordan');
 await shoot('ordinary-membership',manager,['[data-access-decisions]']);
 const appData=await post(root,'company-apps/create',{name:'Salesforce customer operations',entityId:'https://salesforce.example.com',acsUrl:'https://salesforce.example.com/acs'},201);
 await post(root,'decisions/privilege',{kind:'app',targetId:appData.id,privileged:false});await post(root,'requests/policy',{appId:appData.id,deciderId:managerData.id,maxDurationMs:3600000});
 const request=await post(workers,'requests/create',{appId:appData.id,purpose:'Reconcile customer migration handover',role:'reader',durationMs:3600000},201);
 await manager.reload();
 const requestForm=manager.locator('[data-access-decision="request"]');await requestForm.getByLabel('Decision reason').fill('Approved customer handover read access');
 await saved(manager,()=>requestForm.getByRole('button',{name:/Approve.*passkey/}).click());
 await expect(manager.locator('[data-access-requests]')).toContainText('Approved temporary access');
 await shoot('request-approved',manager,['[data-access-requests]']);
 await post(root,'company-apps/assign',{appId:appData.id,principalType:'person',principalId:managerData.id,role:'reader'});
 const buildApp=await post(root,'company-apps/create',{name:'Release engineering workspace',entityId:'https://engineering.example.com',acsUrl:'https://engineering.example.com/acs'},201);
 await post(root,'company-apps/assign',{appId:buildApp.id,principalType:'person',principalId:serviceData.id,role:'editor'});
 await owner.goto(app.origin+'/app/activity');
 const hierarchy=owner.locator('[data-access-form=role-order]').filter({has:owner.locator(`[name=appId][value="${buildApp.id}"]`)});
 await hierarchy.locator('xpath=..').locator('summary').click();
 await hierarchy.getByLabel('Roles from least to most authority').fill('viewer\neditor');
 await saved(owner,()=>hierarchy.getByRole('button',{name:'Publish role hierarchy'}).click());
 const create=owner.locator('[data-access-review-create]');
 await create.getByLabel('Review name').fill('Northwind quarterly certification');await create.locator('[name=reviewerId]').selectOption(managerData.id);
 await create.getByLabel('Due at').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));
 await create.getByLabel('Period start').fill('2026-07-01');await create.getByLabel('Period end').fill(new Date(Date.now()-86400000).toISOString().slice(0,10));
 await saved(owner,()=>create.getByRole('button',{name:'Create quarterly review'}).click());
 const view=await(await root.request.get(app.origin+'/api/auth/reviews')).json(),review=view.reviews[0],item=review.items.find(i=>i.subject_id===workerData.id);
 assert.ok(item);
 // Delegation is a hardware-and-email administrator write.
 const self=review.items.find(i=>i.subject_id===managerData.id);await post(root,'reviews/delegate',{itemId:self.id,reviewerId:(await(await root.request.get(app.origin+'/api/auth/me')).json()).user.id,reason:'Independent owner review of manager access'});
 await manager.reload();const serviceItem=review.items.find(i=>i.subject_id===serviceData.id);assert.ok(serviceItem);
 const reduction=manager.locator(`[data-review-item="${serviceItem.id}"] [data-access-decision="review"]`);await reduction.getByLabel('Reduce to app role').selectOption('viewer');await reduction.getByLabel('Decision reason').fill('Pipeline needs read access only');
 await saved(manager,()=>reduction.getByRole('button',{name:'Reduce access with passkey'}).click());
 const itemForm=manager.locator(`[data-review-item="${item.id}"] [data-access-decision="review"]`);await itemForm.getByLabel('Decision reason').fill('Contract handover complete; remove access');
 await saved(manager,()=>itemForm.getByRole('button',{name:'Revoke access with passkey'}).click());
 await expect(manager.locator('[data-access-reviews]')).toContainText('remote removal unverified');
 await shoot('review-unfinished',manager,['[data-access-reviews]']);
 await owner.reload();const certification=owner.locator(`[data-review-item="${self.id}"] [data-access-decision="review"]`);await certification.getByLabel('Decision reason').fill('Manager still needs customer operations access');
 await saved(owner,()=>certification.getByRole('button',{name:'Certify access with passkey'}).click());
 const exported=await(await root.request.get(app.origin+'/api/auth/reviews/export?id='+review.id)).json();assert.equal(exported.review.completion.complete,false);assert.equal(exported.review.completion.unfinished,2);
 await post(root,'reviews/close',{id:review.id},409);
 await post(root,'decisions/privilege',{kind:'group',targetId:group.id,privileged:true});await manager.reload();await expect(manager.locator('[data-access-decisions]')).toContainText('Privileged access');assert.equal(await manager.locator('[data-access-decision="group"]').count(),0);
 await shoot('privileged-refused',manager,['[data-access-decisions]']);
 await owner.goto(app.origin+'/app/activity');await expect(owner.locator('[data-retention]')).toBeVisible();
 const retention=owner.locator('[data-retention]');await retention.locator('[name="audit.unit"]').selectOption('days');await retention.locator('[name="audit.value"]').fill('30');await retention.getByRole('checkbox',{name:/confirm/i}).check();
 await retention.getByRole('button',{name:/Save retention/i}).click();assert.equal(await retention.locator('[name="audit.value"]').evaluate(input=>input.validity.rangeUnderflow),true);
 await retention.locator('[name="audit.value"]').fill('90');await saved(owner,()=>retention.getByRole('button',{name:/Save retention/i}).click());
 await shoot('retention-refused',owner,['[data-retention]','[data-access-reviews]']);
 await shoot('reviewer-reminder-policy',owner,['[data-followup-panel]'],async()=>{await owner.locator('[data-followup-panel]').getByText('Reminder settings and approved recipients',{exact:true}).click();await expect(owner.getByRole('checkbox',{name:'Current access reviewer'})).toBeVisible();});
 assert.deepEqual(errors,[]);
}
