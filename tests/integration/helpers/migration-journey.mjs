import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {expect} from '@playwright/test';

export async function migrationJourney({app,edge,browser,owner,page,shoot}) {
 const json=async(response,status=200)=>{assert.equal(response.status(),status,await response.text());return response.json();};
 const post=(context,path,data)=>context.request.post(app.origin+path,{data,headers:{origin:app.origin}});
 const people={format:'auth-custom-directory',version:1,people:[{directory_id:'synthetic-auth-91',email:'migrating@example.com',name:'Jordan Rivera',disabled:false,history:[{at:'2025-06-01T00:00:00Z',values:{department:'Engineering'}}]}]};
 const batch=await json(await post(owner,'/api/auth/move-in/stage',{fileName:'reviewed-custom.json',exportDate:'2026-10-23',text:JSON.stringify(people)}),201);
 await page.goto(app.origin+'/app/move-in?batch='+batch.batchId);await expect(page.getByRole('region',{name:'Staged people table'})).toContainText('Jordan Rivera');await shoot('custom-reviewed');
 await page.getByRole('button',{name:'Admit selected'}).click();await expect(page.locator('[data-row-status=admitted]')).toHaveCount(1);
 const directory=await json(await owner.request.get(app.origin+'/api/auth/people')),person=directory.find(row=>row.email==='migrating@example.com');assert.ok(person);
 const credential='synthetic-auth-92',password='synthetic-auth-93';
 edge.responses.set('/legacy-migration',(body,record)=>{assert.equal(record.headers['bridge-signature'],'v1,'+createHmac('sha256',credential).update(record.headers['bridge-call-id']+'.'+record.headers['bridge-timestamp']+'.'+record.body).digest('base64url'));return {body:{authenticated:body.password===password,subject:body.subject}};});
 const bridge=await json(await post(owner,'/api/auth/migration/bridge/register',{url:'https://hooks.example.com/legacy-migration',credential,expiresAt:Date.now()+3600000,subjects:[{sourceSystem:'custom',sourceSubject:'synthetic-auth-91',personId:person.id,batchId:batch.batchId}],confirm:true}),201);
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),mine=await context.newPage(),cdp=await context.newCDPSession(mine);
 await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 assert.equal((await post(context,'/api/auth/migration/bridge/login',{bridgeId:bridge.id,sourceSubject:'synthetic-auth-91',password:'synthetic-auth-wrong'})).status(),403);
 await json(await post(context,'/api/auth/migration/bridge/login',{bridgeId:bridge.id,sourceSubject:'synthetic-auth-91',password}),202);
 assert.equal((await context.request.get(app.origin+'/api/auth/me')).status(),401,'old password itself grants no Auth session');
 const link=await app.link();await mine.goto(link.href);await mine.getByRole('button',{name:'Continue to Auth'}).click();
 await mine.goto(app.origin+'/app/methods');const registered=mine.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify')),loaded=mine.waitForEvent('load');await mine.getByRole('button',{name:'Register a passkey'}).click();await json(await registered);await loaded;
 const me=await json(await context.request.get(app.origin+'/api/auth/me'));assert.equal(me.user.id,person.id);assert.ok(me.user.amr.includes('hwk'));
 // The existing screenshot helper belongs to the owner page; inspect the
 // resulting enrollment through the same normal People door there.
 await page.bringToFront();await page.goto(app.origin+'/app/people');await expect(page.getByText('migrating@example.com',{exact:true})).toBeVisible();await shoot('custom-migrated');
 await json(await post(owner,'/api/auth/migration/bridge/disable',{bridgeId:bridge.id}));assert.equal((await post(context,'/api/auth/migration/bridge/login',{bridgeId:bridge.id,sourceSubject:'synthetic-auth-91',password})).status(),403);
 await context.close();
}
