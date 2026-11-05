import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {chromium,expect} from '@playwright/test';
import {openApp} from './runtime.mjs';
import {service} from '../auth/automations-service.mjs';

test('automation editor publishes two steps, previews a person without remote changes and retains failed run history at desktop and phone widths in both themes',async t=>{
 const edge={},remote=await service(t,edge);
 const app=await openApp({outboundService:async request=>{
  const url=new URL(request.url);
  if(url.origin==='https://cloudflare-dns.com')return Response.json({Status:0,Answer:[{type:1,data:'93.184.216.34'}]});
  if(url.origin==='https://automation.example.com') {
   const response=await fetch(edge.edges[url.origin]+url.pathname,{method:request.method,headers:request.headers,body:request.body,duplex:'half',redirect:'manual'});
   return new Response(response.body,{status:response.status,headers:response.headers});
  }
  return fetch(request);
 }});t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--no-sandbox','--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),cdp=await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const directory=process.env.AUTH_SCREENSHOTS||join(tmpdir(),'auth-automations-journey');await mkdir(directory,{recursive:true});
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);
 const emailRequest=page.waitForResponse(r=>r.url().endsWith('/auth/identity/email/request'));await page.getByRole('button',{name:'Email me a sign-in link'}).click();assert.equal((await emailRequest).status(),202);
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();
 await expect(page).toHaveURL(app.origin+'/setup');await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');const registered=page.waitForResponse(r=>r.url().endsWith('/auth/identity/passkeys/register/verify'));await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);await page.waitForLoadState('domcontentloaded');
 const post=async(path,data,status=200)=>{const response=await context.request.post(app.origin+'/api/auth/'+path,{headers:{origin:app.origin},data});assert.equal(response.status(),status,await response.text());return response.json();};
 // Wait for the passkey registration navigation before using its authority.
 await expect.poll(async()=>{const response=await context.request.get(app.origin+'/api/auth/automations');return response.status();}).toBe(200);
 const group=await post('groups/create',{name:'Automation group'},201);
 const people=await(await context.request.get(app.origin+'/api/auth/people')).json();
 const owner=people.people?.find(p=>p.email===app.vars.OWNER_EMAIL)??people.find?.(p=>p.email===app.vars.OWNER_EMAIL);assert.ok(owner);
 await post('groups/add',{groupId:group.id,personId:owner.id});
 await page.goto(app.origin+'/app/apps');
 const panel=()=>page.getByRole('region',{name:'Automation settings'});
 await panel().getByText('Grant a connection',{exact:true}).click();
 const grant=panel().locator('form').filter({has:page.getByRole('button',{name:'Grant connection',exact:true})});
 for(const [label,value] of Object.entries({'Connection name':'Test REST','Service origin':'https://automation.example.com','OAuth token endpoint':'https://automation.example.com/token','OAuth client ID':'synthetic-auth-1','OAuth client secret':'synthetic-auth-2','OAuth scope':'synthetic-auth-4','Request signing secret':'synthetic-auth-3'}))await grant.getByLabel(label,{exact:true}).fill(value);
 await grant.getByRole('checkbox').check();await grant.getByRole('button',{name:'Grant connection',exact:true}).click();
 await expect(panel().getByRole('button',{name:'Publish version'})).toBeVisible();
 const snapshots=async(state,prepare=async()=>{})=>{
  for(const theme of ['light','dark'])for(const width of [1440,390]) {
   await page.setViewportSize({width,height:1000});await page.evaluate(theme=>{document.documentElement.dataset.theme=theme;localStorage.setItem('auth-theme',theme);},theme);await prepare();
   await panel().screenshot({path:join(directory,`automations-${state}-${theme}-${width}.png`)});
   if(width===1440)assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'automation settings fit desktop');
  }
  await page.setViewportSize({width:1440,height:1000});
 };
 await snapshots('editor');
 await panel().getByRole('button',{name:'Publish version'}).click();await expect(panel().getByRole('button',{name:'Dry run',exact:true})).toBeVisible();
 await panel().getByRole('button',{name:'Dry run',exact:true}).click();
 await expect(panel().getByText('Dry run complete. No outbound calls.',{exact:true})).toBeVisible();
 await expect(panel().locator('[data-automation-preview]')).toContainText('Value from step one');assert.deepEqual(remote.calls,[]);assert.deepEqual(remote.state,[]);
 await snapshots('dry-run');
 await panel().getByRole('button',{name:'Prepare run'}).click();await expect(panel().getByRole('button',{name:'Approve this run'})).toBeVisible();
 const model=await(await context.request.get(app.origin+'/api/auth/automations')).json(),run=model.runs.find(r=>r.state==='awaiting_approval');assert.ok(run);
 await panel().getByLabel('Type the exact run ID to approve',{exact:true}).fill(run.id);await panel().getByRole('button',{name:'Approve this run'}).click();
 await expect(panel().getByRole('button',{name:'Execute approved run'})).toBeVisible();remote.script.push({}, {},{status:503});
 await panel().getByRole('button',{name:'Execute approved run'}).click();
 await expect(panel().getByText('uncertain',{exact:true})).toBeVisible();await expect(panel().getByRole('alert')).toContainText('unresolved obligation');
 assert.deepEqual(remote.state,[{path:'/first',personId:owner.id},{path:'/second',personId:owner.id,responseId:'remote-record-1'}]);
 await snapshots('failure');
 // Shared shell icon controls have delayed hover and immediate focus tooltips.
 for(const control of await page.locator('[data-tooltip]:visible').all()) {
  const label=await control.getAttribute('data-tooltip');await control.hover();await page.waitForTimeout(350);await expect(page.getByRole('tooltip')).toHaveText(label);
  await page.mouse.move(0,0);await control.focus();await expect(page.getByRole('tooltip')).toHaveText(label);await page.keyboard.press('Escape');
 }
 assert.deepEqual(errors,[]);
});

test('administration reads survive expired email proof while writes and throttled email confirmation keep their security boundaries',async t=>{
 const app=await openApp();t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--no-sandbox','--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),cdp=await context.newCDPSession(page);
 await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const post=(path,data={})=>context.request.post(app.origin+path,{headers:{origin:app.origin},data});
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);
 const requested=page.waitForResponse(r=>r.url().endsWith('/auth/identity/email/request'));await page.getByRole('button',{name:'Email me a sign-in link'}).click();assert.equal((await requested).status(),202);
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();
 await expect(page).toHaveURL(app.origin+'/setup');await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify'));await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);
 await expect.poll(async()=>(await context.request.get(app.origin+'/api/auth/automations')).status()).toBe(200);
 // Passkey-only sign-in is the reported alternate trigger: ordinary reads must
 // work even when this browser has no current local-email confirmation at all.
 assert.equal((await post('/api/auth/signout')).status(),200);
 await page.goto(app.origin+'/signin');await page.getByRole('button',{name:'Continue with a passkey'}).click();await expect(page).toHaveURL(app.origin+'/app');
 assert.equal((await(await context.request.get(app.origin+'/api/auth/me')).json()).localEmailConfirmed,false);
 for(const path of ['/app','/app/people','/app/move-in','/app/roles','/app/agents','/app/permissions','/app/activity','/app/erasure','/app/methods','/app/organizations','/app/apps','/api/auth/automations']){
  assert.equal((await context.request.get(app.origin+path)).status(),200,path);
 }
 const apps=await page.goto(app.origin+'/app/apps');assert.equal(apps.status(),200);await expect(page.getByRole('heading',{level:1})).toBeVisible();
 const refused=await post('/api/auth/people/invite',{email:'ravi@example.com'});assert.equal(refused.status(),403);assert.equal((await refused.json()).error,'local_email_step_up_required');
 await page.goto(app.origin+'/app/methods');
 // Initial sign-in used one of the five hourly confirmations. Complete every
 // remaining link in this browser, then prove a blocked request is explicit.
 for(let i=0;i<4;i++){
  const response=page.waitForResponse(r=>r.url().endsWith('/auth/identity/email/request'));await page.getByRole('button',{name:'Confirm my email',exact:true}).click();assert.equal((await response).status(),202);
  await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/app/methods');
 }
 const blocked=page.waitForResponse(r=>r.url().endsWith('/auth/identity/email/request'));await page.getByRole('button',{name:'Confirm my email',exact:true}).click();const limited=await blocked;
 assert.equal(limited.status(),429);assert.ok(Number(limited.headers()['retry-after'])>0);
 await expect(page.locator('[data-auth-status]').first()).toContainText(/Too many email confirmation requests\. Try again in \d+ minutes?\. Your current email confirmation is not extended\./);
 await expect(page.getByRole('button',{name:'Confirm with a passkey',exact:true})).toBeVisible();
 // Reauthenticating with hardware is available before and after the mail
 // refusal, but must never manufacture the independent email proof for writes.
 assert.equal((await post('/api/auth/signout')).status(),200);
 await page.goto(app.origin+'/signin');await page.getByRole('button',{name:'Continue with a passkey'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const signed=page.waitForResponse(r=>r.url().endsWith('/passkeys/authenticate/verify'));await page.getByRole('button',{name:'Confirm with a passkey',exact:true}).click();assert.equal((await signed).status(),200);await expect(page).toHaveURL(app.origin+'/app/methods');
 const me=await(await context.request.get(app.origin+'/api/auth/me')).json();assert.equal(me.localEmailConfirmed,false);
 assert.equal((await post('/api/auth/people/invite',{email:'ravi@example.com'})).status(),403);
 assert.equal((await context.request.get(app.origin+'/app/apps')).status(),200);
});
