import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {openApp} from '../runtime.mjs';
import {diagnosticReply} from '../../auth/diagnostic-edge.mjs';

export async function diagnosticJourney(t) {
 const edge={mode:'normal',requests:[]};
 const app=await openApp({agentModelKey:'synthetic-auth-1',outboundService:async request=>{
  if(new URL(request.url).hostname!=='api.anthropic.com')return fetch(request);
  const body=await request.json();edge.requests.push(body);
  return Response.json(diagnosticReply(body,edge.mode));
 }});t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const directory=process.env.AUTH_SCREENSHOTS||'./test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const shoot=async(name,prepare=async()=>{})=>{
  for(const width of [1440,390]) {
   await page.setViewportSize({width,height:1000});await page.reload();await prepare();
   await expect(page.getByRole('heading',{name:'Agents',exact:true})).toBeVisible();
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits '+width);
   const axe=await new AxeBuilder({page}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>v.id),[],name+' accessibility');
   for(const control of await page.locator('button,a').all())if(await control.isVisible()&&!(await control.innerText()).trim())assert.ok(await control.getAttribute('data-tooltip'),'icon-only controls have a tooltip');
   for(const control of await page.locator('[data-tooltip]:visible').all()) {
    await page.mouse.move(0,0);await control.blur();await control.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();await page.waitForTimeout(200);await expect(page.getByRole('tooltip')).toBeVisible();await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true);await page.keyboard.press('Escape');await control.blur();
   }
   await page.screenshot({path:join(directory,`diagnostic-${name}-${width}.png`),fullPage:true});
   if(await page.locator('.proposal-review').count())await page.locator('.proposal-review').screenshot({path:join(directory,`diagnostic-${name}-${width}-panel.png`)});
  }
  await page.setViewportSize({width:1440,height:1000});
 };
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await page.getByRole('button',{name:'Email me a sign-in link'}).click();await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');const registration=page.waitForResponse(r=>r.url().endsWith('/passkeys/register/verify'));await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registration).status(),200);
 const post=async(path,data)=>{const response=await context.request.post(app.origin+'/api/auth'+path,{data,headers:{origin:app.origin}});assert.ok(response.ok(),await response.text());return response.json();};
 await post('/people/invite',{email:'dana@northwind.example.com',name:'Dana Montgomery'});
 const employee=await browser.newContext();t.after(()=>employee.close());
 await employee.request.post(app.origin+'/auth/identity/email/request',{data:{email:'dana@northwind.example.com'},headers:{origin:app.origin}});const link=await app.link();assert.equal((await employee.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:link.searchParams.get('token')},headers:{origin:app.origin}})).status(),200);
 const people=await(await context.request.get(app.origin+'/api/auth/people')).json(),person=people.find(p=>p.email==='dana@northwind.example.com');
 const company=await post('/oidc-apps/create',{name:'Northwind expense approvals',authMethod:'none',redirectUris:'https://expenses.northwind.example.com/old-callback',postLogoutRedirectUris:'https://expenses.northwind.example.com/signed-out'});
 await post('/company-apps/assign',{appId:company.id,principalType:'person',principalId:person.id,role:'expense-reviewer'});
 const callback='https://expenses.northwind.example.com/sign-in/callback';
 const failed=await employee.request.get(app.origin+'/oidc/authorize?'+new URLSearchParams({client_id:company.clientId,redirect_uri:callback,response_type:'code',scope:'openid email',state:'synthetic-auth-1'}),{maxRedirects:0});assert.equal(failed.status(),400);
 await page.goto(app.origin+'/app/agents');await page.getByLabel('Key label').fill('Northwind sign-in repair agent');await page.getByRole('button',{name:'Mint a key'}).click();await expect(page.locator('[data-agent-secret]')).toBeVisible();await page.reload();
 const openForm=async()=>{await page.getByText('Prepare a repair',{exact:true}).click();await page.getByLabel('Company app',{exact:true}).selectOption(company.id);await page.getByLabel('Assigned test employee',{exact:true}).selectOption(person.id);await page.getByLabel('Expected callback (callback repair)').fill(callback);};
 await shoot('consent',openForm);
 const prepare=async()=>{
  await page.goto(app.origin+'/app/agents');await openForm();await page.getByRole('checkbox',{name:/I approve sending/}).check();const prepared=page.waitForResponse(r=>r.url().endsWith('/api/auth/agents/diagnose'));await page.getByRole('button',{name:'Diagnose and prepare'}).click();assert.equal((await prepared).status(),201);await expect(page).toHaveURL(/\/app\/agents\?proposal=.+/);return {id:new URL(page.url()).searchParams.get('proposal')};
 };
 const proposal=await prepare();await shoot('review',async()=>{for(const source of await page.getByText('Approved sources and citations',{exact:true}).all())await source.click();});
 const approved=page.waitForResponse(r=>r.url().endsWith('/api/auth/agents/approve'));await page.getByRole('button',{name:'Approve with passkey'}).click();assert.equal((await approved).status(),200);await expect(page.locator('[data-proposal-outcome]')).toContainText('Repair applied');await shoot('applied');
 // The browser follows the repaired callback handoff and then ends only
 // this employee's session. The native journey separately runs the complete
 // token exchange, UserInfo and denied-token logout probe.
 const handed=await employee.request.get(app.origin+'/oidc/authorize?'+new URLSearchParams({client_id:company.clientId,redirect_uri:callback,response_type:'code',scope:'openid email',state:'synthetic-auth-2',code_challenge:'synthetic-auth-3'.padEnd(43,'x'),code_challenge_method:'S256'}),{maxRedirects:0});
 assert.equal(handed.status(),302);const destination=new URL(handed.headers().location);assert.equal(destination.origin+destination.pathname,callback);assert.ok(destination.searchParams.get('code'));
 assert.equal((await employee.request.post(app.origin+'/api/auth/signout',{data:{},headers:{origin:app.origin}})).status(),200);
 assert.equal((await employee.request.get(app.origin+'/api/auth/me')).status(),401);
 edge.mode='uncertain';await prepare();await shoot('uncertain');await expect(page.getByRole('button',{name:'Approve with passkey'})).toHaveCount(0);await expect(page.locator('[data-diagnostic-effect]').first()).toContainText('Uncertain diagnosis');
 assert.ok(!JSON.stringify(edge.requests).includes('dana@northwind.example.com'));
 assert.deepEqual(errors,[]);
}
