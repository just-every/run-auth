import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {createResourceAuthorizer} from '../../../packages/delegated-resource/index.mjs';
import {expect} from '@playwright/test';

// The browser owns consent and approval; a separate key-holding agent owns its
// signed request, OAuth assertion and exact native API invocation.
export async function delegatedAssignmentJourney({app,browser,owner,page,shoot}) {
 const ok=async(response,status=200)=>{const actual=response.status();assert.equal(actual,status,actual===status?'':await response.text());};
 const json=async(response,status=200)=>{await ok(response,status);return response.json();};
 const post=(context,path,data)=>context.request.post(app.origin+path,{data,headers:{origin:app.origin}});
 const email=async(context,address)=>{
  await json(await post(context,'/auth/identity/email/request',{email:address}),202);
  await json(await post(context,'/auth/identity/email/confirm',{token:(await app.link()).searchParams.get('token')}));
 };
 const person=async(address,name)=>{
  await json(await post(owner,'/api/auth/people/invite',{email:address,name}),201);
  const context=await browser.newContext({viewport:{width:1440,height:1000}}),mine=await context.newPage();
  mine.on('dialog',dialog=>dialog.accept());
  const cdp=await context.newCDPSession(mine);await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await email(context,address);
  const me=await json(await context.request.get(app.origin+'/api/auth/me'));
  return {context,page:mine,id:me.user.id,address};
 };
 const worker=await person('riley@northwind.example.com','Riley Chen');
 const reviewer=await person('morgan@northwind.example.com','Morgan Patel');
 await json(await post(owner,'/api/auth/people/role',{personId:reviewer.id,role:'admin'}));
 await email(reviewer.context,reviewer.address);
 for(const subject of [worker,reviewer]) {
  await subject.page.goto(app.origin+'/app/methods');
  const enrolled=subject.page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
  await subject.page.getByRole('button',{name:'Register a passkey'}).click();await ok(await enrolled);
  assert.ok((await json(await subject.context.request.get(app.origin+'/api/auth/me'))).user.amr.includes('hwk'),'enrollment creates an independently proven passkey session');
 }
 const company=await json(await post(owner,'/api/auth/company-apps/create',{name:'Northwind project documents',entityId:'https://documents.example.com',acsUrl:'https://documents.example.com/acs',assign:[]}),201);
 await json(await post(owner,'/api/auth/company-apps/assign',{appId:company.id,principalType:'person',principalId:worker.id,role:'reader'}));
 const keys=await generateKeyPair('ES256'),jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-44',alg:'ES256',use:'sig'};
 await page.goto(app.origin+'/app/agents');
 const registration=page.locator('[data-delegated-agent-register]');
 await registration.getByLabel('Agent name',{exact:true}).fill('Project access assistant');
 await registration.getByLabel('Agent task purpose').fill('Apply employee-approved project document roles');
 await registration.getByLabel('Task agent public JWKS').fill(JSON.stringify({keys:[jwk]}));
 await registration.getByLabel('Allowed apps').selectOption(company.id);
 await registration.getByLabel('Accountable employees').selectOption(worker.id);
 await registration.getByLabel('Agent registration expiry').fill(new Date(Date.now()+86400000).toISOString().slice(0,16));
 const registered=page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/agents/register'));
 await registration.getByRole('button',{name:'Register task agent'}).click();await ok(await registered,201);
 await expect(page.locator('[data-task-agent-registration] .data-row',{hasText:'Project access assistant'})).toBeVisible();
 const agent=(await json(await owner.request.get(app.origin+'/api/auth/delegations'))).agents.find(item=>item.name==='Project access assistant');assert.ok(agent);
 await expect(page.locator('[data-task-agent-registration]')).toContainText(agent.clientId);
 await shoot('task-agent-registered',page);
 const target=app.origin+'/api/auth/admin/v1/delegated-assignments/execute';
 const hash=value=>createHash('sha256').update(value).digest('base64url');
 const assertion=(audience,claims)=>new SignJWT(claims).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(agent.clientId).setSubject(agent.clientId).setAudience(audience).setIssuedAt().setExpirationTime('2m').setJti(randomUUID()).sign(keys.privateKey);
 const task=role=>({organizationId:'root',accountablePersonId:worker.id,personId:worker.id,purpose:'Update my project documents assignment',apiId:'auth.assignments',audience:target,resource:`assignment:${company.id}:person:${worker.id}`,operation:'assignment.update',appId:company.id,role,scopes:['assignments.manage'],expiresAt:Date.now()+3600000});
 const create=async effect=>{
  const response=await fetch(app.origin+'/api/auth/delegations/request',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({clientId:agent.clientId,clientAssertion:await assertion(app.origin+'/api/auth/delegations/request',{delegation_use:'request',request_hash:hash(JSON.stringify(effect))}),task:effect})});
  assert.equal(response.status,201,await response.clone().text());return {...await response.json(),task:effect};
 };
 const approve=async(grant,{screens=false}={})=>{
  await worker.page.goto(app.origin+'/app/account?delegation='+grant.grantId);
  await expect(worker.page.locator('[data-delegation-review]')).toContainText('reader');
  await expect(worker.page.locator('[data-delegation-review]')).toContainText(target);
  if(screens)await shoot('task-consent',worker.page);
  const consented=worker.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/consent'));
  await worker.page.getByRole('button',{name:'Consent to this task'}).click();await ok(await consented);
  await reviewer.page.goto(app.origin+'/app/account?delegation='+grant.grantId);
  await expect(reviewer.page.getByRole('button',{name:'Approve this task with passkey'})).toBeVisible();
  if(screens)await shoot('task-independent-approval',reviewer.page);
  const approved=reviewer.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/approve'));
  await reviewer.page.getByRole('button',{name:'Approve this task with passkey'}).click();await ok(await approved);
  await expect(reviewer.page.locator('[data-delegation-state]')).toHaveText('approved');
 };
 const details=grant=>[{type:'auth_assignment_task',locations:[grant.task.audience],actions:[grant.task.operation],identifier:grant.task.resource,grant_id:grant.grantId,effect_digest:grant.effectDigest,task:grant.task}];
 const dpop=(url,nonce,bearer)=>new SignJWT({htm:'POST',htu:url,...(nonce?{nonce}:{}),...(bearer?{ath:hash(bearer)}:{})}).setProtectedHeader({typ:'dpop+jwt',alg:'ES256',jwk}).setIssuedAt().setJti(randomUUID()).sign(keys.privateKey);
 const token=async grant=>{
  const url=app.origin+'/oidc/token',clientAssertion=await assertion(url,{delegation_use:'token',grant_id:grant.grantId,effect_digest:grant.effectDigest});
  const fields=new URLSearchParams({grant_type:'client_credentials',client_id:agent.clientId,grant_id:grant.grantId,resource:target,authorization_details:JSON.stringify(details(grant)),scope:'assignments.manage',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:clientAssertion});
  // RFC 9449 nonce negotiation is an explicit two-message protocol exchange.
  const challenge=await fetch(url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',DPoP:await dpop(url)},body:fields});
  assert.equal(challenge.status,400);const nonce=challenge.headers.get('DPoP-Nonce');assert.ok(nonce);await challenge.body.cancel();
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',DPoP:await dpop(url,nonce)},body:fields});
  assert.equal(response.status,200,await response.clone().text());const body=await response.json();assert.equal(body.token_type,'DPoP');return body.access_token;
 };
 const execute=async(grant,effect,bearer)=>{
  const body=JSON.stringify({grantId:grant.grantId,effectDigest:grant.effectDigest,task:effect});
  const challenge=await fetch(target,{method:'POST',headers:{authorization:'DPoP '+bearer,'content-type':'application/json',DPoP:await dpop(target,null,bearer)},body});
  const nonce=challenge.headers.get('DPoP-Nonce');
  if(!nonce)return challenge; // A final authority refusal has no nonce challenge.
  assert.equal(challenge.status,401);await challenge.body.cancel();
  return fetch(target,{method:'POST',headers:{authorization:'DPoP '+bearer,'content-type':'application/json',DPoP:await dpop(target,nonce,bearer)},body});
 };
 const effect=task('editor'),grant=await create(effect);await approve(grant,{screens:true});
 const bearer=await token(grant),executed=await execute(grant,effect,bearer);assert.equal(executed.status,200,await executed.clone().text());
 await worker.page.reload();await expect(worker.page.locator('[data-delegation-state]')).toHaveText('completed');
 await shoot('task-completed',worker.page);
 const reverse=worker.page.locator('[data-delegation-review]');const requested=worker.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/reverse'));
 await reverse.getByRole('button',{name:'Request reversal'}).click();await ok(await requested);
 await expect(reverse.locator('[data-reversal-state]')).toContainText('assignment stays unchanged');await shoot('task-reversal-requested',worker.page);
 const pendingEffect=task('reader'),pending=await create(pendingEffect);await approve(pending);
 const pendingToken=await token(pending);await worker.page.goto(app.origin+'/app/account');
 const row=worker.page.locator(`[data-delegated-task="${pending.grantId}"]`);
 await expect(row).toContainText('approved');await shoot('task-active',worker.page);
 const revoked=worker.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/revoke'));
 await row.getByRole('button',{name:'Revoke task'}).click();await ok(await revoked);
 await expect(row).toContainText('revoked');await shoot('task-revoked',worker.page);
 assert.equal((await execute(pending,pendingEffect,pendingToken)).status,401,'the existing task bearer loses its next target request');

 // The same human ceremonies authorize an external operation. Its resource
 // calls Auth before execution, and an issued token loses its next call after
 // the employee uses the ordinary My account revoke control.
 for(const kind of ['mcp','api']) {
  const resourceKeys=await generateKeyPair('ES256'),resourceJwk={...await exportJWK(resourceKeys.publicKey),kid:'synthetic-auth-63',alg:'ES256',use:'sig'};
  const resource=await json(await post(owner,'/api/auth/delegations/resources/register',{name:kind==='mcp'?'Expense MCP tools':'Expense API',kind,audience:`https://${kind}.example.com/tasks`,scopes:['expenses.update'],detailType:kind==='mcp'?'mcp_tool_task':'expense_task',operations:[kind==='mcp'?'update_expense':'expense.update'],jwks:{keys:[resourceJwk]}}),201);
  const externalAgent=await json(await post(owner,'/api/auth/delegations/agents/register',{name:'Expense assistant',purpose:'One approved expense update',jwks:{keys:[jwk]},appIds:[],resourceIds:[resource.id],personIds:[worker.id],expiresAt:Date.now()+86400000}),201);
  const effect={organizationId:'root',accountablePersonId:worker.id,personId:worker.id,purpose:'Categorize my approved travel expense',apiId:resource.id,resourceId:resource.id,detailType:resource.detailType,audience:resource.audience,resource:'expense:synthetic-auth-1',operation:resource.operations[0],scopes:['expenses.update'],expiresAt:Date.now()+3600000,arguments:{category:'Travel'}};
  const externalAssertion=(url,claims)=>new SignJWT(claims).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(externalAgent.clientId).setSubject(externalAgent.clientId).setAudience(url).setIssuedAt().setExpirationTime('2m').setJti(randomUUID()).sign(keys.privateKey);
  const filed=await fetch(app.origin+'/api/auth/delegations/request',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({clientId:externalAgent.clientId,clientAssertion:await externalAssertion(app.origin+'/api/auth/delegations/request',{delegation_use:'request',request_hash:hash(JSON.stringify(effect))}),task:effect})});
  assert.equal(filed.status,201,await filed.clone().text());const grant=await filed.json();
  await worker.page.goto(app.origin+'/app/account?delegation='+grant.grantId);
  const review=worker.page.locator('[data-delegation-review]');await expect(review).toContainText(resource.name);await expect(review).toContainText(effect.operation);await expect(review).toContainText('Travel');
  await shoot(kind+'-task-consent',worker.page);
  const consented=worker.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/consent'));
  await worker.page.getByRole('button',{name:'Consent to this task'}).click();await ok(await consented);
  await reviewer.page.goto(app.origin+'/app/account?delegation='+grant.grantId);await shoot(kind+'-task-approval',reviewer.page);
  const approved=reviewer.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/approve'));
  await reviewer.page.getByRole('button',{name:'Approve this task with passkey'}).click();await ok(await approved);
  const tokenUrl=app.origin+'/oidc/token',clientAssertion=await externalAssertion(tokenUrl,{delegation_use:'token',grant_id:grant.grantId,effect_digest:grant.effectDigest});
  const form=new URLSearchParams({grant_type:'client_credentials',client_id:externalAgent.clientId,grant_id:grant.grantId,resource:resource.audience,scope:'expenses.update',client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:clientAssertion});
  const challenge=await fetch(tokenUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',DPoP:await dpop(tokenUrl)},body:form});
  assert.equal(challenge.status,400);const tokenNonce=challenge.headers.get('dpop-nonce');assert.ok(tokenNonce);await challenge.body.cancel();
  const issued=await fetch(tokenUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',DPoP:await dpop(tokenUrl,tokenNonce)},body:form});
  assert.equal(issued.status,200,await issued.clone().text());const externalToken=(await issued.json()).access_token;
  await worker.page.goto(app.origin+'/app/account');const externalRow=worker.page.locator(`[data-delegated-task="${grant.grantId}"]`);await expect(externalRow).toContainText('approved');
  await shoot(kind+'-task-active',worker.page,async page=>{
   for(const control of await page.locator('[data-tooltip]:visible').all()) {
    await control.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();await page.waitForTimeout(200);await expect(page.getByRole('tooltip')).toBeVisible();
    await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true,'keyboard tooltip appears immediately');await page.keyboard.press('Escape');await control.blur();
   }
  });
  const revoked=worker.page.waitForResponse(response=>response.url().endsWith('/api/auth/delegations/revoke'));
  await externalRow.getByRole('button',{name:'Revoke task'}).click();await ok(await revoked);await expect(externalRow).toContainText('revoked');await shoot(kind+'-task-revoked',worker.page);
  const authorize=createResourceAuthorizer({issuer:app.origin,resourceId:resource.id,clientId:resource.clientId,audience:resource.audience,privateKey:resourceKeys.privateKey,kid:resourceJwk.kid});
  const denied=await authorize(new Request(resource.audience,{method:'POST',headers:{authorization:'DPoP '+externalToken,DPoP:await dpop(resource.audience,null,externalToken)}}),{...grant,task:effect,expected:{personId:worker.id,resource:effect.resource,operation:effect.operation,arguments:effect.arguments}});
  assert.equal(denied.ok,false);assert.equal(denied.response.status,401,'My account revocation refuses the next external call');
 }
 await worker.context.close();await reviewer.context.close();
}
