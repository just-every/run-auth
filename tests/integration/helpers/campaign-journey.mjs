import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {expect} from '@playwright/test';
import {authenticator} from '../../auth/webauthn.mjs';

export async function campaignProviderEdge(next) {
 const issuer='https://campaign.okta.example',keys=await generateKeyPair('RS256');
 const jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-campaign-key',alg:'RS256',use:'sig'};
 const subjectEmails=Object.fromEntries(Array.from({length:20},(_,i)=>['synthetic-auth-campaign-'+i,`campaign.worker${i}@example.com`]));
 let token;
 const provider={id:'campaign',label:'Campaign Okta',preset:'okta',issuer,clientId:'synthetic-auth-campaign-client',tokenAuthMethod:'client_secret_basic',clientSecret:'synthetic-auth-campaign-secret',subjectEmails};
 return {provider,async claims(subject,nonce){token=await new SignJWT({sub:subject,nonce,amr:['pwd','mfa']}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(issuer).setAudience(provider.clientId).setIssuedAt().setExpirationTime('2m').sign(keys.privateKey);},async fetch(request) {
  const url=new URL(request.url);
  if(url.origin!==issuer)return next(request);
  const value=url.pathname.endsWith('openid-configuration')?{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true}:url.pathname==='/keys'?{keys:[jwk]}:{id_token:token};
  return Response.json(value);
 }};
}
export async function campaignJourney({app,providerEdge,browser,owner,page,shoot}) {
 const json=async(response,status=200)=>{assert.equal(response.status(),status,await response.text());return response.json();};
 const post=(context,path,data)=>context.request.post(app.origin+path,{data,headers:{origin:app.origin},maxRedirects:0});
 const entries=Object.entries(providerEdge.provider.subjectEmails);
 const users=entries.map(([id,email],i)=>({id,status:'ACTIVE',profile:{email,login:email,firstName:['Amara','Jordan','Morgan','Sofia'][i%4],lastName:'Campaign worker '+(i+1)}}));
 const staged=await json(await post(owner,'/api/auth/move-in/stage',{fileName:'engineering-okta-campaign.json',exportDate:new Date().toISOString().slice(0,10),text:JSON.stringify(users)}),201);
 await json(await post(owner,'/api/auth/move-in/admit',{batchId:staged.batchId,rows:users.map((_,i)=>i)}));
 const probe=await post(owner,'/auth/oidc/campaign/start',{returnTo:'/app/account'});assert.equal(probe.status(),303);
 await page.goto(app.origin+'/app/move-in?batch='+staged.batchId);
 await page.getByText('Start an enrollment campaign',{exact:true}).click();
 await page.getByLabel('Campaign name',{exact:true}).fill('Engineering — November cutover');
 const local=value=>{const date=new Date(value);return new Date(date-date.getTimezoneOffset()*60000).toISOString().slice(0,16);};
 const now=Date.now();
 await page.getByLabel('Enrollment opens',{exact:true}).fill(local(now-4*86400000));
 await page.getByLabel('Enrollment deadline',{exact:true}).fill(local(now-3600000));
 await page.getByLabel('Cutover',{exact:true}).fill(local(now+2*86400000));
 await page.getByText('Reminder recipients',{exact:true}).click();
 await page.getByLabel('Cohort manager',{exact:true}).selectOption({label:'Owner · owner@example.com'});
 await page.getByLabel('Notify the selected manager three days before the deadline',{exact:true}).check();
 await page.getByLabel('Notify me at the deadline',{exact:true}).check();
 await page.getByLabel('I approve this cohort, window and selected reminders',{exact:true}).check();
 await shoot('campaign-setup');
 const created=page.waitForResponse(response=>response.url().endsWith('/move-in/campaigns/create'));
 await page.getByRole('button',{name:'Start campaign',exact:true}).click();await json(await created,201);
 await expect(page.getByRole('heading',{name:'Engineering — November cutover',exact:true})).toBeVisible();
 await shoot('campaign-pending');
 for(let i=0;i<17;i++) {
  const person=await browser.newContext();
  try {
   const started=await post(person,'/auth/oidc/campaign/start',{returnTo:'/app/methods'});assert.equal(started.status(),303);
   const location=new URL(started.headers().location);await providerEdge.claims(entries[i][0],location.searchParams.get('nonce'));
   const callback=await person.request.get(app.origin+'/auth/oidc/campaign/callback?'+new URLSearchParams({code:'synthetic-auth-campaign-code',state:location.searchParams.get('state'),iss:providerEdge.provider.issuer}),{maxRedirects:0});assert.equal(callback.status(),303,await callback.text());
   const link=await app.link();await json(await post(person,'/auth/identity/email/confirm',{token:link.searchParams.get('token')}));
   const key=authenticator(app.origin),registration=await json(await post(person,'/auth/passkeys/register/options',{}));
   await json(await post(person,'/auth/passkeys/register/verify',{transaction:registration.transaction,response:key.register(registration.options)}));
   assert.equal((await person.request.get(app.origin+'/api/auth/people')).status(),403);
  }finally{await person.close();}
 }
 await page.reload();
 await expect(page.locator('[data-campaign-state=passkey_ready]')).toHaveCount(17);
 await expect(page.locator('[data-campaign-state=overdue]')).toHaveCount(3);
 await shoot('campaign-overdue');
 const exported=await owner.request.get(app.origin+await page.getByRole('link',{name:'Export stragglers'}).getAttribute('href'));
 assert.equal(exported.status(),200);const csv=await exported.text();
 for(const i of [17,18,19])assert.ok(csv.includes(`campaign.worker${i}@example.com`));assert.ok(!csv.includes('campaign.worker0@example.com'));
 await page.getByRole('button',{name:'Close campaign',exact:true}).click();
 await expect(page.getByText(/Campaign closed/)).toBeVisible();await shoot('campaign-closed');
 const outsider=await browser.newContext();try{const started=await post(outsider,'/auth/oidc/campaign/start',{returnTo:'/app/methods'});const location=new URL(started.headers().location);await providerEdge.claims(entries[17][0],location.searchParams.get('nonce'));const refused=await outsider.request.get(app.origin+'/auth/oidc/campaign/callback?'+new URLSearchParams({code:'synthetic-auth-campaign-closed',state:location.searchParams.get('state'),iss:providerEdge.provider.issuer}),{maxRedirects:0});assert.equal(refused.status(),403);}finally{await outsider.close();}
}
