import {hookServer} from '../auth/hooks-server.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {createServer} from 'node:http';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {SAML} from '@node-saml/node-saml';
import * as oidc from 'openid-client';
import {openApp} from './runtime.mjs';
import {spCredentials} from '../auth/saml-helpers.mjs';

const views=[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']];
const EMPLOYEE='erin@northwind.example.com';

// A company app at the far edge: a real SAML service provider on its own port.
async function serviceProvider(t,authOrigin) {
 const sp=await spCredentials('expenses.localhost');let saml;
 const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  if(req.url==='/login'){res.writeHead(302,{location:await saml.getAuthorizeUrlAsync('',undefined,{})});return res.end();}
  if(req.url==='/acs'&&req.method==='POST') {
   try {const {profile}=await saml.validatePostResponseAsync(Object.fromEntries(new URLSearchParams(body)));res.writeHead(200,{'content-type':'text/html'});res.end(`<!doctype html><title>Expenses</title><h1>Signed in as ${profile.email} (${profile.role})</h1><p>Cost center ${profile.cost_center??'none'}</p>`);}
   catch(error){res.writeHead(403,{'content-type':'text/plain'});res.end('Refused: '+error.message);}
   return;
  }
  res.writeHead(404);res.end();
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>server.close(done)));
 const origin=`http://localhost:${server.address().port}`;
 const metadata=await (await fetch(authOrigin+'/saml/metadata')).text();
 const idpCert=[...metadata.matchAll(/<ds:X509Certificate>([^<]+)</g)].map(m=>m[1]);
 saml=new SAML({entryPoint:authOrigin+'/saml/sso',issuer:origin,audience:origin,callbackUrl:origin+'/acs',idpCert,idpIssuer:authOrigin+'/saml/metadata',privateKey:sp.key,publicCert:sp.cert,signatureAlgorithm:'sha256',digestAlgorithm:'sha256',identifierFormat:null,disableRequestedAuthnContext:true,wantAssertionsSigned:true,wantAuthnResponseSigned:true});
 return {origin,metadata:saml.generateServiceProviderMetadata(null,sp.cert)};
}

// An OpenID Connect app at the far edge: openid-client as a real relying party.
async function relyingParty(t,authOrigin) {
 let config,pending;const rp={};
 const server=createServer(async(req,res)=>{
  const url=new URL(req.url,rp.origin);
  if(url.pathname==='/start') {
   config??=await oidc.discovery(new URL(authOrigin),rp.clientId,{},oidc.ClientSecretBasic(rp.secret),{execute:[oidc.allowInsecureRequests]});
   pending={verifier:oidc.randomPKCECodeVerifier(),state:oidc.randomState(),nonce:oidc.randomNonce()};
   res.writeHead(302,{location:oidc.buildAuthorizationUrl(config,{redirect_uri:rp.origin+'/cb',scope:'openid email profile',code_challenge:await oidc.calculatePKCECodeChallenge(pending.verifier),code_challenge_method:'S256',state:pending.state,nonce:pending.nonce}).href});return res.end();
  }
  if(url.pathname==='/cb') {
   res.writeHead(200,{'content-type':'text/html'});
   if(url.searchParams.get('error'))return res.end(`<!doctype html><title>Wiki</title><h1>Refused: ${url.searchParams.get('error')}</h1>`);
   // A fresh install signs only with keys published five minutes earlier, so this
   // journey checks the authorization response; tests/auth/oidc-apps.test.mjs redeems codes.
   const ok=url.searchParams.get('iss')===authOrigin&&url.searchParams.get('state')===pending.state&&/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('code')||'');
   return res.end(`<!doctype html><title>Wiki</title><h1>${ok?'Authorization code received from Auth':'Unexpected response'}</h1>`);
  }
  res.writeHead(404);res.end();
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>server.close(done)));
 rp.origin=`http://localhost:${server.address().port}`;
 return rp;
}

test('company apps journey: the owner adds a SAML app from its metadata, an OpenID Connect app, a group and assignments; an employee signs in through Auth, and loses both when removed, at desktop/mobile in both themes',async t=>{
 const edge=await hookServer(t),app=await openApp({outboundService:edge.fetch});t.after(()=>app.close());await app.claim();
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic','--no-sandbox'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 page.on('dialog',dialog=>dialog.accept());
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 const shoot=async(target,name)=>{for(const [width,theme] of views){
  await target.setViewportSize({width,height:1000});await target.emulateMedia({colorScheme:theme});await target.reload();
  await expect(target.locator('h1')).toBeVisible();
  const results=await new AxeBuilder({page:target}).analyze();
  assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],`${width} ${theme} ${name}`);
  assert.ok(await target.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} fits ${width}px`);
  await target.screenshot({path:join(directory,`company-apps-${name}-${width}-${theme}.png`),fullPage:true});
 }await target.setViewportSize({width:1440,height:1000});await target.emulateMedia({colorScheme:'light'});};

 // Owner: browser email link, setup, hardware passkey.
 await page.goto(app.origin+'/signin?returnTo=%2Fsetup');
 await page.getByLabel('Email address',{exact:true}).fill(app.vars.OWNER_EMAIL);await page.getByRole('button',{name:'Email me a sign-in link'}).click();
 await page.goto((await app.link()).href);await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(app.origin+'/setup');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(app.origin+'/app');
 await page.goto(app.origin+'/app/methods');
 const registered=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registered).status(),200);await page.waitForTimeout(500);

 // An employee, invited and signed in from their own browser.
 assert.equal((await context.request.post(app.origin+'/api/auth/people/invite',{data:{email:EMPLOYEE,name:'Erin Example'},headers:{origin:app.origin}})).status(),201);
 const employee=await browser.newContext(),employeePage=await employee.newPage();
 assert.equal((await employee.request.post(app.origin+'/auth/identity/email/request',{data:{email:EMPLOYEE},headers:{origin:app.origin}})).status(),202);
 const link=await app.link();assert.equal((await employee.request.post(app.origin+'/auth/identity/email/confirm',{data:{token:link.searchParams.get('token')},headers:{origin:app.origin}})).status(),200);

 // The app's own metadata, pasted on the Apps page.
 const sp=await serviceProvider(t,app.origin);
 await page.goto(app.origin+'/app/apps');
 const create=page.locator('form[action="/api/auth/company-apps/create"]');
 await create.getByLabel('Name',{exact:true}).fill('Expenses');await create.getByLabel('Service provider metadata').fill(sp.metadata);await create.getByLabel('Sign',{exact:true}).selectOption('both');await create.getByLabel(/^Attributes/).fill('email=email\nrole=role');
 await create.getByLabel('Let people open it from Auth').check();
 await create.getByRole('button',{name:'Add app'}).click();
 await expect(page.getByRole('heading',{name:'Expenses'})).toBeVisible();
 await page.getByLabel('Group name').fill('Finance');await page.getByRole('button',{name:'Create group'}).click();
 const groupRow=()=>page.locator('section[aria-labelledby="groups-heading"] .data-row',{hasText:'Finance'}),finance=groupRow();await expect(finance).toBeVisible();
 await finance.getByLabel('Add by email').fill(EMPLOYEE);await finance.getByRole('button',{name:'Add',exact:true}).click();
 await expect(page.locator('.data-row',{hasText:EMPLOYEE}).first()).toBeVisible();
 const assign=page.locator('form[data-assign]').first();
 await assign.getByLabel('Give access to').selectOption({label:'Group: Finance'});await assign.getByLabel('App role (optional)').fill('approver');await assign.getByRole('button',{name:'Assign'}).click();
 await expect(page.locator('.data-row',{hasText:'role approver'})).toBeVisible();
 // A bookmark is configured through the administrator form and carries no SSO.
 const bookmarkForm=page.locator('form[action="/api/auth/bookmarks/create"]');
 await bookmarkForm.getByLabel('Bookmark name',{exact:true}).fill('Team handbook');
 await bookmarkForm.getByLabel('Bookmark URL',{exact:true}).fill('https://handbook.example.com/start');
 await bookmarkForm.getByLabel('Bookmark group',{exact:true}).selectOption({label:'Finance'});
 await bookmarkForm.getByRole('button',{name:'Add bookmark'}).click();
 await expect(page.locator('section[aria-labelledby="bookmarks-heading"]')).toContainText('Team handbook');
 // Preview and save computed mappings in the existing app setup panel.
 const expenses=page.locator('section[aria-labelledby^="company-app-"]',{has:page.getByRole('heading',{name:'Expenses',exact:true})});
 await expenses.locator('[data-mapping] summary').click();
 const mapping=expenses.locator('[data-mapping-form]');
 const program={language:1,nameId:{expression:{op:'lower',args:[{op:'concat',args:[{field:'first_name'},'.',{field:'last_name'}]}]},unique:true},saml:{role:{op:'if',args:[{op:'inGroup',args:['Finance']},'approver','reader']}}};
 await mapping.getByLabel('Mapping expressions (JSON)').fill(JSON.stringify(program,null,2));
 await mapping.getByLabel('Preview people').selectOption([{label:EMPLOYEE},{label:app.vars.OWNER_EMAIL}]);
 await mapping.getByRole('button',{name:'Preview mapping'}).click();
 await expect(mapping.locator('[data-mapping-result]')).toContainText('erin.example');
 await expect(mapping.getByRole('button',{name:'Save mapping'})).toBeEnabled();
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await mapping.scrollIntoViewIfNeeded();await page.screenshot({path:join(directory,`company-apps-mapping-preview-${width}.png`)});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));}
 await mapping.getByRole('button',{name:'Save mapping'}).click();
 await expect(expenses.locator('[data-mapping] summary')).toContainText('version 1');
 await shoot(page,'apps');


 // Configure a signed SAML hook through the same real app setup form.
 const hooks=page.locator('section[aria-labelledby="inline-hooks-heading"]'),hookForm=hooks.locator('[data-hook-register]');
 await hookForm.getByLabel('Hook point').selectOption('saml');
 await hookForm.getByLabel('App scope (token or SAML only)').selectOption({label:'Expenses (SAML)'});
 await hookForm.getByLabel('Allowed output fields (comma separated)').fill('cost_center');
 await hookForm.getByLabel('Hook HTTPS endpoint').fill('https://private.example.com/saml');
 await hookForm.getByRole('button',{name:'Register hook'}).click();
 await expect(page.locator('[data-auth-status]')).toContainText('resolves only to public addresses');
 await hookForm.getByLabel('Hook HTTPS endpoint').fill('https://hooks.example.com/saml');
 await hookForm.getByRole('button',{name:'Register hook'}).click();
 await expect(page.locator('[data-auth-status]')).toContainText('Signing secret, shown once');
 await page.reload();await expect(hooks.locator('.data-row')).toContainText('cost_center');
 for(const width of [1440,390]){await page.setViewportSize({width,height:1100});await hooks.evaluate(el=>el.scrollIntoView({block:'start'}));await page.screenshot({path:join(directory,`company-apps-hooks-${width}.png`)});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));}
 await page.setViewportSize({width:1440,height:1000});
 // The employee opens the app: it asks Auth, Auth answers in the browser, the app signs them in.
 await employeePage.goto(sp.origin+'/login');
 await expect(employeePage.getByRole('heading',{name:`Signed in as ${EMPLOYEE} (approver)`})).toBeVisible();await expect(employeePage.getByText('Cost center CC-42')).toBeVisible();
 await hooks.getByRole('button',{name:'Stop hook'}).click();await expect(hooks.getByText('No inline hooks yet.')).toBeVisible();
 for(const width of [1440,390]){await page.setViewportSize({width,height:1100});await hooks.evaluate(el=>el.scrollIntoView({block:'start'}));await page.screenshot({path:join(directory,`company-apps-hooks-stopped-${width}.png`)});}
 await page.goto(app.origin+'/app/activity');
 await expect(page.locator('.activity-row',{hasText:'Inline Hook Called'}).first()).toContainText('Latency:');
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await page.screenshot({path:join(directory,`company-apps-hook-activity-${width}.png`)});}
 await page.goto(app.origin+'/app/apps');
 // An OpenID Connect app registered on the same page; its secret is shown once.
 const rp=await relyingParty(t,app.origin);
 const register=page.locator('form[action="/api/auth/oidc-apps/create"]');
 await register.getByLabel('App name').fill('Wiki');await register.getByLabel('Redirect URIs (one per line)').fill(rp.origin+'/cb');await register.getByLabel('App sign-in URL (optional)').fill(rp.origin+'/start');
 await register.getByRole('button',{name:'Add app'}).click();
 const shown=page.locator('[data-auth-status]');await expect(shown).toContainText('Client secret, shown once');
 [,rp.clientId,rp.secret]=(await shown.textContent()).match(/Client ID (\S+)\. Client secret, shown once: (\S+)/);
 await page.reload();
 const wiki=page.locator('section',{has:page.getByRole('heading',{name:'Wiki'})});
 await wiki.locator('form[data-assign]').getByLabel('Give access to').selectOption({label:'Group: Finance'});await wiki.getByRole('button',{name:'Assign'}).click();
 await expect(page.locator('section',{has:page.getByRole('heading',{name:'Wiki'})}).locator('.data-row',{hasText:'Finance'})).toBeVisible();
 await employeePage.goto(rp.origin+'/start');
 await expect(employeePage.getByRole('heading',{name:'Authorization code received from Auth'})).toBeVisible();
 const archiveResponse=await context.request.post(app.origin+'/api/auth/company-apps/create',{data:{name:'Archive',entityId:'https://archive.example.com',acsUrl:'https://archive.example.com/acs'},headers:{origin:app.origin}});assert.equal(archiveResponse.status(),201);
 const archive=await archiveResponse.json(),ownerModel=await (await context.request.get(app.origin+'/api/auth/me')).json();
 assert.equal((await context.request.post(app.origin+'/api/auth/requests/policy',{data:{appId:archive.id,deciderId:ownerModel.user.id,maxDurationMs:60000},headers:{origin:app.origin}})).status(),200);
 await employeePage.goto(app.origin+'/app/account');await expect(employeePage.getByRole('heading',{name:'Your apps'})).toBeVisible();
 const tiles=employeePage.locator('[data-launcher-tile]'),handbook=tiles.filter({hasText:'Team handbook'}),expenseTile=tiles.filter({hasText:'Expenses'});
 await expect(tiles).toHaveCount(4);await expect(handbook).toContainText('No credentials');
 await employeePage.getByLabel('Search your apps').fill('HANDBOOK');await expect(employeePage.locator('[data-launcher-tile]:visible')).toHaveCount(1);
 await employeePage.getByLabel('Search your apps').fill('missing');await expect(employeePage.locator('[data-launcher-empty]')).toBeVisible();
 await employeePage.getByLabel('Search your apps').fill('');
 await handbook.getByRole('button',{name:'Add favorite',exact:true}).click();await expect(handbook.getByRole('button',{name:'Remove favorite'})).toBeVisible();
 await employeePage.getByLabel('Show apps').selectOption('favorites');await expect(employeePage.locator('[data-launcher-tile]:visible')).toHaveCount(1);
 const bookmarkURL=await handbook.getByRole('link',{name:'Open',exact:true}).getAttribute('href');
 const bookmarkOpened=await employee.request.get(app.origin+bookmarkURL,{maxRedirects:0});assert.equal(bookmarkOpened.status(),303);assert.equal(bookmarkOpened.headers().location,'https://handbook.example.com/start');assert.equal(bookmarkOpened.headers()['set-cookie'],undefined);
 await employeePage.reload();await employeePage.getByLabel('Show apps').selectOption('recent');await expect(employeePage.locator('[data-launcher-tile]:visible')).toHaveCount(1);await expect(handbook).toContainText('Recently opened');
 await employeePage.getByLabel('Show apps').selectOption('all');
 await expenseTile.getByRole('button',{name:'Add favorite',exact:true}).click();await expect(expenseTile.getByRole('button',{name:'Remove favorite'})).toBeVisible();
 await expenseTile.getByRole('link',{name:'Open',exact:true}).click();await expect(employeePage.getByRole('heading',{name:`Signed in as ${EMPLOYEE} (approver)`})).toBeVisible();
 await employeePage.goto(app.origin+'/app/account');
 await employeePage.locator('[data-launcher-tile]',{hasText:'Wiki'}).getByRole('link',{name:'Open',exact:true}).click();await expect(employeePage.getByRole('heading',{name:'Authorization code received from Auth'})).toBeVisible();
 await employeePage.goto(app.origin+'/app/account');
 const ownerLauncher=await context.request.get(app.origin+'/api/auth/launcher');assert.equal((await ownerLauncher.json()).apps.some(a=>a.name==='Team handbook'),false);
 const requestTile=tiles.filter({hasText:'Archive'});await expect(requestTile.getByRole('link',{name:'Open',exact:true})).toHaveCount(0);
 await requestTile.getByRole('link',{name:'Request access',exact:true}).click();
 await expect(employeePage.locator('[data-access-request-create] select[name="appId"]')).toHaveValue(archive.id);
 await expect(employeePage.getByRole('button',{name:'Request temporary access with passkey'})).toBeVisible();
 const theme=employeePage.getByRole('button',{name:'Toggle color theme'});await theme.focus();await expect(employeePage.getByRole('tooltip')).toHaveText('Color theme');await theme.blur();
 await shoot(employeePage,'launcher');

 // Removed from the group: Auth refuses the next sign-in to the app.
 await page.goto(app.origin+'/app/apps');
 await groupRow().getByRole('button',{name:`Remove ${EMPLOYEE}`}).click();
 await expect(groupRow().getByText('No members')).toBeVisible();
 await employeePage.goto(app.origin+'/app/account');await expect(employeePage.locator('[data-launcher-tile]')).toHaveCount(1);await expect(employeePage.locator('[data-launcher-tile]')).toContainText('Archive');
 assert.equal((await employee.request.get(app.origin+bookmarkURL,{maxRedirects:0})).status(),403);
 await employeePage.goto(sp.origin+'/login');
 await expect(employeePage.getByRole('heading',{name:'You are not assigned to this app'})).toBeVisible();
 await employeePage.goto(rp.origin+'/start');await expect(employeePage.getByRole('heading',{name:'Refused: access_denied'})).toBeVisible();
 await employee.close();
 assert.deepEqual(errors,[],'no browser runtime errors');
});
