import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {execFileSync, spawn} from 'node:child_process';
import {mkdtemp, mkdir, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium, expect} from '@playwright/test';
import {openApp} from './runtime.mjs';

const EMPLOYEE = 'synthetic-auth-104@example.com';

test('installed Hono browser quickstart enrolls independent employer memberships, validates callbacks, switches, rotates, revokes and logs out with server-only custody', {timeout: 420000}, async t => {
  const app = await openApp(); t.after(() => app.close()); await app.claim();
  const directory = await mkdtemp(join(tmpdir(), 'auth-browser-sdk-')); t.after(() => rm(directory, {recursive: true, force: true}));
  const root = fileURLToPath(new URL('../../', import.meta.url));
  for (const name of ['session-sdk', 'hono-sdk']) execFileSync('npm', ['pack', join(root, 'packages', name), '--pack-destination', directory], {stdio: 'pipe'});
  await writeFile(join(directory, 'package.json'), '{"name":"synthetic-auth-104","private":true,"type":"module"}');
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', ...['sdk','hono'].map(name => join(directory, 'runeditrun-auth-' + name + '-0.1.0.tgz'))], {cwd: directory, stdio: 'pipe'});
  const socket = createServer(); await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const origin = 'http://127.0.0.1:' + socket.address().port; await new Promise(resolve => socket.close(resolve));
  const browser = await chromium.launch({headless: true, executablePath: process.env.AUTH_CHROMIUM || undefined, args: ['--no-sandbox', '--use-mock-keychain', '--password-store=basic']}); t.after(() => browser.close());
  const owner = await browser.newContext({viewport: {width: 1440, height: 1000}}), employee = await browser.newContext({viewport: {width: 1440, height: 1000}});
  const page = await employee.newPage(), admin = await owner.newPage();
  const json = async (response, status = 200) => {assert.equal(response.status(), status, await response.text()); return response.json();};
  const post = (context, prefix, path, data) => context.request.post(app.origin + prefix + '/api/auth' + path, {data, headers: {origin: app.origin}});
  const email = async (target, prefix, address, returnTo = '/app/methods') => {
    await target.goto(app.origin + prefix + '/signin?returnTo=' + encodeURIComponent(returnTo));
    await target.getByLabel('Email address', {exact: true}).fill(address);
    await target.getByRole('button', {name: 'Email me a sign-in link'}).click();
    await target.goto((await app.link(prefix)).href);
    await target.getByRole('button', {name: 'Continue to Auth'}).click();
    await expect(target).toHaveURL(app.origin + prefix + returnTo);
  };
  const authenticators = new WeakSet();
  const enroll = async (target, prefix) => {
    if (!authenticators.has(target)) {
    const cdp = await target.context().newCDPSession(target); await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    authenticators.add(target);
    }
    await target.goto(app.origin + prefix + '/app/methods');
    const registered = target.waitForResponse(response => response.url().endsWith('/passkeys/register/verify')), loaded = target.waitForEvent('load');
    await target.getByRole('button', {name:'Register a passkey'}).click(); assert.equal((await registered).status(), 200); await loaded;
  };
  await email(admin, '', app.vars.OWNER_EMAIL, '/setup');
  await admin.getByRole('checkbox').check(); await admin.getByRole('button', {name:'Finish setup'}).click(); await expect(admin).toHaveURL(app.origin + '/app');
  await enroll(admin, '');
  const organization = await json(await post(owner, '', '/organizations/create', {name:'Employer B'}), 201), prefix = '/org/' + organization.id;
  await email(admin, prefix, app.vars.OWNER_EMAIL); await enroll(admin, prefix);
  const invited = [];
  for (const path of ['', prefix]) invited.push(await json(await post(owner, path, path ? '/organizations/invite' : '/people/invite', {email: EMPLOYEE, name:'SDK Employee'}), 201));
  await email(page, '', EMPLOYEE); await enroll(page, '');
  const employeeA = (await json(await employee.request.get(app.origin + '/api/auth/me'))).user.id;
  const peopleB = await json(await owner.request.get(app.origin + prefix + '/api/auth/people'));
  const employeeB = (peopleB.people || peopleB).find(person => person.email === EMPLOYEE).id;
  const configurations = [];
  let signingReady = 0;
  for (const [i, path] of ['', prefix].entries()) {
    const id = i ? 'b' : 'a';
    const signing = await json(await post(owner, path, '/keys/stage', {alg:'ES256'}),201);
    signingReady = Math.max(signingReady, signing.useAfter);
    const registered = await json(await post(owner, path, '/oidc-apps/create', {name:'SDK Documents ' + id, authMethod:'none', idTokenAlg:'ES256', redirectUris:[origin + '/callback/' + id]}), 201);
    const resource = origin + '/api/' + id;
    const api = await json(await post(owner, path, '/resource-apis/register', {appId:registered.id, name:'Documents', audience:resource, scopes:['read'], roles:[{role:'reader',scopes:['read'],resources:['document:*']}], resources:[{id:'document:budget'}]}), 201);
    await json(await post(owner, path, '/resource-apis/assign', {apiId:api.id,principalType:'person',principalId:i ? employeeB : employeeA,role:'reader'}));
    await json(await post(owner, path, '/refresh/profile', {clientId:registered.clientId,apiId:api.id,scopes:['read'],idleHours:1,absoluteHours:24}));
    configurations.push({id, name: i ? 'Employer B' : 'Employer A', issuer:app.origin + path, clientId:registered.clientId, apiId:api.id, resource});
  }
  const configPath = join(directory, 'app.json'); await writeFile(configPath, JSON.stringify({origin,organizations:configurations}));
  let processHandle, exited;
  const start = async () => {
    processHandle = spawn(process.execPath, [join(directory, 'node_modules/@runeditrun/auth-hono/examples/server.mjs')], {cwd: directory, env:{...process.env, AUTH_APP_CONFIG:configPath}, stdio:['ignore','pipe','pipe']});
    exited = new Promise(resolve => processHandle.once('exit', resolve));
    await new Promise((resolve, reject) => {processHandle.stdout.once('data', resolve); processHandle.once('error', reject); processHandle.once('exit', code => reject(new Error('quickstart exited ' + code)));});
  };
  const stop = async () => {if (processHandle && processHandle.exitCode === null) {processHandle.kill('SIGTERM'); await exited;}};
  t.after(stop); await start();
  const api = async () => employee.request.get(origin + '/documents/budget');
  const csrf = async () => {await page.goto(origin); return page.locator('input[name="csrf"]').first().inputValue();};
  const appPost = async (path, form, csrfValue) => employee.request.post(origin + path, {form:{csrf:csrfValue || await csrf(),...form}, headers:{origin}, maxRedirects:0});
  const screenshots = process.env.AUTH_SCREENSHOTS || './test-results/auth-journeys'; await mkdir(screenshots, {recursive:true});
  const shoot = async name => {
    await expect(page.locator('h1')).toBeVisible();
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),'screen fits the desktop assertion viewport');
    for (const width of [1440,390]) for (const theme of ['light','dark']) {
      await page.setViewportSize({width,height:1000}); await page.emulateMedia({colorScheme:theme});
      await page.screenshot({path:join(screenshots, `sdk-${name}-${width}-${theme}.png`),fullPage:true});
    }
    await page.setViewportSize({width:1440,height:1000}); await page.emulateMedia({colorScheme:'light'});
  };
  await page.goto(origin); assert.equal((await api()).status(),401);
  assert.equal((await appPost('/switch',{organization:'b'})).status(),403,'an unproved employer cannot become active');
  assert.equal((await employee.request.get(app.origin + prefix + '/api/auth/me')).status(),401,'root email and passkey do not create employer B proof');
  const begin = async id => {await page.goto(origin); await page.getByRole('button',{name:'Sign in to Employer ' + id.toUpperCase(),exact:true}).click(); await expect(page.getByRole('button',{name:'Allow offline access'})).toBeVisible();};
  const finish = async () => {await page.getByRole('button',{name:'Allow offline access'}).click(); await expect.poll(()=>new URL(page.url()).pathname).toBe('/');};
  // Observe only the browser's own application traffic: tokens and private keys never enter it.
  const exposed = [];
  let lastCallback;
  page.on('request', request => {if(request.url().startsWith(origin + '/callback/')) lastCallback = request.url();});
  page.on('response', response => {if(response.url().startsWith(origin + '/') && ['application/json','text/html'].some(type=>response.headers()['content-type']?.includes(type))) exposed.push(response.text().catch(()=>''));});
  await begin('a'); await shoot('consent');
  // Respect Auth's public signing-key publication deadline on a fresh installation.
  await new Promise(resolve => setTimeout(resolve, Math.max(0, signingReady - Date.now() + 25)));
  await finish();
  const first = await json(await api()); assert.equal(first.organization,'a'); assert.equal(first.document,'Budget'); assert.ok(first.subject && first.subject !== employeeA);
  await shoot('signed-in');
  const oldCookie = (await employee.cookies(origin)).find(cookie => cookie.name === 'auth_quickstart'); assert.ok(oldCookie.httpOnly); assert.equal(oldCookie.sameSite,'Lax');
  assert.equal((await employee.request.post(origin + '/switch',{form:{organization:'b',csrf:await csrf()},headers:{origin:'https://foreign.example.com'}})).status(),403);
  assert.equal((await employee.request.post(origin + '/logout',{form:{csrf:'synthetic-auth-wrong'},headers:{origin}})).status(),403);
  // Wrong callback authority is refused by Auth itself, before issuing a redirect or a code.
  const redirect = await appPost('/login',{organization:'a'}), wrong = new URL(redirect.headers().location); wrong.searchParams.set('redirect_uri',origin + '/wrong');
  assert.equal((await employee.request.get(wrong.href,{maxRedirects:0})).status(),400);
  // Real consent callbacks are delivered to the unchanged installed app with one parameter altered.
  for (const [parameter, value, error] of [['state','synthetic-auth-wrong','invalid_state'], ['iss','https://wrong.example.com','invalid_issuer']]) {
    await page.route(origin + '/callback/a?*', async route => {const changed = new URL(route.request().url()); changed.searchParams.set(parameter,value); await route.continue({url:changed.href});}, {times:1});
    await begin('a'); await page.getByRole('button',{name:'Allow offline access'}).click();
    await expect(page.locator('body')).toContainText(error);
  }
  await email(page, prefix, EMPLOYEE); await enroll(page, prefix);
  await begin('b'); await finish();
  const second = await json(await api()); assert.equal(second.organization,'b'); assert.notEqual(second.subject,first.subject,'separate employers retain separate subjects');
  await page.getByRole('button',{name:'Switch to Employer A',exact:true}).click(); await expect(page.locator('strong')).toHaveText('Employer A');
  assert.equal((await json(await api())).subject,first.subject);
  await page.getByRole('button',{name:'Switch to Employer B',exact:true}).click(); await expect(page.locator('strong')).toHaveText('Employer B');
  await page.getByRole('button',{name:'Rotate session',exact:true}).click(); await expect(page).toHaveURL(origin + '/'); assert.equal((await json(await api())).subject,second.subject);
  await shoot('switched');
  await app.pause(); await app.resume();
  assert.equal((await json(await api())).subject,second.subject,'Auth restart preserves separately proved server-held authority');
  // Revocation is performed at Auth's employee door and is visible to the next API request.
  const grants = await json(await employee.request.get(app.origin + prefix + '/api/auth/refresh'));
  const grant = grants.grants.find(row => row.clientId === configurations[1].clientId || row.client_id === configurations[1].clientId); assert.ok(grant);
  await json(await post(employee,prefix,'/refresh/revoke',{id:grant.id})); assert.equal((await api()).status(),401);
  assert.equal((await appPost('/switch',{organization:'a'})).status(),303);
  assert.equal((await json(await api())).subject,first.subject,'B revocation preserves independent A authority');
  const refusedSwitch = await appPost('/switch',{organization:'b'}); assert.notEqual(refusedSwitch.status(),303);
  await begin('b'); await finish();
  const endedCookie = (await employee.cookies(origin)).find(cookie => cookie.name === 'auth_quickstart'), endedCallback = lastCallback;
  await page.getByRole('button',{name:'Sign out of application and Auth',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Sign out of Auth?',exact:true})).toBeVisible(); await shoot('logout-confirmation');
  await page.getByRole('button',{name:'Sign out',exact:true}).click(); await expect(page.getByRole('heading',{name:'You are signed out',exact:true})).toBeVisible(); await shoot('signed-out');
  assert.equal((await api()).status(),401); assert.equal((await employee.request.get(app.origin + prefix + '/api/auth/me')).status(),401);
  assert.equal((await employee.request.get(app.origin + '/api/auth/me')).status(),200,'ending B does not borrow or destroy A source authority');
  assert.equal((await fetch(endedCallback,{headers:{cookie:endedCookie.name + '=' + endedCookie.value}})).status,400);
  const replay = await fetch(origin + '/documents/budget',{headers:{cookie:endedCookie.name + '=' + endedCookie.value}}); assert.equal(replay.status,401);
  assert.equal((await fetch(origin + '/documents/budget',{headers:{cookie:oldCookie.name + '=' + oldCookie.value}})).status,401);
  // A process restart cannot restore authority from an otherwise live opaque cookie.
  await begin('a'); await finish(); assert.equal((await api()).status(),200);
  const pendingLogin = new URL((await appPost('/login',{organization:'a'})).headers().location);
  const pendingCallback = new URL(origin + '/callback/a');
  pendingCallback.search = new URLSearchParams({state:pendingLogin.searchParams.get('state'),iss:configurations[0].issuer,code:'synthetic-auth-105'}).toString();
  await stop(); await start(); assert.equal((await api()).status(),401);
  assert.equal((await employee.request.get(pendingCallback.href)).status(),400);
  await page.goto(origin); await expect(page.locator('strong')).toHaveText('None');
  assert.equal((await appPost('/switch',{organization:'a'})).status(),403);
  assert.ok(exposed.length > 0);
  assert.ok((await Promise.all(exposed)).every(body => !/access_token|refresh_token|privateKey|DPoP/.test(body)),'browser responses contain no server-held OAuth material');
  assert.equal(await page.evaluate(()=>localStorage.length + sessionStorage.length),0);
  await owner.close(); await employee.close();
});
