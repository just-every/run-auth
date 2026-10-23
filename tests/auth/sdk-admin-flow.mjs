import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {execFileSync} from 'node:child_process';
import {mkdtemp, rm, readdir, writeFile, cp} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL, fileURLToPath} from 'node:url';
import {generateKeyPair, exportJWK, exportPKCS8} from 'jose';
import {openRuntime} from './runtime.mjs';
import {passkeyPerson, post} from './agents-helpers.mjs';

export async function sdkAdminFlow(t) {
  const directory = await mkdtemp(join(tmpdir(), 'auth-sdk-install-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const root = fileURLToPath(new URL('../../', import.meta.url));
  execFileSync('npm', ['pack', join(root, 'packages/session-sdk'), '--pack-destination', directory], {stdio: 'pipe'});
  const archive = (await readdir(directory)).find(name => name.endsWith('.tgz'));
  await writeFile(join(directory, 'package.json'), '{"name":"synthetic-auth-101","private":true,"type":"module"}');
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', join(directory, archive)], {cwd: directory, stdio: 'pipe'});
  const installed = join(directory, 'node_modules/@runeditrun/auth-sdk');
  const {createAdminClient, AuthAdminError} = await import(pathToFileURL(join(installed, 'admin.mjs')));
  assert.equal(typeof (await import(pathToFileURL(join(installed, 'index.mjs')))).createSessionClient, 'function');
  const {r,owner,requests}=await adminRuntime(t);
  const key = await generateKeyPair('ES256', {extractable: true});
  const create = async resources => {
    const response = await r.call('/api/auth/admin-service-apps/create', post({name: 'SDK group reconciler', purpose: 'Exercise scoped v1 integration', ownerId: 'owner',
      jwks: {keys: [{...await exportJWK(key.publicKey), kid: 'synthetic-auth-101', alg: 'ES256'}]},
      scopes: ['groups.manage', 'groups.read'], resources, expiresAt: r.now + 3600000}, owner.cookie));
    assert.equal(response.status, 201, await response.clone().text()); return response.json();
  };
  const service = await create({people: [], groups: ['*'], apps: []});
  const settings = {issuer: r.origin, clientId: service.clientId, privateKey: key.privateKey, kid: 'synthetic-auth-101', scopes: ['groups.manage']};
  const client = createAdminClient(settings);
  const concurrent = await Promise.all([client.request('GET', '/groups'), client.request('GET', '/groups')]);
  assert.deepEqual(concurrent.map(row => row.status), [200, 200]);
  assert.equal(requests.filter(([method, path]) => path === '/oidc/token').length, 1, 'concurrent reads share one private-key exchange');
  // Native writes intentionally share a revision fence. Submit independent
  // creations deliberately; the SDK must never retry a refused concurrent write.
  const made = [];
  for (const name of ['Engineering', 'Support']) made.push(await client.request('POST', '/groups', {body: {name}}));
  assert.deepEqual(made.map(row => row.status), [201, 201]);
  const pages = []; for await (const page of client.pages('/groups', {limit: 1})) pages.push(page.data);
  assert.equal(pages.length, 2); assert.equal(pages[0].total, 2); assert.equal(pages[1].nextOffset, null);
  const id = made[0].data.id, old = await client.request('GET', '/groups/' + id);
  await client.request('POST', '/groups', {body: {name: 'Operations'}});
  const staleAt = requests.length;
  await assert.rejects(client.request('DELETE', '/groups/' + id, {etag: old.etag}), error => error instanceof AuthAdminError && error.status === 412);
  assert.equal(requests.length - staleAt, 1, 'a stale write is never automatically retried');
  const current = await client.request('GET', '/groups/' + id);
  assert.ok(current.rateLimitRemaining !== null);
  await client.request('DELETE', '/groups/' + id, {etag: current.etag});
  await assert.rejects(client.request('GET', '/people'), error => error.status === 403 && error.code === 'admin_service_scope_required');
  const restricted = await create({people: [], groups: [made[1].data.id], apps: []});
  const limited = createAdminClient({...settings, clientId: restricted.clientId});
  const only = await limited.request('GET', '/groups'); assert.equal(only.data.total, 1);
  assert.equal(only.data.items[0].id, made[1].data.id);
  await assert.rejects(limited.request('POST', '/groups', {body: {name: 'Forbidden'}}), error => error.status === 403);
  const before = requests.length;
  for (const path of ['https://other.example.com/people', '//other.example.com/groups', '/groups/../people', '/groups/%2e%2e/people', '/groups/%2fpeople']) {
    await assert.rejects(client.request('GET', path), error => error.code === 'invalid_path');
  }
  assert.equal(requests.length, before, 'unsafe paths never send a token');
  assert.throws(() => createAdminClient({...settings, issuer: 'http://other.example.com'}), /invalid_issuer/);
  // Run the installed quickstart unchanged, against this real HTTP installation.
  const privateFile = join(directory, 'signing.pem');
  await writeFile(privateFile, await exportPKCS8(key.privateKey), {mode: 0o600});
  const {spawn} = await import('node:child_process');
  const example = spawn(process.execPath, [join(installed, 'examples/admin.mjs')], {env: {...process.env,
    AUTH_ISSUER: r.origin, AUTH_CLIENT_ID: service.clientId, AUTH_PRIVATE_KEY_FILE: privateFile, AUTH_KEY_ID: 'synthetic-auth-101'}});
  let output = ''; example.stdout.on('data', chunk => { output += chunk; }); example.stderr.on('data', chunk => { output += chunk; });
  const code = await new Promise(resolve => example.on('exit', resolve));
  // The installed example uses its explicitly registered, narrower read scope.
  assert.equal(code, 0, output); assert.match(output, /Support/); assert.match(output, /Operations/);
  assert.ok(!output.includes('PRIVATE KEY') && !output.includes('access_token'));
  const response = await r.call('/api/auth/admin-service-apps/revoke', post({id: service.id}, owner.cookie));
  assert.equal(response.status, 200, await response.clone().text());
  const revokeAt = requests.length;
  await assert.rejects(client.request('GET', '/groups'), error => error.status === 401);
  assert.equal(requests.length - revokeAt, 1, 'a revoked request returns its refusal without reauthentication');
}

async function adminRuntime(t) {
  const r = await openRuntime(); t.after(() => r.close());
  const requests = [];
  const server = createServer(async (req, res) => {
    const parts = []; for await (const part of req) parts.push(part);
    const body = Buffer.concat(parts).toString(), isJSON = req.headers['content-type']?.startsWith('application/json');
    requests.push([req.method, req.url]);
    const response = await r.call(req.url, {method: req.method, headers: req.headers,
      ...(body ? isJSON ? {data: JSON.parse(body)} : {form: Object.fromEntries(new URLSearchParams(body))} : {})});
    res.writeHead(response.status, Object.fromEntries(response.headers)); res.end(await response.text());
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  r.origin = 'http://127.0.0.1:' + server.address().port; r.local = true; r.now = Date.now();
  const owner = await passkeyPerson(r, 'owner', 'owner@example.com', 'owner');
  return {r,owner,requests};
}

export async function pythonAdminFlow(t) {
 const directory=await mkdtemp(join(tmpdir(),'auth-python-install-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const source=join(directory,'source');await cp(fileURLToPath(new URL('../../packages/admin-python',import.meta.url)),source,{recursive:true});
 execFileSync('python3',['-m','venv',join(directory,'venv')],{stdio:'pipe'});
 const python=join(directory,'venv','bin','python');
 execFileSync(python,['-m','pip','wheel','--no-deps',source,'--wheel-dir',directory],{stdio:'pipe'});
 execFileSync(python,['-m','pip','install',join(directory,'runeditrun_auth-0.1.0-py3-none-any.whl')],{stdio:'pipe'});
 const {r,owner,requests}=await adminRuntime(t);
 const key=await generateKeyPair('ES256',{extractable:true});
 const create=async resources=>{
  const response=await r.call('/api/auth/admin-service-apps/create',post({name:'Python scoped groups',purpose:'Fresh Python installation',ownerId:'owner',
   jwks:{keys:[{...await exportJWK(key.publicKey),kid:'synthetic-auth-102',alg:'ES256'}]},scopes:['groups.read','groups.manage'],resources,expiresAt:r.now+3600000},owner.cookie));
  assert.equal(response.status,201,await response.clone().text());return response.json();
 };
 const service=await create({people:[],groups:['*'],apps:[]});
 const privateFile=join(directory,'signing.pem');await writeFile(privateFile,await exportPKCS8(key.privateKey),{mode:0o600});
 const environment={...process.env,AUTH_ISSUER:r.origin,AUTH_CLIENT_ID:service.clientId,AUTH_PRIVATE_KEY_FILE:privateFile,AUTH_KEY_ID:'synthetic-auth-102'};
 const {spawn}=await import('node:child_process');
 const {createInterface}=await import('node:readline');
 const driver=spawn(python,['-u','-c',`
import json, os, sys
from pathlib import Path
from runeditrun_auth import AdminClient, AuthAdminError
settings = dict(issuer=os.environ['AUTH_ISSUER'], client_id=os.environ['AUTH_CLIENT_ID'], private_key=Path(os.environ['AUTH_PRIVATE_KEY_FILE']).read_bytes(), kid=os.environ['AUTH_KEY_ID'], scopes=['groups.manage'])
client = AdminClient(**settings)
print('ready', flush=True)
for line in sys.stdin:
    try:
        command = json.loads(line)
        if command['op'] == 'limited':
            client = AdminClient(**{**settings, 'client_id': command['clientId']})
            result = {'ok': True}
        elif command['op'] == 'pages':
            result = list(client.pages(command['path'], limit=1))
        else:
            result = client.request(command['method'], command['path'], **command.get('options', {}))
        print(json.dumps({'result': result}), flush=True)
    except AuthAdminError as error:
        print(json.dumps({'error': error.code, 'status': error.status}), flush=True)
`],{cwd:directory,env:environment,stdio:['pipe','pipe','pipe']});
 let stderr='';driver.stderr.on('data',chunk=>{stderr+=chunk;});
 const lines=createInterface({input:driver.stdout})[Symbol.asyncIterator]();
 const finished=new Promise(resolve=>driver.on('exit',code=>resolve(code)));
 t.after(async()=>{driver.stdin.end();await finished;});
 assert.equal((await lines.next()).value,'ready',stderr);
 const send=async command=>{driver.stdin.write(JSON.stringify(command)+'\n');const line=await lines.next();assert.equal(line.done,false,stderr);return JSON.parse(line.value);};
 const a=(await send({op:'request',method:'POST',path:'/groups',options:{body:{name:'Python engineering'}}})).result;
 assert.equal(a.status,201);
 const old=(await send({op:'request',method:'GET',path:'/groups/'+a.data.id})).result;
 const b=(await send({op:'request',method:'POST',path:'/groups',options:{body:{name:'Python support'}}})).result;
 assert.equal(b.status,201);
 const pages=(await send({op:'pages',path:'/groups'})).result;assert.equal(pages.length,2);assert.equal(pages[0].data.total,2);
 const before=requests.length;
 const stale=await send({op:'request',method:'DELETE',path:'/groups/'+a.data.id,options:{etag:old.etag}});assert.equal(stale.status,412);assert.equal(requests.length,before+1);
 const current=(await send({op:'request',method:'GET',path:'/groups/'+a.data.id})).result;
 assert.equal((await send({op:'request',method:'DELETE',path:'/groups/'+a.data.id,options:{etag:current.etag}})).result.status,200);
 assert.equal((await send({op:'request',method:'GET',path:'/people'})).status,403);
 const beforePaths=requests.length;
 for(const path of ['//other.example.com/groups','/groups/../people','/groups/%2e%2e/people','/groups/%2fpeople'])assert.equal((await send({op:'request',method:'GET',path})).error,'invalid_path');
 assert.equal(requests.length,beforePaths);
 const quickstart=spawn(python,['-m','runeditrun_auth.quickstart'],{cwd:directory,env:environment});
 let output='';quickstart.stdout.on('data',chunk=>{output+=chunk;});quickstart.stderr.on('data',chunk=>{output+=chunk;});
 assert.equal(await new Promise(resolve=>quickstart.on('exit',resolve)),0,output);assert.match(output,/Python support/);assert.ok(!output.includes('PRIVATE KEY')&&!output.includes('access_token'));
 assert.equal((await r.call('/api/auth/admin-service-apps/revoke',post({id:service.id},owner.cookie))).status,200);
 const revokedAt=requests.length;
 assert.equal((await send({op:'request',method:'GET',path:'/groups'})).status,401);assert.equal(requests.length,revokedAt+1,'cached authority is refused without a retry');
 const limited=await create({people:[],groups:[b.data.id],apps:[]});
 await send({op:'limited',clientId:limited.clientId});
 assert.equal((await send({op:'request',method:'GET',path:'/groups'})).result.data.total,1);
 assert.equal((await send({op:'request',method:'POST',path:'/groups',options:{body:{name:'Forbidden'}}})).status,403);
 driver.stdin.end();assert.equal(await finished,0,stderr);
}

export async function honoPermissionFlow(t) {
 const directory=await mkdtemp(join(tmpdir(),'auth-hono-install-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const root=fileURLToPath(new URL('../../',import.meta.url));
 for(const name of ['session-sdk','hono-sdk'])execFileSync('npm',['pack',join(root,'packages',name),'--pack-destination',directory],{stdio:'pipe'});
 await writeFile(join(directory,'package.json'),'{"name":"synthetic-auth-103","private":true,"type":"module"}');
 execFileSync('npm',['install','--ignore-scripts','--no-audit','--no-fund',...['sdk','hono'].map(name=>join(directory,'runeditrun-auth-'+name+'-0.1.0.tgz'))],{cwd:directory,stdio:'pipe'});
 const installed=join(directory,'node_modules','@runeditrun','auth-hono');
 const {createSessionClient}=await import(pathToFileURL(join(installed,'index.mjs')));
 const {createProtectedApp}=await import(pathToFileURL(join(installed,'examples/protected.mjs')));
 const {r,owner}=await adminRuntime(t);
 const employee=await passkeyPerson(r,'employee','employee@example.com');
 const command=async(path,data,status=200,cookie=owner.cookie)=>{r.now=Date.now();const response=await r.call('/api/auth'+path,post(data,cookie));assert.equal(response.status,status,await response.clone().text());return response.json();};
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const redirectUri='https://documents.example.com/callback';
 const app=await command('/oidc-apps/create',{name:'Installed Hono documents',authMethod:'none',redirectUris:[redirectUri]},201);
 const api=await command('/resource-apis/register',{appId:app.id,name:'Documents',audience:'https://documents.example.com/api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['document:*']}],resources:[{id:'document:budget'}]},201);
 await command('/resource-apis/assign',{apiId:api.id,principalType:'person',principalId:'employee',role:'reader'});
 await command('/refresh/profile',{clientId:app.clientId,apiId:api.id,scopes:['read'],idleHours:1,absoluteHours:24});
 const sdk=await createSessionClient({issuer:r.origin,clientId:app.clientId,redirectUri});
 const authorization=await sdk.authorization({resource:'https://documents.example.com/api',scopes:['read'],deviceName:'Installed Hono server'});
 const url=new URL(authorization.url),offered=await r.call(url.pathname+url.search,{cookie:employee.cookie});
 const consentId=new URL(offered.headers.get('location'),r.origin).searchParams.get('refreshConsent');assert.ok(consentId);
 const consent=await command('/refresh/consent',{id:consentId,decision:'approve'},200,employee.cookie);
 const wrong=new URL(consent.redirect);wrong.pathname='/wrong';await assert.rejects(sdk.complete(wrong.href),error=>error.code==='invalid_callback');
 const tokens=await sdk.complete(consent.redirect);
 let caller=null;
 const protectedApp=createProtectedApp({apiId:api.id,session:()=>caller});
 const door=()=>protectedApp.request('/documents/budget');
 assert.equal((await door()).status,401);
 caller=sdk;const allowed=await door();assert.equal(allowed.status,200);assert.notEqual((await allowed.json()).subject,'employee');
 const rotated=await sdk.refresh();assert.notEqual(rotated.refresh_token,tokens.refresh_token);assert.equal((await door()).status,200);
 await command('/refresh/revoke',{id:tokens.grant_id},200,employee.cookie);assert.equal((await door()).status,401);
 caller=null;assert.equal((await door()).status,401);
}
