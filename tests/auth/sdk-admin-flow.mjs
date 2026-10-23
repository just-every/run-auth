import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {execFileSync} from 'node:child_process';
import {mkdtemp, rm, readdir, writeFile} from 'node:fs/promises';
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
