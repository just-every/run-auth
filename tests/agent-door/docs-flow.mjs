import assert from 'node:assert/strict'
import { randomBytes, randomUUID, webcrypto } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { serveHosted, HOSTED_ORIGIN } from '@runeditrun/rer/internal/cli/hosted-output.mjs'
import { createCapturedMail } from '@runeditrun/rer/internal/cli/agent-mail.mjs'
import { createAgentConformanceNetwork } from '@runeditrun/rer/internal/cli/agent-network.mjs'
import { createProtocol } from '../../src/modules/agent-door/conformance/protocol.mjs'
import { signJws, seconds, autonomousPolicy } from '../../src/modules/agent-door/conformance/crypto.mjs'
import { nativePerson } from './native-person.mjs'
import { checkAgentGuide, readAgentRegistry, readDoorVocabulary, generateAgentGuide, validateGuideMetadata } from '../../scripts/agent-docs.mjs'

const root = fileURLToPath(new URL('../../', import.meta.url))
export async function openGuideInstallation() {
  const email = ['synthetic-auth-guide-1', 'example.com'].join('@'), sub = 'synthetic-auth-guide-owner'
  const workerEmail = ['synthetic-auth-0', 'example.com'].join('@'), workerMail = createCapturedMail(workerEmail)
  const issuer = 'https://synthetic-auth-guide-1.invalid', installationId = randomUUID(), kid = randomUUID(), business = 'synthetic-auth-guide-1'
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const publicKeys = { [kid]: { ...await webcrypto.subtle.exportKey('jwk', pair.publicKey), kid, alg: 'ES256', use: 'sig' } }
  const network = await createAgentConformanceNetwork(root, undefined, { email })
  let hosted
  try {
    hosted = await serveHosted(root, { outboundService: async request => { const copy = request.clone(), response = await network.fetch(request); if (response.ok) await workerMail.capture(copy); else await copy.body?.cancel(); return response }, bindings: {
      RER_OWNER_CLAIM_ISSUER: issuer, RER_OWNER_CLAIM_INSTALLATION_ID: installationId, RER_OWNER_CLAIM_APP_ORIGIN: HOSTED_ORIGIN,
      RER_OWNER_CLAIM_PUBLIC_KEYS: JSON.stringify(publicKeys), OWNER_EMAIL: email,
      RER_BUSINESS_TRUST: JSON.stringify({ v: 1, issuer, audience: HOSTED_ORIGIN, subject: installationId, email, keys: publicKeys }),
      AUTH_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
    } })
    const request = (absolute, init = {}) => {
      const url = new URL(absolute)
      assert.equal(url.origin, hosted.origin)
      return hosted.fetch(url.pathname.slice(1) + url.search, { ...init, headers: Object.fromEntries(new Headers(init.headers)) })
    }
    const surface = JSON.parse(await readFile(new URL('../../agent-surface.json', import.meta.url), 'utf8'))
    return { hosted, request, email, surface, async initialize() {
      const iat = seconds(), claimToken = await signJws(pair.privateKey, kid, 'rer-owner-claim+jwt', {
        v: 1, iss: issuer, aud: hosted.origin, installationId, email, jti: randomUUID(), iat, exp: iat + 300,
      })
      const owner = await nativePerson({ request, origin: hosted.origin, email, mail: network.mail, claim: { path: '/auth/owner-claim', token: claimToken } })
      const invited = await owner.call('/api/auth/people/invite', { email: workerEmail, name: 'Synthetic Auth Worker' })
      assert.equal(invited.status, 201, await invited.clone().text())
      await nativePerson({ request, origin: hosted.origin, email: workerEmail, mail: workerMail })
      const settings = await signJws(pair.privateKey, kid, 'rer-business-settings+jwt', {
        v: 1, iss: issuer, aud: hosted.origin, sub: installationId, business, email, owner_id: sub,
        jti: randomUUID(), iat, exp: iat + 300, rev: 1, values: {}, logo: null, team: null,
      })
      const paired = await request(hosted.origin + '/api/rer/business-settings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ settings }) })
      assert.equal(paired.status, 200, await paired.clone().text())
      const c = createProtocol({ fetch: request, origin: hosted.origin, surface, signer: { issuer, installationId, kid, privateKey: pair.privateKey },
        person: { email, sub, cookie: owner.cookie() }, business, consent: randomUUID(), agentId: 'synthetic-auth-guide-agent', seq: 0, revision: 0, points: [] })
      await c.adopt(autonomousPolicy())
      return { c, owner }
    }, async close() { try { await hosted.close() } finally { await network.close(); workerMail.close() } } }
  } catch (error) { await hosted?.close(); await network.close(); workerMail.close(); throw error }
}

// One sanity flow through a fresh production Worker, not an adapter test door.
export async function agentDocsFlow(t, siteGuide) {
  const guide = await checkAgentGuide(root), registry = await readAgentRegistry(root), vocabulary = await readDoorVocabulary(root)
  const app = await openGuideInstallation(); t.after(() => app.close())
  const get = (path = '/docs/agents', init) => app.request(app.hosted.origin + path, init)
  const fresh = await get(); assert.equal(fresh.status, 200)
  assert.equal(fresh.headers.get('set-cookie'), null, 'reading public docs creates no identity')
  const original = await fresh.text()
  assert.equal((await get('/docs/agents', { method: 'HEAD' })).status, 200)
  assert.equal(await (await get('/docs/agents', { method: 'HEAD' })).text(), '')
  assert.equal((await get('/docs/agents', { method: 'POST' })).status, 405)
  const { c, owner } = await app.initialize()
  const listed = await c.mcp(['tools', 'list'].join('/')), templates = await c.mcp(['resources', 'templates', 'list'].join('/'))
  assert.equal(listed.status, 200); assert.ok(listed.result?.tools?.length)
  assert.equal(templates.status, 200); assert.ok(templates.result?.resourceTemplates?.length)
  assert.deepEqual(listed.result.tools, registry.tools, 'guide uses the actual production tool descriptors and computed scopes')
  assert.deepEqual(templates.result.resourceTemplates.map(resource => resource.uriTemplate), registry.resources.map(resource => resource.uriTemplate))
  const names = [...guide.matchAll(/^`(auth\.[a-z.]+)`$/gm)].map(match => match[1])
  const listedNames = listed.result.tools.map(tool => tool.name)
  assert.deepEqual(names, listedNames, 'documented tool headings have neither extra nor missing tools')
  for (const [door, html] of [['installation', original], ['run site', siteGuide]]) {
    const servedNames = [...html.matchAll(/<p><code>(auth\.[a-z.]+)<\/code><\/p>/g)].map(match => match[1])
    assert.deepEqual(servedNames, listedNames, door + ' serves every production tool and no extra tool')
    for (const resource of templates.result.resourceTemplates) assert.ok(html.includes(resource.uriTemplate.replaceAll('&', '&amp;')), door + ' serves resource templates')
    const sections = new Map([...html.matchAll(/<h3\b[\s\S]*?(?=<h[23]\b|$)/g)].flatMap(([section]) => {
      const name = section.match(/<p><code>(auth\.[a-z.]+)<\/code><\/p>/)?.[1]
      return name ? [[name, section]] : []
    }))
    const escaped = value => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;')
    for (const tool of listed.result.tools) {
      const section = sections.get(tool.name)
      assert.ok(section, door + ' has a job section for ' + tool.name)
      assert.ok(section.includes('Scope: <code>' + tool._meta['com.runeditrun/scope'] + '</code>. Classes: ' +
        tool._meta['com.runeditrun/classes'].map(cls => '<code>' + cls + '</code>').join(', ') + '.'),
      door + ' attaches the exact scope and classes to ' + tool.name)
      assert.ok(section.includes(escaped(JSON.stringify(tool.inputSchema, null, 2))), door + ' documents the production input bounds for ' + tool.name)
      for (const [index, step] of app.surface.journey.entries()) if (step.tool === tool.name) {
        for (const [item, expected] of step.expect.entries()) {
          assert.ok(section.includes('<code>' + expected.class + '</code> with facts <code>' + escaped(JSON.stringify(expected.facts ?? {})) + '</code>'),
            door + ' attaches the computed class facts to ' + tool.name)
          assert.ok(section.includes('journey ' + step.id + ', JSON pointer /journey/' + index + '/expect/' + item),
            door + ' links the exact class fixture for ' + tool.name)
        }
      }
    }
  }
  for (const resource of templates.result.resourceTemplates) assert.ok(guide.includes('`' + resource.uriTemplate + '`'))
  for (const tool of listed.result.tools) {
    assert.ok(guide.includes('Scope: `' + tool._meta['com.runeditrun/scope'] + '`'))
    for (const cls of tool._meta['com.runeditrun/classes']) assert.ok(guide.includes('`' + cls + '`'))
  }
  const outputs = new Map()
  for (const step of app.surface.journey) {
    const answer = await c.stepTool(step, c.args(step, outputs))
    assert.equal(answer.status, 200, step.id)
    assert.equal(answer.result?.isError, false, step.id)
    assert.deepEqual(answer.decision.classes.map(({ class: cls, facts }) => ({ class: cls, facts })), step.expect, 'documented class fixture ' + step.id)
    outputs.set(step.id, answer.result.structuredContent)
  }
  const discover = await c.mcp(['server', 'discover'].join('/'))
  assert.deepEqual(discover.result._meta['com.runeditrun/limits'], registry.limits)
  const prompts = await c.mcp(['prompts', 'list'].join('/'))
  assert.equal(prompts.status, 200)
  assert.deepEqual(prompts.result.prompts.map(({ name }) => name), registry.prompts.map(({ name }) => name))
  const events = outputs.get('events').events
  assert.ok(events.length, 'event documentation is checked against retained effects')
  const mismatch = await c.mcp(['server', 'discover'].join('/'), {}, { headers: { 'Mcp-Method': ['tools', 'list'].join('/') } })
  assert.equal(mismatch.status, 400)
  assert.equal(mismatch.message.error.message, 'HeaderMismatch')
  for (const [door, html] of [['installation', original], ['run site', siteGuide]]) {
    assert.ok(html.includes('<code>' + registry.specialist + '</code>'), door + ' names the current specialist')
    for (const prompt of prompts.result.prompts) assert.ok(html.includes('<code>' + prompt.name + '</code>'), door + ' documents the declared specialist job')
    for (const resource of registry.resources) assert.ok(html.includes('<code>' + resource.uriTemplate + '</code> — ' + resource.name +
      '; scope <code>' + resource.scope + '</code>; classes ' + resource.classes.map(cls => '<code>' + cls + '</code>').join(', ') + '.'),
      door + ' attaches scope and classes to the correct resource template')
    for (const type of new Set(events.map(event => event.type))) assert.ok(html.includes('<li><code>' + type + '</code></li>'), door + ' documents emitted event types')
    assert.ok(html.includes('Requests per minute per agent: <code>' + registry.limits.requestsPerMinute + '</code>'), door + ' documents the enforced request capacity')
    assert.ok(html.includes('Maximum request body bytes: <code>' + registry.limits.maxBodyBytes + '</code>'), door + ' documents the enforced body capacity')
    assert.ok(html.includes('<code>' + mismatch.message.error.message + '</code>'), door + ' documents the observed protocol error')
  }
  const populated = await get('/docs/agents', { headers: { cookie: owner.cookie(), authorization: 'Bearer synthetic-auth-private-1' } })
  assert.equal(await populated.text(), original, 'signed-in populated installation returns the same public document')
  for (const value of [app.email, 'Avery Owner', 'synthetic-auth-private-1', ...outputs.values()].filter(value => typeof value === 'string')) assert.ok(!original.includes(value), 'no private record or credential in public guide')
  const people = outputs.get('people').items
  assert.ok(people.length, 'privacy proof uses a populated directory')
  for (const person of people) for (const value of [person.id, person.email, person.name]) if (value) assert.ok(!original.includes(value), 'directory data remains private')
  for (const change of [
    surface => surface.tools.pop(),
    surface => surface.tools.push({ ...surface.tools[0], name: 'auth.synthetic.extra' }),
    surface => surface.tools[0].scope = 'synthetic:stale',
    surface => surface.tools[0].classes = ['access'],
    surface => surface.resources.pop(),
    surface => surface.resources.push('auth://synthetic/{id}'),
    surface => surface.specialist = 'synthetic stale role',
    surface => surface.journey = surface.journey.filter(step => step.tool !== surface.tools[0].name),
    surface => surface.journey.push({ ...surface.journey[0], id: 'synthetic-extra', tool: 'auth.synthetic.extra' }),
    surface => surface.journey[1].id = surface.journey[0].id,
    surface => delete surface.journey[0].id,
    surface => surface.journey[0].expect = [],
    surface => surface.journey[0].expect.push({ ...surface.journey[0].expect[0] }),
  ]) {
    const stale = structuredClone(app.surface); change(stale)
    assert.throws(() => validateGuideMetadata(stale, registry), /Agent guide:/)
  }
  assert.equal(generateAgentGuide({ ...app.surface, verification: { private: 'synthetic-auth-private-2' } }, registry, vocabulary), guide, 'private verification metadata is excluded by construction')
  console.log('PROBE BASE-AGENT-013 1: production tools / list and resources / templates / list -> 10 tool headings and 3 resource templates agree; public guide unchanged after real enrollment and group operations')
  console.log('PROBE BASE-AGENT-013 2: production tools / call for declared journey -> documented class fixtures agree; missing, extra and stale metadata refused')
}
