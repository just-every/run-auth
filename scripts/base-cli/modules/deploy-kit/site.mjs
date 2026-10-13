import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { assert, hash, resourceName } from './validation.mjs';
import { regularBytes } from './artifact.mjs';
import { ownerWorkerName, withStateLock, workerSettings } from './owner.mjs';
import { uploadAssets, workerOrigin } from './worker.mjs';

/* A seed's run site (run-<seed>.com): an assets-only Worker serving the folder
 * `rer build --site` writes, on the owner's own account. It has no script, no
 * bindings, no secrets and no schedules, and its name can never be the
 * installed app's Worker name, so a site deploy never touches the app or its
 * resources. The apex domain is a Workers Custom Domain; www.<domain> is a
 * second Custom Domain (DNS and certificate) answered by a zone redirect rule
 * to the apex, 301, path and query kept. Ownership follows owner-account mode:
 * a state file per environment records what this kit created, and anything of
 * the same name it did not create is refused, never adopted. */

const STATE_KIND = 'rer-deploy-site-state';
const APEX = /^(?!www\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;
const PHASE = 'http_request_dynamic_redirect';
export const SITE_ASSETS_CONFIG = Object.freeze({ html_handling: 'auto-trailing-slash', not_found_handling: '404-page' });

function refuse(code, kind, name) { const error = new Error(code); error.resource = `${kind}:${name}`; return error; }

/** deploy-site.json: `{ "version": 1, "domain": "run-cradle.com" }`, the apex hostname only. */
export function siteDeclaration(value) {
  assert(value && typeof value === 'object' && !Array.isArray(value) && value.version === 1 && Object.keys(value).sort().join() === 'domain,version', 'invalid-site-declaration');
  assert(typeof value.domain === 'string' && value.domain.length <= 253 && APEX.test(value.domain), 'invalid-site-domain');
  return value;
}

/** The app is `<project>-<environment>`; owner names never hold `--`, so the site Worker cannot be it. */
export function siteWorkerName(project, environment) {
  const worker = `${ownerWorkerName(project, environment)}--site`;
  assert(resourceName(worker), 'owner-name-too-long');
  return worker;
}

/** The zone rule sending www.<domain> to the apex, found again by its ref. */
export function wwwRedirectRule(domain) {
  return { ref: `rer_site_www_${hash(domain).slice(0, 16)}`, description: `rer site: www.${domain} to ${domain}`, expression: `(http.host eq "www.${domain}")`, action: 'redirect',
    action_parameters: { from_value: { status_code: 301, target_url: { expression: `concat("https://${domain}", http.request.uri.path)` }, preserve_query_string: true } }, enabled: true };
}

/** Everything a site deploy will do, with no provider request. */
export function sitePlan({ project, environment, compatibilityDate, declaration, assets }) {
  const { domain } = siteDeclaration(declaration);
  assert(/^\d{4}-\d{2}-\d{2}$/.test(compatibilityDate ?? ''), 'invalid-plan');
  assert(typeof assets === 'string' && assets.startsWith('/'), 'invalid-site-assets');
  return { version: 1, worker: siteWorkerName(project, environment), appWorker: ownerWorkerName(project, environment), assetsOnly: true, assets, compatibilityDate,
    bindings: [], secrets: [], crons: [], workersDev: false, assetsConfig: { ...SITE_ASSETS_CONFIG },
    domain, hostnames: [domain, `www.${domain}`],
    redirects: [{ from: `https://www.${domain}/*`, to: `https://${domain}/`, status: 301, keeps: ['path', 'query'] }] };
}

function emptyState(accountId, plan) {
  return { version: 1, kind: STATE_KIND, accountId, worker: plan.worker, domain: plan.domain, owned: { worker: null, domains: {}, redirect: null }, receipt: null };
}
async function readState(path, accountId, plan) {
  let bytes;
  try { bytes = await regularBytes(path, 1024 * 1024); } catch (error) { if (error.code === 'ENOENT') return emptyState(accountId, plan); throw error; }
  let state; try { state = JSON.parse(bytes); } catch { throw new Error('invalid-owner-state'); }
  assert(state?.version === 1 && state.kind === STATE_KIND && state.owned && typeof state.owned.domains === 'object', 'invalid-owner-state');
  assert(state.accountId === accountId && state.worker === plan.worker && state.domain === plan.domain, 'owner-state-target-mismatch');
  return state;
}
async function writeState(path, state) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(state, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await rename(temporary, path);
}
async function latestDeployment(api, worker) {
  const result = await api.request(`/workers/scripts/${worker}/deployments`);
  assert(Array.isArray(result?.deployments) && result.deployments.length > 0 && typeof result.deployments[0].id === 'string', 'invalid-deployments');
  return result.deployments[0].id;
}
async function redirectEntrypoint(api, zoneId) {
  try { return await api.zoneRequest(`/zones/${zoneId}/rulesets/phases/${PHASE}/entrypoint`); }
  catch (error) { if (error.status === 404) return null; throw error; }
}
const sameRule = (row, rule) => row && row.expression === rule.expression && row.action === rule.action && JSON.stringify(row.action_parameters) === JSON.stringify(rule.action_parameters) && row.enabled !== false;

/** Read-only preflight, then the assets-only upload, both Custom Domains and the www rule, then readback. */
export async function siteDeploy({ api, plan, files, statePath }) {
  assert(typeof statePath === 'string' && statePath.length, 'missing-owner-state-path');
  assert(plan?.assetsOnly === true && Array.isArray(files) && files.some(file => file.path === 'index.html'), 'invalid-site-assets');
  return withStateLock(statePath, async () => {
    const state = await readState(statePath, api.accountId, plan);
    const save = () => writeState(statePath, state);
    const zones = await api.zoneRequest(`/zones?name=${plan.domain}&account.id=${api.accountId}`);
    const zone = Array.isArray(zones) ? zones.find(row => row?.name === plan.domain && row.account?.id === api.accountId) : null;
    if (!zone) throw refuse('site-zone-missing', 'zone', plan.domain);
    // Preflight: every name is this kit's own or absent before any write.
    const settings = await workerSettings(api, plan.worker), owned = state.owned.worker;
    if (settings && !owned) throw refuse('resource-name-collision', 'worker', plan.worker);
    if (settings && owned.status !== 'created') throw refuse('uncertain-resource-create', 'worker', plan.worker);
    if (!settings && owned?.status === 'created') throw refuse('owned-resource-missing', 'worker', plan.worker);
    if (settings && await latestDeployment(api, plan.worker) !== owned.deploymentId) throw refuse('owned-resource-replaced', 'worker', plan.worker);
    const attached = await api.request(`/workers/domains?zone_id=${zone.id}`);
    assert(Array.isArray(attached), 'invalid-domain-list');
    for (const hostname of plan.hostnames) {
      const row = attached.find(item => item?.hostname === hostname), entry = state.owned.domains[hostname];
      if (row && !entry) throw refuse('resource-name-collision', 'domain', hostname);
      if (row && entry.status !== 'created') throw refuse('uncertain-resource-create', 'domain', hostname);
      if (row && (row.id !== entry.id || row.service !== plan.worker)) throw refuse('owned-resource-replaced', 'domain', hostname);
      if (!row && entry?.status === 'created') throw refuse('owned-resource-missing', 'domain', hostname);
    }
    const rule = wwwRedirectRule(plan.domain), entrypoint = await redirectEntrypoint(api, zone.id);
    const existing = entrypoint?.rules?.find(row => row.ref === rule.ref);
    if (existing && !state.owned.redirect) throw refuse('resource-name-collision', 'redirect', rule.ref);
    if (existing && (state.owned.redirect.ruleId !== existing.id || state.owned.redirect.rulesetId !== entrypoint.id)) throw refuse('owned-resource-replaced', 'redirect', rule.ref);
    if (!existing && state.owned.redirect?.status === 'created') throw refuse('owned-resource-missing', 'redirect', rule.ref);

    // The assets-only Worker: metadata and asset manifest only, no module.
    if (!owned) { state.owned.worker = { status: 'pending' }; await save(); }
    const fingerprint = hash({ files: files.map(({ path, sha256 }) => ({ path, sha256 })), config: plan.assetsConfig, compatibilityDate: plan.compatibilityDate });
    const jwt = await uploadAssets(api, plan.worker, files);
    const body = new FormData();
    body.set('metadata', new Blob([JSON.stringify({ compatibility_date: plan.compatibilityDate, bindings: [], assets: { jwt, config: plan.assetsConfig }, annotations: { 'workers/message': `rer-site:${fingerprint}` } })], { type: 'application/json' }));
    await api.request(`/workers/scripts/${plan.worker}`, { method: 'PUT', body });
    state.owned.worker = { status: 'created', deploymentId: await latestDeployment(api, plan.worker) }; await save();
    await workerOrigin(api, plan.worker, { enable: true, workersDev: false });
    for (const hostname of plan.hostnames) {
      if (state.owned.domains[hostname]?.status === 'created') continue;
      state.owned.domains[hostname] = { status: 'pending' }; await save();
      const row = await api.request('/workers/domains', { method: 'PUT', body: { environment: 'production', hostname, service: plan.worker, zone_id: zone.id } });
      assert(row?.hostname === hostname && row.service === plan.worker && typeof row.id === 'string', 'invalid-domain-attach');
      state.owned.domains[hostname] = { status: 'created', id: row.id }; await save();
    }
    if (!existing || !sameRule(existing, rule)) {
      if (!existing) { state.owned.redirect = { status: 'pending' }; await save(); }
      const result = existing ? await api.zoneRequest(`/zones/${zone.id}/rulesets/${entrypoint.id}/rules/${existing.id}`, { method: 'PATCH', body: rule })
        : entrypoint ? await api.zoneRequest(`/zones/${zone.id}/rulesets/${entrypoint.id}/rules`, { method: 'POST', body: rule })
        : await api.zoneRequest(`/zones/${zone.id}/rulesets/phases/${PHASE}/entrypoint`, { method: 'PUT', body: { rules: [rule] } });
      const created = result?.rules?.find(row => row.ref === rule.ref);
      assert(created && typeof result.id === 'string', 'invalid-redirect-rule');
      state.owned.redirect = { status: 'created', rulesetId: result.id, ruleId: created.id }; await save();
    }
    // Readback: the Worker, both domains on it and the rule as written.
    assert(await workerSettings(api, plan.worker), 'site-worker-missing');
    const domains = await api.request(`/workers/domains?zone_id=${zone.id}`);
    for (const hostname of plan.hostnames) assert(domains.some(row => row.hostname === hostname && row.service === plan.worker && row.id === state.owned.domains[hostname].id), 'domain-readback-mismatch');
    const readback = await redirectEntrypoint(api, zone.id);
    assert(sameRule(readback?.rules?.find(row => row.id === state.owned.redirect.ruleId), rule), 'redirect-readback-mismatch');
    state.receipt = { worker: plan.worker, domain: plan.domain, zoneId: zone.id, deploymentId: state.owned.worker.deploymentId, fingerprint, files: files.length, hostnames: plan.hostnames, redirect: { ...plan.redirects[0], ruleId: state.owned.redirect.ruleId } };
    await save();
    return { origin: `https://${plan.domain}`, receipt: state.receipt };
  });
}
