// Auth's export and import on Base's portability engine. Export first writes a
// signed grant map into the database, so the archive carries it; import checks
// every client and person against the destination's own rules before restoring.
// Runtime modules load lazily: this adapter must load before `rer install`.
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { localPortability } from '@runeditrun/rer/portability';
import { fileRecords } from '@runeditrun/rer/modules/portability/files';
import { readSettings } from '@runeditrun/rer/adapter-settings';
import { RerError } from '@runeditrun/rer/errors';

// Kept: people, emails, passkey public keys, clients, grants, pairwise subjects,
// former subjects, the audit log, grant maps and withdrawn RER keys (withdrawal
// is for good). Left out: sessions and one-time state, signing keys, the pairwise
// key (auth_settings), recovery and preparer secrets, move-in staging rows, link
// transients and the RER keys an owner trusted, SAML signing keys and sessions,
// provisioning connectors (their credentials stay with the installation) and
// queue, OIDC app secrets, codes and sessions, and event subscriptions (their
// secrets) and deliveries.
export const POLICY = {
 product: 'identity-auth',
 includeTables: ['oa_operators', 'oa_external_identities', 'oa_domain_rules', 'oa_invitation_cancellations', 'oa_bootstrap', 'oa_first_run', 'auth_rer_withdrawals'],
 excludeTables: ['auth_sessions', 'auth_challenges', 'auth_limits', 'auth_codes', 'auth_assertions', 'auth_signing_keys', 'auth_settings',
  'auth_recoveries', 'auth_recovery_tokens', 'auth_notices', 'auth_upstream_proofs', 'auth_agent_%', 'auth_import_rows',
  'auth_link_requests', 'auth_link_tokens', 'auth_link_codes', 'auth_session_clients', 'auth_logout_deliveries', 'auth_rer_%',
  'auth_saml_keys', 'auth_saml_requests', 'auth_saml_sessions', 'auth_saml_logouts', 'auth_scim_connectors', 'auth_provisioning', 'auth_oidc_secrets', 'auth_oidc_codes', 'auth_oidc_sessions', 'auth_oidc_logouts',
  'auth_event_subscriptions', 'auth_event_deliveries'],
 requiredConfiguration: ['AUTH_ENCRYPTION_KEY'],
};
const engine = localPortability({ database: 'auth', policy: POLICY });

async function withDatabase(root, work) {
 const { getPlatformProxy } = createRequire(join(root, 'package.json'))('wrangler');
 const proxy = await getPlatformProxy({ configPath: join(root, 'wrangler.jsonc'), persist: { path: join(root, '.wrangler/state/v3') }, remoteBindings: false });
 try { return await work(proxy.env.DB); } finally { await proxy.dispose(); }
}
const settings = async root => (await readSettings(root, { file: '.dev.vars' })).values;

async function exportAuth(context) {
 const vars = await settings(context.root);
 const { writeGrantMap, issuerOf } = await import('../../src/auth/links/grant-map.mjs');
 const map = await withDatabase(context.root, async db => {
  const ctx = { db, secret: vars.AUTH_ENCRYPTION_KEY, now: Date.now, local: vars.AUTH_LOCAL === 'true' };
  // The issuer apps last discovered; a local install that never served discovery uses its own origin.
  ctx.origin = await issuerOf(ctx) ?? vars.AUTH_ORIGIN;
  return writeGrantMap(ctx);
 });
 context.store.report(`Signed grant map: ${map.sectors} apps, ${map.subjects} pairwise subjects, ${map.former} former subjects.`);
 return { ...await engine.export(context), grantMap: map };
}

// A local install serves only loopback apps and a hosted one never does; a dev
// persona never becomes a real person.
export function refusal(table, row, local, validateClientOrigin) {
 if (table === 'auth_clients') {
  try { validateClientOrigin({ local }, row.origin); } catch { return `app ${row.origin} cannot be served by this ${local ? 'local' : 'hosted'} install`; }
 }
 if (table === 'oa_operators' && /@dev\.localhost$/i.test(String(row.email)) && row.status !== 'inactive') return `dev persona ${row.email}`;
 return null;
}
async function importAuth(context) {
 // rer import restores into this checkout: local unless its settings say it is configured as hosted.
 const local = (await settings(context.root).catch(() => ({}))).AUTH_LOCAL !== 'false', { validateClientOrigin } = await import('../../src/auth/core.mjs');
 for await (const record of fileRecords(context.path)) {
  for (const item of record.kind === 'part' ? record.items : []) {
   const reason = item.kind === 'row' ? refusal(item.table, item.row, local, validateClientOrigin) : null;
   if (reason) throw new RerError('restore_refused', `Restore refused (auth_import): ${reason}.`, 4);
  }
 }
 return engine.import(context);
}
export const portability = { export: exportAuth, import: importAuth };
