import {maintainAutomations} from './automations/engine.mjs';
import {maintainDirectorySources} from './directory-sources/maintenance.mjs';
import {maintainNotifications} from './notifications/index.mjs';
import {executeHrRows} from './hris/files/apply.mjs';
import {maintainFamilies} from './tokens/lifecycle.mjs';
import {maintainReviews} from './reviews/routes.mjs';
import {maintainRequests} from './requests/index.mjs';
import {maintainRetention} from './retention/index.mjs';
import {maintainObligations} from './obligations/delivery.mjs';
import {organizationContext} from './tenancy/context.mjs';
import {deliverLogouts} from './links/logout.mjs';
import {maintainProvisioning} from './provisioning/obligations.mjs';
import {deliverGenericLogouts} from './oidc-apps/session.mjs';
import {deliverEvents} from './events/delivery.mjs';
// Safe for a Worker scheduled handler; no identity or audit history is removed.
// It also retries back-channel logouts, provisioning and event deliveries that are due.
export async function maintainAuth(ctx) {
 const now=ctx.now();
 // Personal receipt keys exist only in the installation, never in an employer.
 if(!ctx.organizationId||ctx.organizationId==='root')await ctx.db.prepare("UPDATE auth_erasure_person_receipts SET expired_at=expires_at,person_id=NULL,notices='[]' WHERE expires_at<=? AND expired_at IS NULL").bind(now).run();
 await ctx.db.batch([
  ctx.db.prepare('DELETE FROM auth_federation_transactions WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_federation_replays WHERE expires_at<=?').bind(now),
  ctx.db.prepare("UPDATE auth_migration_bridges SET state='disabled',sealed_credential=NULL,disabled_at=? WHERE state='active' AND expires_at<=?").bind(now,now),
  ctx.db.prepare('DELETE FROM auth_upstream_proofs WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_challenges WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_limits WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_assertions WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_admin_service_assertions WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_delegation_assertions WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_delegation_resource_assertions WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_delegation_dpop_nonces WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_delegation_dpop_proofs WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_codes WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_signing_keys WHERE retire_at IS NOT NULL AND retire_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_link_codes WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_link_tokens WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_saml_requests WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_saml_logouts WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_oidc_codes WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_link_intents WHERE expires_at<=?').bind(now),
 ]);
 await maintainAutomations(ctx);
 await maintainDirectorySources(ctx);
 await executeHrRows(ctx);
 await maintainFamilies(ctx);
 await runRefreshCleanup(ctx);
 await deliverLogouts(ctx);
 await deliverGenericLogouts(ctx);
 await deliverEvents(ctx);
 await maintainRequests(ctx);
 await maintainReviews(ctx);
 await maintainProvisioning(ctx);
 await maintainNotifications(ctx);
 await maintainObligations(ctx);
 await maintainRetention(ctx);
 if(!ctx.organizationId||ctx.organizationId==='root') {
  const organizations=(await ctx.db.prepare("SELECT id FROM auth_organizations WHERE status='active' ORDER BY created_at,id").all()).results;
  for(const organization of organizations)await maintainAuth(await organizationContext(ctx,organization.id));
 }
}

async function runRefreshCleanup(ctx) {
 await ctx.db.batch([
  ctx.db.prepare('DELETE FROM auth_refresh_credentials WHERE family_id IN (SELECT id FROM auth_refresh_families WHERE revoked_at IS NOT NULL)'),
  ctx.db.prepare('UPDATE auth_refresh_families SET current_hash=NULL WHERE revoked_at IS NOT NULL'),
  ctx.db.prepare('DELETE FROM auth_refresh_proofs WHERE expires_at<=?').bind(ctx.now()),ctx.db.prepare('DELETE FROM auth_refresh_consents WHERE expires_at<=?').bind(ctx.now())]);
}
