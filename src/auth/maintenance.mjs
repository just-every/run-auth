import {deliverLogouts} from './links/logout.mjs';
// Safe for a Worker scheduled handler; no identity or audit history is removed.
// It also retries back-channel logouts that are due.
export async function maintainAuth(ctx) {
 const now=ctx.now();
 await ctx.db.batch([
  ctx.db.prepare('DELETE FROM auth_upstream_proofs WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_challenges WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_limits WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_assertions WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_codes WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_signing_keys WHERE retire_at IS NOT NULL AND retire_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_link_codes WHERE expires_at<=?').bind(now),
  ctx.db.prepare('DELETE FROM auth_link_tokens WHERE expires_at<=?').bind(now),
 ]);
 await deliverLogouts(ctx);
}
