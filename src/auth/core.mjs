import {permitsSession,upstreamProof} from './domain-policy.mjs';
export {createSession} from './session-write.mjs';
export const DAY = 86400000;
export const EMAIL_MAX_AGE = 30 * DAY;
export const SESSION_MAX_AGE = DAY;
export const utf8 = new TextEncoder();
export const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64 = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
export const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
export const hash = async value => b64(await crypto.subtle.digest('SHA-256', utf8.encode(value)));
export const email = value => typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim()) ? value.trim().toLowerCase() : null;
export class AuthError extends Error { constructor(code, status = 400) { super(code); this.status = status; } }
export const fail = (code, status) => { throw new AuthError(code, status); };
export const json = (value, status = 200, headers = {}) => new Response(JSON.stringify(value), {status, headers: {'content-type':'application/json', 'cache-control':'no-store', 'referrer-policy':'no-referrer', ...headers}});
export const scopedCookieName=(ctx,name)=>name+(ctx.organizationId&&ctx.organizationId!=='root'?'_'+ctx.organizationId:'');
export const cookieName = ctx => scopedCookieName(ctx,ctx.local ? 'auth_session' : '__Host-auth_session');
export const cookies = request => Object.fromEntries((request.headers.get('cookie') || '').split(';').map(v => v.trim().split('=')));
export const cookie = (ctx, name, value, age = 86400) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${ctx.local ? '' : '; Secure'}`;
export const bindingName = ctx => scopedCookieName(ctx,ctx.local ? 'auth_browser' : '__Host-auth_browser');
export async function binding(ctx, request) { const raw = cookies(request)[bindingName(ctx)]; return raw ? hash(raw) : null; }
export async function input(ctx, request) {
 if (request.headers.get('origin') !== ctx.origin) fail('origin_required', 403);
 const type = request.headers.get('content-type') || '';
 if (Number(request.headers.get('content-length') || 0) > 65536) fail('request_too_large', 413);
 const text = await request.text(); if (text.length > 65536) fail('request_too_large', 413);
 if (type.startsWith('application/json')) { try { return JSON.parse(text); } catch { fail('invalid_json'); } }
 if (type.startsWith('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(text));
 fail('unsupported_content_type',415);
}
export const one = (ctx, sql, ...args) => ctx.db.prepare(sql).bind(...args).first();
export const run = (ctx, sql, ...args) => ctx.db.prepare(sql).bind(...args).run();
export async function all(ctx, sql, ...args) { return (await ctx.db.prepare(sql).bind(...args).all()).results; }
export async function audit(ctx, actor, event, subject = null) { await run(ctx, 'INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES(?,?,?,?)',actor,event,subject,ctx.now()); }
// An entry with the names behind it, such as who an undo removed or which key filed a proposal.
export async function auditDetail(ctx, actor, event, subject, detail) {
 await ctx.db.batch([
  ctx.db.prepare('INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES(?,?,?,?)').bind(actor,event,subject,ctx.now()),
  ctx.db.prepare('INSERT INTO auth_activity_details(activity_id,detail) VALUES(last_insert_rowid(),?)').bind(JSON.stringify(detail)),
 ]);
}
export async function limit(ctx, key, maximum, duration) {
 return (await limitState(ctx,key,maximum,duration)).allowed;
}
export async function limitState(ctx, key, maximum, duration) {
 const now = ctx.now();
 const row = await one(ctx, 'INSERT INTO auth_limits(bucket,count,expires_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN expires_at<=? THEN 1 ELSE count+1 END, expires_at=CASE WHEN expires_at<=? THEN excluded.expires_at ELSE expires_at END RETURNING count,expires_at',key,now+duration,now,now);
 return {allowed:row.count<=maximum,retryAfter:Math.max(1,Math.ceil((row.expires_at-now)/1000))};
}
export async function session(ctx, request) {
 const raw = cookies(request)[cookieName(ctx)]; if (!raw) return null;
 return activeSession(ctx,request,'token_hash',await hash(raw));
}
export const sessionById=(ctx,request,id)=>id?activeSession(ctx,request,'id',id):null;
async function activeSession(ctx,request,column,value) {
 const s=await one(ctx, `SELECT s.*,p.email,p.display_name,p.role FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id WHERE s.${column}=? AND s.revoked_at IS NULL AND s.expires_at>? AND s.person_version=p.version AND p.status='active'`,value,ctx.now());
 if(!s)return null;
 const methods=JSON.parse(s.amr);
 if(methods.includes('dev')&&!ctx.local)return null;
 if(methods.length&&methods.every(method=>method==='dev')&&(!ctx.allowDevSession||!await ctx.allowDevSession(request)))return null;
 // Also end sessions issued before the email-horizon cap was introduced.
 if(!(methods.length&&methods.every(method=>method==='dev'))) {
  const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',s.person_id);
  if(!proof||proof.verified_at+EMAIL_MAX_AGE<=ctx.now())return null;
 }
 // Optional or owner sessions can continue using Auth proofs after a provider
 // disappears, but cannot carry obsolete provider evidence into a new session.
 if(s.upstream_proof_id&&!await upstreamProof(ctx,s.person_id,s.upstream_proof_id))s.upstream_proof_id=null;
 if(!await permitsSession(ctx,s))return null;
 return s;
}
export async function requireSession(ctx, request, admin = false) {
 const s = await session(ctx,request); if (!s) fail('sign_in_required',401);
 if (admin && (!['owner','admin'].includes(s.role) || !JSON.parse(s.amr).includes('hwk'))) fail('passkey_admin_required',403);
 return s;
}
// With a guard the challenge is stored only while that guard holds; null otherwise.
export async function challenge(ctx, purpose, personId, bindingHash, payload, duration = 600000, guard = null) {
 const id = random(), stored = await run(ctx,`INSERT INTO auth_challenges(id,purpose,person_id,binding_hash,payload,expires_at) SELECT ?,?,?,?,?,? WHERE ${guard ? guard.clause : '1'}`,await hash(id),purpose,personId,bindingHash,JSON.stringify(payload),ctx.now()+duration,...(guard ? guard.args : []));
 return stored.meta.changes ? id : null;
}
export async function consumeChallenge(ctx,id,purpose,bindingHash) {
 if (!id || !bindingHash) fail('invalid_challenge');
 const row=await one(ctx,'DELETE FROM auth_challenges WHERE id=? AND purpose=? AND binding_hash=? AND expires_at>? RETURNING *',await hash(id),purpose,bindingHash,ctx.now());
 if (!row) fail('invalid_challenge'); return {...row,payload:JSON.parse(row.payload)};
}
export const isLoopback = host => host === 'localhost' || /^127\./.test(host) || host === '[::1]' || /^\[::ffff:7f[0-9a-f]{2}:/.test(host) || host === 'localhost.' || host.endsWith('.localhost') || host.endsWith('.localhost.');
export function validateClientOrigin(ctx, value) { let url; try {url=new URL(value);} catch {fail('invalid_client_origin');} if(url.username||url.password||url.hash||url.search||url.pathname!=='/') fail('invalid_client_origin'); if(ctx.local ? !isLoopback(url.hostname) : (isLoopback(url.hostname)||url.protocol!=='https:')) fail('invalid_client_origin'); if(!['http:','https:'].includes(url.protocol)) fail('invalid_client_origin'); return url.origin; }

export function returnPath(value) {if(typeof value!=='string'||!value.startsWith('/')||value.startsWith('//')||/[\\\r\n]/.test(value))return '/app/account';const u=new URL(value,'https://auth.invalid');return u.origin==='https://auth.invalid'?u.pathname+u.search:'/app/account';}
