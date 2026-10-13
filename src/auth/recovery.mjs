import {DAY,random,hash,one,all,run,requireSession,audit,json,fail} from './core.mjs';
import {requireLocalEmail,authority,requireAuthority} from './local-email.mjs';
export async function startRecovery(ctx,request) {
 const s=await requireSession(ctx,request),id=random(),now=ctx.now();
 if(!await one(ctx,'SELECT id FROM auth_passkeys WHERE person_id=? LIMIT 1',s.person_id))fail('no_passkeys');
 try {await run(ctx,'INSERT INTO auth_recoveries(id,person_id,session_id,created_at,ready_at) VALUES(?,?,?,?,?)',id,s.person_id,s.id,now,now+3*DAY);}catch{fail('recovery_already_pending',409);}
 await run(ctx,"INSERT INTO auth_notices(id,session_id,recovery_id,message,created_at) SELECT lower(hex(randomblob(24))),id,?,'Passkey recovery requested. Cancel this request if it was not you.',? FROM auth_sessions WHERE person_id=? AND revoked_at IS NULL AND expires_at>?",id,now,s.person_id,now);
 if(ctx.mail)await ctx.mail({to:s.email,subject:'Auth passkey recovery requested',text:`A passkey recovery was requested. It becomes available after 72 hours unless another administrator approves it. Sign in to ${ctx.origin}/app/account to cancel it.`,html:`<p>A passkey recovery was requested. Sign in to Auth to review or cancel it.</p>`});
 await audit(ctx,s.person_id,'recovery_requested',id);return json({id,readyAt:now+3*DAY},201);
}
export async function changeRecovery(ctx,request,data,action) {
 const s=await requireSession(ctx,request,action==='approve'),id=data.id||data.recoveryId;
 const r=await one(ctx,'SELECT * FROM auth_recoveries WHERE id=? AND cancelled_at IS NULL AND completed_at IS NULL',id);if(!r)fail('recovery_unavailable',404);
 if(action==='approve') {
  if(r.person_id===s.person_id)fail('distinct_admin_required',403);
  requireLocalEmail(ctx,s);const guard=authority(ctx,s,['owner','admin']);
  const result=await run(ctx,`UPDATE auth_recoveries SET approved_by=? WHERE id=? AND cancelled_at IS NULL AND completed_at IS NULL AND ${guard.clause}`,s.person_id,id,...guard.args);
  if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('recovery_changed',409);}
 } else if(action==='cancel') {
  if(r.person_id!==s.person_id)fail('forbidden',403);
  const result=await run(ctx,'UPDATE auth_recoveries SET cancelled_at=? WHERE id=? AND completed_at IS NULL',ctx.now(),id);if(!result.meta.changes)fail('recovery_changed',409);
 } else {
  if(r.person_id!==s.person_id)fail('requesting_session_required',403);
  if(!JSON.parse(s.amr).includes('email'))fail('email_proof_required',403);
  requireLocalEmail(ctx,s);
  const now=ctx.now(),marker=random(),guard=authority(ctx,s);
  // Conditional D1 transaction makes cancellation and completion mutually exclusive.
  const results=await ctx.db.batch([
   ctx.db.prepare(`UPDATE auth_recoveries SET completed_at=?,completion_marker=? WHERE id=? AND cancelled_at IS NULL AND completed_at IS NULL AND (ready_at<=? OR approved_by IS NOT NULL) AND ${guard.clause}`).bind(now,marker,id,now,...guard.args),
   ctx.db.prepare('DELETE FROM auth_passkeys WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_recoveries WHERE id=? AND completion_marker=?)').bind(s.person_id,id,marker),
   ctx.db.prepare('UPDATE oa_operators SET version=version+1 WHERE id=? AND EXISTS(SELECT 1 FROM auth_recoveries WHERE id=? AND completion_marker=?)').bind(s.person_id,id,marker),
   ctx.db.prepare("UPDATE auth_sessions SET person_version=(SELECT version FROM oa_operators WHERE id=?),amr=? WHERE id=? AND EXISTS(SELECT 1 FROM auth_recoveries WHERE id=? AND completion_marker=?)").bind(s.person_id,JSON.stringify([...(ctx.local?['dev']:[]),...(s.upstream_proof_id?['oidc']:[]),'email']),s.id,id,marker),
   ctx.db.prepare('UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND id!=? AND EXISTS(SELECT 1 FROM auth_recoveries WHERE id=? AND completion_marker=?)').bind(now,s.person_id,s.id,id,marker),
  ]);if(!results[0].meta.changes){await requireAuthority(ctx,s,guard);fail('recovery_wait_required',403);}
 }
 await audit(ctx,s.person_id,`recovery_${action}`,id);return json({ok:true});
}
// CLI adapter generates token locally, sends only this SHA-256 digest via wrangler D1 execute,
// and saves the raw token in a mode-0600 file, printing only its path. There is no public installation route.
export async function installRecoveryToken(db,token,now=Date.now()) { if(typeof token!=='string'||token.length<43)throw new Error('Use at least 32 random bytes'); await db.prepare('INSERT INTO auth_recovery_tokens(token_hash,created_at) VALUES(?,?)').bind(await hash(token),now).run(); }
export async function redeemRecoveryToken(ctx,request,data) {
 const s=await requireSession(ctx,request);if(s.role!=='owner')fail('owner_required',403);
 requireLocalEmail(ctx,s);
 const tokenHash=await hash(String(data.token||'')),now=ctx.now(),marker=random(),guard=authority(ctx,s,['owner']);
 const results=await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_recovery_tokens SET consumed_at=?,consumption_marker=? WHERE token_hash=? AND consumed_at IS NULL AND ${guard.clause}`).bind(now,marker,tokenHash,...guard.args),
  ctx.db.prepare('DELETE FROM auth_passkeys WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_recovery_tokens WHERE token_hash=? AND consumption_marker=?)').bind(s.person_id,tokenHash,marker),
  ctx.db.prepare('UPDATE oa_operators SET version=version+1 WHERE id=? AND EXISTS(SELECT 1 FROM auth_recovery_tokens WHERE token_hash=? AND consumption_marker=?)').bind(s.person_id,tokenHash,marker),
  ctx.db.prepare("UPDATE auth_sessions SET person_version=(SELECT version FROM oa_operators WHERE id=?),amr=? WHERE id=? AND EXISTS(SELECT 1 FROM auth_recovery_tokens WHERE token_hash=? AND consumption_marker=?)").bind(s.person_id,JSON.stringify(ctx.local?['dev','email']:['email']),s.id,tokenHash,marker),
  ctx.db.prepare('UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND id!=? AND EXISTS(SELECT 1 FROM auth_recovery_tokens WHERE token_hash=? AND consumption_marker=?)').bind(now,s.person_id,s.id,tokenHash,marker),
 ]);if(!results[0].meta.changes){await requireAuthority(ctx,s,guard);fail('invalid_recovery_token');}await audit(ctx,s.person_id,'emergency_recovery');return json({ok:true});
}
