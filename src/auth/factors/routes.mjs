import {all,one,fail,json,random,hash,requireSession,limit} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {seal,unseal} from '../keys.mjs';
import {prepareSession} from '../session-write.mjs';
import {notifySecurity} from '../notifications/index.mjs';
import {encodeSecret,matchingStep} from './totp.mjs';
import {factorCommit,endSessions} from './writes.mjs';
import {configurePolicy,policyModel} from './policy.mjs';

async function management(ctx,request) {
 const s=await requireSession(ctx,request);
 if(!JSON.parse(s.amr).includes('hwk'))fail('passkey_required',403);
 requireLocalEmail(ctx,s);return s;
}
export async function factorsModel(ctx,s) {
 return {totp:await all(ctx,'SELECT id,created_at,confirmed_at FROM auth_totp_factors WHERE person_id=? AND confirmed_at IS NOT NULL',s.person_id),recoveryCodes:(await one(ctx,'SELECT COUNT(*) AS n FROM auth_person_recovery_codes WHERE person_id=? AND consumed_at IS NULL',s.person_id)).n,
 assurance:{passkey:'phishing-resistant',totp:'one-time code; not phishing-resistant',recovery:'enrollment only; never administrator access'},...(s.role==='owner'&&JSON.parse(s.amr).includes('hwk')?await policyModel(ctx):{})};
}
export async function factorsRead(ctx,request) {return json(await factorsModel(ctx,await requireSession(ctx,request)));}
export async function factorsAction(ctx,request,path,data) {
 if(path==='/policy')return configurePolicy(ctx,request,data);
 if(path==='/totp/verify')return verifyTotp(ctx,request,data);
 if(path==='/recovery/redeem')return redeemCode(ctx,request,data);
 const s=await management(ctx,request),guard=authority(ctx,s);
 if(path==='/totp/begin') {
  if(await one(ctx,'SELECT 1 FROM auth_totp_factors WHERE person_id=? AND confirmed_at IS NOT NULL',s.person_id))fail('remove_existing_totp',409);
  const secret=encodeSecret(crypto.getRandomValues(new Uint8Array(20))),id=random();
  const encrypted=await seal(ctx,'totp:'+id,secret);
  await factorCommit(ctx,s,guard,'totp_enrollment_started',(q,held)=>[
   q(`DELETE FROM auth_totp_factors WHERE person_id=? AND confirmed_at IS NULL AND ${held}`,s.person_id),
   q(`INSERT INTO auth_totp_factors(id,person_id,sealed_secret,created_at,expires_at) SELECT ?,?,?,?,? WHERE ${held}`,id,s.person_id,encrypted,ctx.now(),ctx.now()+600000),
  ]);
  const issuer=new URL(ctx.origin).host;
  return json({id,secret,uri:'otpauth://totp/'+encodeURIComponent(issuer+':'+s.email)+'?'+new URLSearchParams({secret,issuer,algorithm:'SHA1',digits:'6',period:'30'})});
 }
 if(path==='/totp/confirm') {
  if(!await limit(ctx,'totp-confirm:'+s.person_id,10,300000))fail('rate_limited',429);
  const f=await one(ctx,'SELECT * FROM auth_totp_factors WHERE id=? AND person_id=? AND confirmed_at IS NULL AND expires_at>?',String(data.id??''),s.person_id,ctx.now());if(!f)fail('factor_unavailable',404);
  const step=await matchingStep(await unseal(ctx,'totp:'+f.id,f.sealed_secret),data.code,ctx.now());
  guard.clause+=' AND EXISTS(SELECT 1 FROM auth_totp_factors WHERE id=? AND confirmed_at IS NULL AND expires_at>?)';guard.args.push(f.id,ctx.now());
  const operation=await factorCommit(ctx,s,guard,'totp_enrolled',(q,held)=>[
   q(`UPDATE auth_totp_factors SET confirmed_at=?,last_step=? WHERE id=? AND ${held}`,ctx.now(),step,f.id),
  ]);
  await notifySecurity(ctx,{personId:s.person_id,event:'factor_enrolled',sourceId:operation,request,factor:'TOTP'});
  return json({ok:true});
 }
 if(path==='/remove') {
  const id=String(data.id??''),kind=data.kind;
  if(!['passkey','totp'].includes(kind))fail('invalid_factor');
  const table=kind==='passkey'?'auth_passkeys':'auth_totp_factors';
  guard.clause+=` AND EXISTS(SELECT 1 FROM ${table} WHERE id=? AND person_id=?)`;guard.args.push(id,s.person_id);
  if(kind==='passkey'){if((await one(ctx,'SELECT COUNT(*) AS n FROM auth_passkeys WHERE person_id=?',s.person_id)).n<2)fail('replacement_passkey_required',409);guard.clause+=' AND (SELECT COUNT(*) FROM auth_passkeys WHERE person_id=?)>1';guard.args.push(s.person_id);}
  const operation=await factorCommit(ctx,s,guard,'factor_removed',(q,held)=>[
   q(`DELETE FROM ${table} WHERE id=? AND person_id=? AND ${held}`,id,s.person_id),
   ...endSessions(ctx,s,q,held),
  ]);
  await notifySecurity(ctx,{personId:s.person_id,event:'factor_removed',sourceId:operation,request,factor:kind});
  return json({ok:true,message:'Factor removed. All Auth sessions ended. Sign in again with a remaining passkey.'});
 }
 if(path==='/recovery/rotate') {
  const codes=Array.from({length:8},()=>random()),digests=await Promise.all(codes.map(hash));
  const operation=await factorCommit(ctx,s,guard,'recovery_codes_rotated',(q,held)=>[
   q(`DELETE FROM auth_person_recovery_codes WHERE person_id=? AND ${held}`,s.person_id),
   ...digests.map(digest=>q(`INSERT INTO auth_person_recovery_codes(code_hash,person_id,created_at) SELECT ?,?,? WHERE ${held}`,digest,s.person_id,ctx.now())),
   ...endSessions(ctx,s,q,held),
  ]);
  await notifySecurity(ctx,{personId:s.person_id,event:'factor_reset',sourceId:operation,request,factor:'Recovery codes replaced'});
  return json({codes,message:'Save these codes now. They are shown once. All Auth sessions ended; sign in again.'});
 }
 fail('not_found',404);
}
async function verifyTotp(ctx,request,data) {
 const s=await requireSession(ctx,request);
 if(JSON.parse(s.amr).some(m=>['tap','onboarding','recovery_code'].includes(m)))fail('enrollment_only',403);
 if(!await limit(ctx,'totp-verify:'+s.person_id,10,300000))fail('rate_limited',429);
 const f=await one(ctx,'SELECT * FROM auth_totp_factors WHERE person_id=? AND confirmed_at IS NOT NULL',s.person_id);if(!f)fail('invalid_factor_code',403);
 const step=await matchingStep(await unseal(ctx,'totp:'+f.id,f.sealed_secret),data.code,ctx.now(),f.last_step);
 // The transaction claims this exact time step before writing its proof.
 const g={clause:`EXISTS(SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id WHERE a.id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>?) AND EXISTS(SELECT 1 FROM auth_totp_factors WHERE id=? AND confirmed_at IS NOT NULL AND last_step=?)`,args:[s.id,s.amr,ctx.now(),f.id,f.last_step]};
 await factorCommit(ctx,s,g,'totp_verified',(q,held)=>[
  q(`UPDATE auth_totp_factors SET last_step=? WHERE id=? AND ${held}`,step,f.id),
  q(`INSERT INTO auth_factor_proofs(session_id,person_id,factor_id,verified_at) SELECT ?,?,?,? WHERE ${held} ON CONFLICT(session_id) DO UPDATE SET factor_id=excluded.factor_id,verified_at=excluded.verified_at`,s.id,s.person_id,f.id,ctx.now()),
 ]);
 return json({ok:true,message:'TOTP confirmed for this session. Administrator access still requires a passkey.'});
}
async function redeemCode(ctx,request,data) {
 const s=await requireSession(ctx,request);requireLocalEmail(ctx,s);
 if(JSON.parse(s.amr).some(m=>['tap','onboarding','recovery_code'].includes(m)))fail('enrollment_only',403);
 // Administrator recovery stays separate, including active delegated roles.
 const safe=`EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND role='member' AND status='active') AND NOT EXISTS(SELECT 1 FROM auth_role_grants WHERE person_id=? AND revoked_at IS NULL)`;
 if(!(await one(ctx,`SELECT ${safe} AS held`,s.person_id,s.person_id)).held)fail('administrator_recovery_required',403);
 if(!await limit(ctx,'recovery-code:'+s.person_id,10,300000))fail('rate_limited',429);
 const digest=await hash(String(data.code??'')),g=authority(ctx,s);
 g.clause+=` AND ${safe} AND EXISTS(SELECT 1 FROM auth_person_recovery_codes WHERE code_hash=? AND person_id=? AND consumed_at IS NULL)`;g.args.push(s.person_id,s.person_id,digest,s.person_id);
 const prepared=await prepareSession(ctx,s.person_id,['email','recovery_code'],s.upstream_proof_id,{localEmailVerifiedAt:s.local_email_verified_at,expiresAt:ctx.now()+600000,sourceSession:s,guard:g});
 const [inserted]=await ctx.db.batch([
  prepared.statement,
  ctx.db.prepare('UPDATE auth_person_recovery_codes SET consumed_at=? WHERE code_hash=? AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)').bind(ctx.now(),digest,prepared.id),
  ...['auth_passkeys','auth_totp_factors'].map(table=>ctx.db.prepare(`DELETE FROM ${table} WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`).bind(s.person_id,prepared.id)),
  ctx.db.prepare('UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE person_id=? AND id<>? AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)').bind(ctx.now(),s.person_id,prepared.id,prepared.id),
  ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT person_id,'recovery_code_consumed',id,? FROM auth_sessions WHERE id=?").bind(ctx.now(),prepared.id),
 ]);
 if(!inserted.meta.changes)fail('invalid_recovery_code',403);
 await notifySecurity(ctx,{personId:s.person_id,event:'factor_reset',sourceId:prepared.id,request,factor:'Recovery code reset'});
 return json({ok:true,message:'Enroll a replacement passkey within ten minutes. Apps and administration remain unavailable.'},200,{'set-cookie':prepared.header});
}
