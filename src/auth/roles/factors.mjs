import {verificationGuard,HOUR} from '../recovery-cases/index.mjs';
import {notifySecurity} from '../notifications/index.mjs';
import {json,fail,random,hash} from '../core.mjs';
import {requireRolePermission,permitted} from './policy.mjs';
import {commit} from './commit.mjs';
import {fencePerson} from '../links/logout.mjs';
import {emit,personSubject} from '../events/store.mjs';

export async function resetFactors(ctx,s,data) {
 const personId=String(data.personId??''),guard=await requireRolePermission(ctx,s,'people.factors.reset',{personId,write:true});
 const {state}=guard,p=state.dir.people.get(personId);
 // Scoped factor reset is never an administrator recovery mechanism. Even a
 // strictly lower scoped administrator must use the existing recovery process.
 if(p.role!=='member'||state.rankOf(personId)>0)fail('administrator_recovery_required',403);
 const reason=String(data.reason??'').trim();
 if(!reason||reason.length>500)fail('reset_reason_required');
 if(!data.caseId&&!state.legacy)fail('verified_recovery_case_required',403);
 let review=null;
 if(data.caseId) {
  review=state.cases.find(c=>c.id===data.caseId&&c.person_id===personId);
  if(!review||review.state!=='verified')fail('verified_recovery_case_required',403);
  // A case is an additional condition, never a replacement for people scope.
  if(!permitted(state,'cases.verify',{caseId:review.id,write:true})||!permitted(state,'recovery.approve',{caseId:review.id,write:true}))fail('role_permission_required',403);
  const verified=verificationGuard(ctx,state,review);
  guard.clause+=` AND ${verified.clause} AND NOT EXISTS(SELECT 1 FROM auth_recovery_enrollments WHERE case_id=?)`;guard.args.push(...verified.args,review.id);
 }
 const token=review?random():null,tokenHash=token?await hash(token):null;
 const {operationId}=await commit(ctx,s,guard,'roles.factors.reset',personId,{reason,caseId:review?.id??null,personVersion:p.version},(g,q)=>[
  q(`INSERT INTO auth_notices(id,session_id,recovery_id,message,created_at) SELECT lower(hex(randomblob(24))),id,NULL,?,? FROM auth_sessions WHERE person_id=? AND ${g.clause}`,'An administrator reset your passkeys and ended all sessions. Sign in with your email to enroll a new passkey. Contact your administrator if unexpected.',ctx.now(),personId,...g.args),
  q(`DELETE FROM auth_passkeys WHERE person_id=? AND ${g.clause}`,personId,...g.args),
  q(`UPDATE oa_operators SET version=version+1 WHERE id=? AND ${g.clause}`,personId,...g.args),
  q(`UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE person_id=? AND ${g.clause}`,ctx.now(),personId,...g.args),
  q(`UPDATE auth_recoveries SET cancelled_at=? WHERE person_id=? AND cancelled_at IS NULL AND completed_at IS NULL AND ${g.clause}`,ctx.now(),personId,...g.args),
  q(`UPDATE auth_recovery_enrollments SET cancelled_at=COALESCE(cancelled_at,?) WHERE person_id=? AND completed_at IS NULL AND ${g.clause}`,ctx.now(),personId,...g.args),
  ...(review?[
   q(`INSERT INTO auth_recovery_enrollments(case_id,person_id,person_version,issuer_id,issuer_session_id,token_hash,created_at,expires_at) SELECT ?,?,version,?,?,?,?,? FROM oa_operators WHERE id=? AND ${g.clause}`,review.id,personId,s.person_id,s.id,tokenHash,ctx.now(),ctx.now()+HOUR,personId,...g.args),
  ]:[]),
 ]);
 await notifySecurity(ctx,{personId,event:'factor_reset',sourceId:operationId,factor:'Passkeys reset by help desk'});
 await fencePerson(ctx,personId);
 await emit(ctx,'recovery.completed',await personSubject(ctx,personId),{method:'scoped_factor_reset',caseId:review?.id??null,operationId});
 if(review&&ctx.mail) {
  const link=`${ctx.origin}${ctx.basePath??''}/app/account#caseId=${encodeURIComponent(review.id)}&token=${encodeURIComponent(token)}`;
  await ctx.mail({to:p.email,subject:'Auth recovery enrollment link',text:`Case ${review.id}: your passkeys and native Auth sessions were revoked. Confirm your email in this browser, then open this single-use link within one hour to enroll a passkey:\n${link}`,html:`<p>Your passkeys and native Auth sessions were revoked. Confirm your email, then <a href="${link.replaceAll('&','&amp;')}">enroll a replacement passkey</a> within one hour.</p>`});
  const verification=JSON.parse(review.verification),manager=state.dir.people.get(verification.managerId);
  await ctx.mail({to:manager.email,subject:'Auth employee recovery reset',text:`Case ${review.id}: help desk reset ${p.email} after your attestation. Their passkeys and native Auth sessions were revoked. A single-use enrollment link expires within one hour.`,html:'<p>Help desk reset your employee after your attestation. Contact help desk if unexpected.</p>'});
 }
 if(!review&&ctx.mail)await ctx.mail({to:p.email,subject:'Auth passkeys reset',text:`An administrator reset your passkeys and ended all Auth sessions. Sign in at ${ctx.origin}/signin with your email to enroll a new passkey. Contact your administrator if you did not request this.`,html:'<p>An administrator reset your passkeys and ended all Auth sessions. Contact your administrator if you did not request this.</p>'});
 return json({ok:true,operationId});
}
