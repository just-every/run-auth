import {notifySecurity} from '../notifications/index.mjs';
import {json,fail} from '../core.mjs';
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
 let review=null;
 if(data.caseId) {
  review=state.cases.find(c=>c.id===data.caseId&&c.person_id===personId);
  if(!review||review.state!=='verified')fail('verified_recovery_case_required',403);
  // A case is an additional condition, never a replacement for people scope.
  if(!permitted(state,'cases.view',{caseId:review.id}))fail('role_permission_required',403);
 }
 const {operationId}=await commit(ctx,s,guard,'roles.factors.reset',personId,{reason,caseId:review?.id??null,personVersion:p.version},(g,q)=>[
  q(`INSERT INTO auth_notices(id,session_id,recovery_id,message,created_at) SELECT lower(hex(randomblob(24))),id,NULL,?,? FROM auth_sessions WHERE person_id=? AND ${g.clause}`,'An administrator reset your passkeys and ended all sessions. Sign in with your email to enroll a new passkey. Contact your administrator if unexpected.',ctx.now(),personId,...g.args),
  q(`DELETE FROM auth_passkeys WHERE person_id=? AND ${g.clause}`,personId,...g.args),
  q(`UPDATE oa_operators SET version=version+1 WHERE id=? AND ${g.clause}`,personId,...g.args),
  q(`UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE person_id=? AND ${g.clause}`,ctx.now(),personId,...g.args),
  q(`UPDATE auth_recoveries SET cancelled_at=? WHERE person_id=? AND cancelled_at IS NULL AND completed_at IS NULL AND ${g.clause}`,ctx.now(),personId,...g.args),
  ...(review?[q(`UPDATE auth_role_cases SET state='closed',updated_at=? WHERE id=? AND ${g.clause}`,ctx.now(),review.id,...g.args)]:[]),
 ]);
 await notifySecurity(ctx,{personId,event:'factor_reset',sourceId:operationId,factor:'Passkeys reset by help desk'});
 await fencePerson(ctx,personId);
 await emit(ctx,'recovery.completed',await personSubject(ctx,personId),{method:'scoped_factor_reset',caseId:review?.id??null,operationId});
 if(ctx.mail)await ctx.mail({to:p.email,subject:'Auth passkeys reset',text:`An administrator reset your passkeys and ended all Auth sessions. Sign in at ${ctx.origin}/signin with your email to enroll a new passkey. Contact your administrator if you did not request this.`,html:'<p>An administrator reset your passkeys and ended all Auth sessions. Contact your administrator if you did not request this.</p>'});
 return json({ok:true,operationId});
}
