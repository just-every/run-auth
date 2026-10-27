import {one,random,hash,json,fail,requireSession} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {roleState} from '../roles/state.mjs';
import {requireHardware,roleGuard,permitted} from '../roles/policy.mjs';
import {commit} from '../roles/commit.mjs';

export const HOUR=3600000;
const managerOf=(state,id)=>{const p=state.dir.people.get(id);return p?state.dir.values(p).manager:null;};
function employee(state,id) {
 const p=state.dir.people.get(id);
 if(!p||p.status!=='active'||p.role!=='member'||state.rankOf(id)>0)fail('administrator_recovery_required',403);
 return p;
}
export function verificationGuard(ctx,state,review) {
 employee(state,review.person_id);
 const v=review.verification?JSON.parse(review.verification):null;
 if(review.state!=='verified'||v?.method!=='manager_attestation'||v.caseId!==review.id||v.personId!==review.person_id||v.managerId!==managerOf(state,review.person_id)||v.managerId===review.person_id||v.at>ctx.now()||v.at<=ctx.now()-HOUR)fail('manager_attestation_required',403);
 return {clause:`EXISTS(SELECT 1 FROM auth_role_cases c JOIN auth_sessions a ON a.id=c.verified_session_id JOIN oa_operators p ON p.id=a.person_id WHERE c.id=? AND c.state='verified' AND c.verification=? AND c.verified_by=? AND a.person_id=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND a.amr LIKE '%"hwk"%')`,args:[review.id,review.verification,v.managerId,v.managerId,ctx.now()]};
}
export async function attestCase(ctx,request,data) {
 const s=await requireSession(ctx,request);requireHardware(s);requireLocalEmail(ctx,s);
 const state=await roleState(ctx,s),review=state.cases.find(c=>c.id===data.caseId);
 if(!review||review.state!=='open')fail('case_unavailable',404);
 employee(state,review.person_id);
 if(s.person_id===review.person_id||managerOf(state,review.person_id)!==s.person_id)fail('current_manager_required',403);
 const verification={method:'manager_attestation',caseId:review.id,personId:review.person_id,managerId:s.person_id,at:ctx.now()},guard=roleGuard(ctx,s,state);
 guard.clause+=" AND EXISTS(SELECT 1 FROM auth_role_cases WHERE id=? AND state='open')";guard.args.push(review.id);
 await commit(ctx,s,guard,'recovery.case.attested',review.id,verification,(g,q)=>[
  q(`UPDATE auth_role_cases SET state='verified',verification=?,verified_by=?,verified_session_id=?,updated_at=? WHERE id=? AND ${g.clause}`,JSON.stringify(verification),s.person_id,s.id,ctx.now(),review.id,...g.args),
 ]);
 return json({ok:true});
}
export async function recoveryCasesModel(ctx,s) {
 const state=await roleState(ctx,s);
 return {cases:state.cases.filter(c=>c.person_id===s.person_id||managerOf(state,c.person_id)===s.person_id||permitted(state,'cases.view',{caseId:c.id})).map(c=>({id:c.id,personId:c.person_id,email:state.dir.people.get(c.person_id)?.email,state:c.state,canAttest:c.state==='open'&&managerOf(state,c.person_id)===s.person_id&&c.person_id!==s.person_id,canReset:c.state==='verified'&&permitted(state,'people.factors.reset',{personId:c.person_id,write:true})&&permitted(state,'cases.verify',{caseId:c.id,write:true})&&permitted(state,'recovery.approve',{caseId:c.id,write:true}),canClose:c.person_id===s.person_id||permitted(state,'cases.verify',{caseId:c.id,write:true})}))};
}
export async function cancelCase(ctx,request,data) {
 const s=await requireSession(ctx,request);requireLocalEmail(ctx,s);
 const state=await roleState(ctx,s),review=state.cases.find(c=>c.id===data.caseId);
 if(!review||review.person_id!==s.person_id)fail('case_unavailable',404);
 const guard=roleGuard(ctx,s,state);
 await commit(ctx,s,guard,'recovery.case.cancelled',review.id,{personId:s.person_id},(g,q)=>[
  q(`UPDATE auth_role_cases SET state='closed',updated_at=? WHERE id=? AND ${g.clause}`,ctx.now(),review.id,...g.args),
  q(`UPDATE auth_recovery_enrollments SET cancelled_at=COALESCE(cancelled_at,?) WHERE case_id=? AND completed_at IS NULL AND ${g.clause}`,ctx.now(),review.id,...g.args),
 ]);
 return json({ok:true});
}
// Authority is recomputed at each use. The epoch only fences the current atomic
// write; an unrelated directory edit does not permanently invalidate a link.
async function enrollmentAuthority(ctx,s,link) {
 const state=await roleState(ctx,s),review=state.cases.find(c=>c.id===link.case_id);
 if(!review||link.person_id!==s.person_id||link.person_version!==s.person_version||link.expires_at<=ctx.now()||link.cancelled_at||link.completed_at)fail('recovery_link_unavailable',403);
 const verified=verificationGuard(ctx,state,review);
 const issuer=await one(ctx,`SELECT a.*,p.role FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id WHERE a.id=? AND a.person_id=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND a.amr LIKE '%"hwk"%'`,link.issuer_session_id,link.issuer_id,ctx.now());
 if(!issuer)fail('recovery_authority_changed',403);
 const issuerState=await roleState(ctx,issuer);
 if(issuerState.epoch!==state.epoch||!permitted(issuerState,'people.factors.reset',{personId:s.person_id,write:true})||!permitted(issuerState,'cases.verify',{caseId:review.id,write:true})||!permitted(issuerState,'recovery.approve',{caseId:review.id,write:true}))fail('recovery_authority_changed',403);
 const local=authority(ctx,s);
 return {clause:`${local.clause} AND ${verified.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?) AND EXISTS(SELECT 1 FROM auth_recovery_enrollments WHERE case_id=? AND person_version=? AND expires_at>? AND cancelled_at IS NULL AND completed_at IS NULL) AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=? AND revoked_at IS NULL AND expires_at>?)`,args:[...local.args,...verified.args,state.epoch,review.id,s.person_version,ctx.now(),issuer.id,ctx.now()]};
}
export async function redeemEnrollment(ctx,request,data) {
 const s=await requireSession(ctx,request);requireLocalEmail(ctx,s);
 if(!JSON.parse(s.amr).includes('email'))fail('email_proof_required',403);
 const link=await one(ctx,'SELECT * FROM auth_recovery_enrollments WHERE case_id=? AND token_hash=?',String(data.caseId??''),await hash(String(data.token??'')));
 if(!link||link.consumed_at)fail('recovery_link_unavailable',403);
 const guard=await enrollmentAuthority(ctx,s,link),marker=random();
 guard.clause+=' AND EXISTS(SELECT 1 FROM auth_recovery_enrollments WHERE case_id=? AND consumed_at IS NULL)';guard.args.push(link.case_id);
 await commit(ctx,s,guard,'recovery.link.redeemed',link.case_id,{personId:s.person_id},(g,q)=>[
  q(`UPDATE auth_recovery_enrollments SET consumed_at=?,enrollment_session_id=? WHERE case_id=? AND ${g.clause}`,ctx.now(),s.id,link.case_id,...g.args),
 ] ,marker);
 return json({ok:true,redirect:'/app/methods'});
}
export async function enrollmentGuard(ctx,s) {
 // A closed case or a superseding person version ends this requirement. An
 // expired link on a current open recovery still fails closed at authority.
 const link=await one(ctx,`SELECT e.* FROM auth_recovery_enrollments e JOIN auth_role_cases c ON c.id=e.case_id WHERE e.person_id=? AND e.person_version=? AND e.cancelled_at IS NULL AND c.state='verified' ORDER BY e.created_at DESC,e.rowid DESC LIMIT 1`,s.person_id,s.person_version);
 if(!link||link.completed_at)return null;
 if(!link.consumed_at||link.enrollment_session_id!==s.id)fail('recovery_link_required',403);
 return enrollmentAuthority(ctx,s,link);
}
export function completeEnrollment(ctx,s,newSessionId) {
 const q=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 return [
  q(`UPDATE auth_recovery_enrollments SET completed_at=? WHERE person_id=? AND enrollment_session_id=? AND completed_at IS NULL AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,ctx.now(),s.person_id,s.id,newSessionId),
  q(`UPDATE auth_role_cases SET state='closed',updated_at=? WHERE id IN (SELECT case_id FROM auth_recovery_enrollments WHERE enrollment_session_id=? AND completed_at=?) AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,ctx.now(),s.id,ctx.now(),newSessionId),
  q(`UPDATE auth_sessions SET revoked_at=? WHERE id=? AND EXISTS(SELECT 1 FROM auth_recovery_enrollments WHERE enrollment_session_id=? AND completed_at=?) AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,ctx.now(),s.id,s.id,ctx.now(),newSessionId),
  q(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?, 'recovery.case.completed',case_id,? FROM auth_recovery_enrollments WHERE enrollment_session_id=? AND completed_at=? AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,s.person_id,ctx.now(),s.id,ctx.now(),newSessionId),
 ];
}
