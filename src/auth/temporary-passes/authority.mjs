import {one,fail} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {permitted} from '../roles/policy.mjs';

export const HOUR=3600000;
export const managerOf=(state,id)=>{const person=state.dir.people.get(id);return person?state.dir.values(person).manager:null;};
export function target(state,id) {
 const person=state.dir.people.get(id);
 if(!person||!['active','invited'].includes(person.status)||person.role!=='member'||state.rankOf(id)>0)fail('temporary_pass_target_refused',403);
 return person;
}
export const canIssue=(state,id)=>['cases.open','people.factors.reset','cases.verify','recovery.approve'].every(permission=>permitted(state,permission,{personId:id,write:true}));
export async function hireGuard(ctx,state,id,version) {
 const person=target(state,id);
 if(person.version!==version)fail('temporary_pass_target_changed',403);
 const guard={clause:`EXISTS(SELECT 1 FROM oa_operators p JOIN auth_onboarding h ON h.person_id=p.id WHERE p.id=? AND p.version=? AND p.role='member' AND p.status IN ('active','invited') AND h.rescinded_at IS NULL) AND NOT EXISTS(SELECT 1 FROM auth_passkeys WHERE person_id=?)`,args:[id,version,id]};
 if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail('temporary_pass_target_refused',403);
 return guard;
}
export async function verificationGuard(ctx,state,review) {
 if(!review||review.expires_at<=ctx.now()||review.created_at>ctx.now()||review.manager_id===review.person_id||managerOf(state,review.person_id)!==review.manager_id)fail('manager_attestation_required',403);
 const hire=await hireGuard(ctx,state,review.person_id,review.person_version);
 const clause=`${hire.clause} AND EXISTS(SELECT 1 FROM auth_temporary_pass_requests r JOIN auth_sessions a ON a.id=r.manager_session_id JOIN oa_operators p ON p.id=a.person_id WHERE r.id=? AND r.manager_id=? AND r.expires_at>? AND a.person_id=r.manager_id AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND a.amr LIKE '%"hwk"%')`;
 const args=[...hire.args,review.id,review.manager_id,ctx.now(),ctx.now()];
 if(!await one(ctx,`SELECT 1 WHERE ${clause}`,...args))fail('manager_attestation_required',403);
 return {clause,args};
}
export async function capabilityGuard(ctx,pass) {
 if(!pass||pass.revoked_at!==null||pass.completed_at!==null||pass.expires_at<=ctx.now())fail('temporary_pass_unavailable',403);
 const issuer=await one(ctx,`SELECT a.*,p.role FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id WHERE a.id=? AND a.person_id=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND a.amr LIKE '%"hwk"%'`,pass.issuer_session_id,pass.issuer_id,ctx.now());
 if(!issuer)fail('temporary_pass_authority_changed',403);
 const state=await roleState(ctx,issuer);
 if(!canIssue(state,pass.person_id))fail('role_permission_required',403);
 const review=await one(ctx,'SELECT * FROM auth_temporary_pass_requests WHERE id=?',pass.request_id);
 const verified=await verificationGuard(ctx,state,review);
 if(pass.person_version!==review.person_version)fail('temporary_pass_target_changed',403);
 return {clause:`${verified.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?) AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=? AND revoked_at IS NULL AND expires_at>?) AND EXISTS(SELECT 1 FROM auth_temporary_passes WHERE id=? AND person_version=? AND expires_at>? AND revoked_at IS NULL AND completed_at IS NULL)`,args:[...verified.args,state.epoch,issuer.id,ctx.now(),pass.id,pass.person_version,ctx.now()]};
}
