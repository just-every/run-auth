import {one,fail} from '../core.mjs';
import {authority} from '../local-email.mjs';
import {capabilityGuard} from './authority.mjs';

const isTap=s=>JSON.parse(s?.amr??'[]').includes('tap');
export async function sessionPass(ctx,s) {
 if(!isTap(s))return null;
 return one(ctx,'SELECT * FROM auth_temporary_passes WHERE enrollment_session_id=? AND person_id=? AND person_version=? AND consumed_at IS NOT NULL',s.id,s.person_id,s.person_version);
}
export async function sessionValid(ctx,s) {
 if(!isTap(s))return true;
 const pass=await sessionPass(ctx,s);
 try {const guard=await capabilityGuard(ctx,pass);return Boolean(await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args));}
 catch(error){if(error.status===403)return false;throw error;}
}
export async function enrollmentGuard(ctx,s) {
 if(!isTap(s))return null;
 const pass=await sessionPass(ctx,s),capability=await capabilityGuard(ctx,pass),local=authority(ctx,s);
 return {clause:`${local.clause} AND ${capability.clause} AND EXISTS(SELECT 1 FROM auth_temporary_passes WHERE id=? AND enrollment_session_id=? AND consumed_at IS NOT NULL)`,args:[...local.args,...capability.args,pass.id,s.id]};
}
export function rebindSession(ctx,s,newSessionId) {
 if(!isTap(s))return [];
 return [ctx.db.prepare(`UPDATE auth_temporary_passes SET enrollment_session_id=? WHERE enrollment_session_id=? AND completed_at IS NULL AND revoked_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`).bind(newSessionId,s.id,ctx.now(),newSessionId)];
}
export function completeEnrollment(ctx,s,newSessionId) {
 if(!isTap(s))return [];
 const q=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 return [
  q(`UPDATE auth_temporary_passes SET completed_at=? WHERE enrollment_session_id=? AND completed_at IS NULL AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,ctx.now(),s.id,newSessionId),
  q(`UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND amr LIKE '%"tap"%' AND EXISTS(SELECT 1 FROM auth_temporary_passes WHERE enrollment_session_id=? AND completed_at=?) AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,ctx.now(),s.person_id,s.id,ctx.now(),newSessionId),
  q(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT person_id,'temporary_pass.completed',id,? FROM auth_temporary_passes WHERE enrollment_session_id=? AND completed_at=? AND EXISTS(SELECT 1 FROM auth_sessions WHERE id=?)`,ctx.now(),s.id,ctx.now(),newSessionId),
 ];
}
