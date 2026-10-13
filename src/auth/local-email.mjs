import {fail,one} from './core.mjs';

const MAX_AGE=10*60000;
export function freshLocalEmail(ctx,s) {
 const at=s?.local_email_verified_at,now=ctx.now();
 return Number.isSafeInteger(at)&&at>0&&at<=now&&now-at<MAX_AGE;
}
export function requireLocalEmail(ctx,s) {
 if(!freshLocalEmail(ctx,s))fail('local_email_step_up_required',403);
}
// Sensitive writes append this clause to their own condition, so the acting
// session's authority snapshot (live, same methods/version/role) and its local
// email proof younger than ten minutes are checked in the committing statement.
export function authority(ctx,s,roles=null) {
 const now=ctx.now();
 return {clause:`EXISTS(SELECT 1 FROM auth_sessions a JOIN oa_operators ap ON ap.id=a.person_id WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=? AND a.person_version=ap.version AND ap.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND a.local_email_verified_at>? AND a.local_email_verified_at<=?${roles?` AND ap.role IN (${roles.map(()=>'?').join(',')})`:''})`,
  args:[s.id,s.person_id,s.amr,s.person_version,now,now-MAX_AGE,now,...(roles||[])]};
}
// After a guarded write changed nothing: refuse if the authority lapsed, otherwise
// return so the caller reports its own no-op or conflict.
export async function requireAuthority(ctx,s,guard) {
 if((await one(ctx,`SELECT ${guard.clause} AS held`,...guard.args)).held)return;
 fail(freshLocalEmail(ctx,s)?'session_authority_changed':'local_email_step_up_required',403);
}
