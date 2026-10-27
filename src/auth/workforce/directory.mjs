import {effectiveRole} from '../reviews/reductions.mjs';
// Groups and app assignments: who may use which company app, and with which
// app role. A direct assignment's role wins over a group's.
import {one,all} from '../core.mjs';

const ASSIGNED=`SELECT a.role,0 AS rank FROM auth_app_assignments a WHERE a.app_id=? AND a.principal_type='person' AND a.principal_id=? AND NOT EXISTS(SELECT 1 FROM auth_access_requests r WHERE r.app_id=a.app_id AND r.person_id=a.principal_id AND r.decided_by=a.created_by AND r.decided_at=a.created_at AND r.role IS a.role AND r.expires_at<=? AND r.state IN ('approved','revocation_pending','expired_verified'))
 UNION ALL SELECT a.role,1 FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group' AND m.person_id=?
 ORDER BY rank LIMIT 1`;

// The person's assignment to an active app while the person is active; null otherwise.
export async function assignment(ctx,appId,personId) {
 const person=await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active'",personId);
 const app=await one(ctx,'SELECT id FROM auth_apps WHERE id=? AND disabled_at IS NULL',appId);
 if(!person||!app||await one(ctx,'SELECT 1 FROM auth_app_denials WHERE app_id=? AND person_id=?',appId,personId))return null;
 return effectiveRole(ctx,appId,personId,await one(ctx,ASSIGNED,appId,personId,ctx.now(),appId,personId));
}

export const groupNames=async(ctx,personId)=>(await all(ctx,'SELECT g.name FROM auth_group_members m JOIN auth_groups g ON g.id=m.group_id WHERE m.person_id=? ORDER BY g.name',personId)).map(r=>r.name);

// Everyone the app should know about: assigned now (directly or by group) or
// holding an account Auth made there.
export async function appSubjects(ctx,appId) {
 return (await all(ctx,`SELECT principal_id AS id FROM auth_app_assignments WHERE app_id=? AND principal_type='person'
  UNION SELECT m.person_id FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group'
  UNION SELECT subject_id FROM auth_scim_accounts WHERE app_id=? AND subject_type='person'`,appId,appId,appId)).map(r=>r.id);
}

export {launcher} from '../launcher/index.mjs';
