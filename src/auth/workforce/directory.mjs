// Groups and app assignments: who may use which company app, and with which
// app role. A direct assignment's role wins over a group's.
import {one,all} from '../core.mjs';

const ASSIGNED=`SELECT a.role,0 AS rank FROM auth_app_assignments a WHERE a.app_id=? AND a.principal_type='person' AND a.principal_id=?
 UNION ALL SELECT a.role,1 FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group' AND m.person_id=?
 ORDER BY rank LIMIT 1`;

// The person's assignment to an active app while the person is active; null otherwise.
export async function assignment(ctx,appId,personId) {
 const person=await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active'",personId);
 const app=await one(ctx,'SELECT id FROM auth_apps WHERE id=? AND disabled_at IS NULL',appId);
 if(!person||!app)return null;
 return one(ctx,ASSIGNED,appId,personId,appId,personId);
}

export const groupNames=async(ctx,personId)=>(await all(ctx,'SELECT g.name FROM auth_group_members m JOIN auth_groups g ON g.id=m.group_id WHERE m.person_id=? ORDER BY g.name',personId)).map(r=>r.name);

// Everyone the app should know about: assigned now (directly or by group) or
// holding an account Auth made there.
export async function appSubjects(ctx,appId) {
 return (await all(ctx,`SELECT principal_id AS id FROM auth_app_assignments WHERE app_id=? AND principal_type='person'
  UNION SELECT m.person_id FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group'
  UNION SELECT subject_id FROM auth_scim_accounts WHERE app_id=? AND subject_type='person'`,appId,appId,appId)).map(r=>r.id);
}

// Apps a person can open now, for the launcher.
export async function launcher(ctx,personId) {
 const apps=await all(ctx,`SELECT DISTINCT p.id,p.name,p.idp_initiated,p.launch_url FROM auth_apps p JOIN auth_app_assignments a ON a.app_id=p.id
  LEFT JOIN auth_group_members m ON a.principal_type='group' AND m.group_id=a.principal_id
  JOIN oa_operators o ON o.id=? AND o.status='active'
  WHERE p.disabled_at IS NULL AND ((a.principal_type='person' AND a.principal_id=?) OR m.person_id=?) ORDER BY p.name`,personId,personId,personId);
 return apps.map(a=>({id:a.id,name:a.name,launch:a.idp_initiated?`/saml/launch/${encodeURIComponent(a.id)}`:a.launch_url}));
}
