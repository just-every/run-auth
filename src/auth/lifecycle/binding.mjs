import {hash,one} from '../core.mjs';
// The opaque digest binds work to the approved connection without retaining
// its credential. A later rotation or destination change needs fresh review.
export const scimBinding=connector=>hash(JSON.stringify([connector.base_url,connector.sealed_token,connector.deprovision,connector.push_groups,connector.created_by,connector.created_at]));
export const logoutBinding=(client,generic=false)=>hash(JSON.stringify(generic?[client.client_id,client.app_id,client.backchannel_logout_uri]:[client.id,client.sector_id,client.logout_uri]));
export async function approvedBinding(ctx,workId,current) {
 const step=await one(ctx,`SELECT s.binding,(o.status='inactive' AND d.terminated_at=p.denial_at
  AND NOT EXISTS(SELECT 1 FROM auth_lifecycle_plans newer WHERE newer.person_id=p.person_id AND newer.rowid>p.rowid)) AS active_episode
  FROM auth_lifecycle_steps s LEFT JOIN auth_lifecycle_plans p ON p.id=s.plan_id
  LEFT JOIN oa_operators o ON o.id=p.person_id LEFT JOIN auth_people d ON d.person_id=p.person_id WHERE s.work_id=?`,workId);
 return step?step.active_episode===1&&step.binding===current:!workId.startsWith('leaver:');
}

// An active approved episode keeps ownership of its original SCIM work even
// when ordinary drift reconciliation or assignment maintenance visits it.
export function leaverWorkGuard(appId,type,subjectId,workColumn=null) {
 return {clause:`EXISTS(SELECT 1 FROM auth_lifecycle_steps s JOIN auth_lifecycle_plans p ON p.id=s.plan_id
  JOIN oa_operators o ON o.id=p.person_id JOIN auth_people d ON d.person_id=p.person_id
  WHERE o.status='inactive' AND d.terminated_at=p.denial_at
  AND NOT EXISTS(SELECT 1 FROM auth_lifecycle_plans newer WHERE newer.person_id=p.person_id AND newer.rowid>p.rowid)
  AND s.app_id=? ${workColumn?'AND s.work_id='+workColumn:''} AND ((?='person' AND s.kind='scim' AND s.person_id=?)
   OR (?='group' AND s.kind='scim_group' AND EXISTS(SELECT 1 FROM json_each(p.plan,'$.lifecycle.steps') j
    WHERE json_extract(j.value,'$.kind')='scim_group' AND json_extract(j.value,'$.appId')=s.app_id
    AND json_extract(j.value,'$.subjectId')=?))))`,args:[appId,type,subjectId,type,subjectId]};
}
