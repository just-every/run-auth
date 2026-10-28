// Capture the inventory and effects under the same authority as the inactive
// state write. No post-commit callback is needed to discover the work on restart.
import {random,run} from '../core.mjs';
const FENCE='https://runeditrun.com/events/identity-fence';

export function terminationStatements(ctx,g,personId,{id,at}) {
 const statement=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const exists='EXISTS(SELECT 1 FROM auth_timing_episodes WHERE id=?)';
 return [
  statement(`INSERT INTO auth_timing_episodes(id,employer_id,person_id,event_at,local_denial_at)
   SELECT ?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND role!='owner' AND status IN ('active','inactive'))`,id,ctx.organizationId??'root',personId,at,at,...g.args,personId),
  statement(`INSERT INTO auth_timing_apps(episode_id,app_id,channel,app_name,remote_id)
   SELECT ?,a.id,CASE WHEN c.app_id IS NULL THEN 'unsupported' ELSE 'scim' END,a.name,s.remote_id
   FROM auth_apps a LEFT JOIN auth_scim_connectors c ON c.app_id=a.id
   LEFT JOIN auth_scim_accounts s ON s.app_id=a.id AND s.subject_type='person' AND s.subject_id=?
   WHERE ${exists} AND (s.remote_id IS NOT NULL OR EXISTS(SELECT 1 FROM auth_app_assignments x
    LEFT JOIN auth_group_members m ON x.principal_type='group' AND m.group_id=x.principal_id
    WHERE x.app_id=a.id AND ((x.principal_type='person' AND x.principal_id=?) OR m.person_id=?)))`,id,personId,id,personId,personId),
  statement(`INSERT INTO auth_timing_apps(episode_id,app_id,channel,app_name)
   SELECT ?,c.id,'backchannel',c.name FROM auth_clients c JOIN auth_grants x ON x.client_id=c.id
   WHERE x.person_id=? AND ${exists}`,id,personId,id),
  statement(`UPDATE auth_provisioning SET state='superseded' WHERE subject_type='person' AND subject_id=?
   AND state IN ('pending','failed','blocked') AND ${exists}`,personId,id),
  statement(`INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at,timing_episode_id)
   SELECT lower(hex(randomblob(16))),app_id,'person',?,'person_terminated',?,'pending',?,?
   FROM auth_timing_apps WHERE episode_id=? AND channel='scim'`,personId,at,at,id,id),
  statement(`INSERT INTO auth_logout_deliveries(id,client_id,person_id,event,jti,next_attempt_at,created_at,timing_episode_id)
   SELECT lower(hex(randomblob(16))),c.id,?,?,lower(hex(randomblob(16))),?,?,?
   FROM auth_timing_apps a JOIN auth_clients c ON c.id=a.app_id
   WHERE a.episode_id=? AND a.channel='backchannel' AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL`,personId,FENCE,at,at,id,id),
 ];
}

export const newEpisode=ctx=>({id:random(),at:ctx.now()});
export const endEpisodes=(ctx,g,personId)=>ctx.db.prepare(`UPDATE auth_timing_episodes SET ended_at=? WHERE person_id=? AND ended_at IS NULL AND ${g.clause}`).bind(ctx.now(),personId,...g.args);

// A later profile update can replace the work queue, but keeps the exact
// termination episode. Rehire ends the correlation, even when clocks coincide.
export const currentEpisode=`(SELECT e.id FROM auth_timing_episodes e JOIN oa_operators p ON p.id=e.person_id
 JOIN auth_people d ON d.person_id=p.id WHERE e.person_id=? AND p.status='inactive'
 AND e.ended_at IS NULL AND d.terminated_at=e.event_at ORDER BY e.event_at DESC LIMIT 1)`;

export async function observeProvisioning(ctx,ob,{dispatchedAt,verifiedAt,operation}) {
 if(!ob.timing_episode_id||ob.subject_type!=='person')return;
 await run(ctx,`UPDATE auth_timing_apps SET dispatched_at=COALESCE(dispatched_at,?),
  verified_at=COALESCE(verified_at,CASE WHEN remote_id IS NOT NULL AND remote_id=(SELECT remote_id FROM auth_scim_accounts
   WHERE app_id=? AND subject_type='person' AND subject_id=?) THEN ? ELSE NULL END) WHERE episode_id=? AND app_id=? AND channel='scim'
  AND EXISTS(SELECT 1 FROM auth_timing_episodes e WHERE e.id=episode_id AND e.ended_at IS NULL)
  `,dispatchedAt,ob.app_id,ob.subject_id,['delete','deactivate'].includes(operation)?verifiedAt:null,ob.timing_episode_id,ob.app_id);
}

export async function observeLogout(ctx,d,{dispatchedAt,acceptedAt=null}) {
 if(!d.timing_episode_id)return;
 // A back-channel HTTP receipt establishes acceptance, never remote readback.
 await run(ctx,`UPDATE auth_timing_apps SET dispatched_at=COALESCE(dispatched_at,?),accepted_at=COALESCE(accepted_at,?)
  WHERE episode_id=? AND app_id=? AND channel='backchannel'
  AND EXISTS(SELECT 1 FROM auth_timing_episodes e WHERE e.id=episode_id AND e.ended_at IS NULL)`,dispatchedAt,acceptedAt,d.timing_episode_id,d.client_id);
}
