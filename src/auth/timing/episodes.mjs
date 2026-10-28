// Capture the inventory and effects under the same authority as the inactive
// state write. No post-commit callback is needed to discover the work on restart.
import {random,all,one} from '../core.mjs';
const FENCE='https://runeditrun.com/events/identity-fence';
const liveEpisode=`EXISTS(SELECT 1 FROM auth_timing_episodes e JOIN oa_operators p ON p.id=e.person_id
 JOIN auth_people d ON d.person_id=p.id WHERE e.id=episode_id AND e.ended_at IS NULL
 AND p.status='inactive' AND d.terminated_at=e.event_at)`;

export function terminationStatements(ctx,g,personId,{id,at},actorId) {
 const statement=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const exists='EXISTS(SELECT 1 FROM auth_timing_episodes WHERE id=?)';
 return [
  statement(`UPDATE auth_timing_episodes SET ended_at=? WHERE person_id=? AND ended_at IS NULL AND ${g.clause}`,at,personId,...g.args),
  statement(`INSERT INTO auth_timing_episodes(id,employer_id,person_id,event_at,local_denial_at)
   SELECT ?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND role!='owner' AND status IN ('active','inactive'))`,id,ctx.organizationId??'root',personId,at,at,...g.args,personId),
  statement(`INSERT INTO auth_timing_apps(episode_id,app_id,channel,app_name,remote_id)
   SELECT ?,a.id,CASE WHEN c.app_id IS NULL THEN 'unsupported' ELSE 'scim' END,a.name,s.remote_id
   FROM auth_apps a LEFT JOIN auth_scim_connectors c ON c.app_id=a.id
   LEFT JOIN auth_scim_accounts s ON s.app_id=a.id AND s.subject_type='person' AND s.subject_id=?
   WHERE ${exists} AND (s.remote_id IS NOT NULL OR EXISTS(SELECT 1 FROM auth_app_assignments x
    LEFT JOIN auth_group_members m ON x.principal_type='group' AND m.group_id=x.principal_id
    WHERE x.app_id=a.id AND ((x.principal_type='person' AND x.principal_id=?) OR m.person_id=?)))`,id,personId,id,personId,personId),
  statement(`INSERT INTO auth_timing_apps(episode_id,app_id,channel,app_name,remote_id)
   SELECT ?,a.app_id,'scim-group:'||a.principal_id,p.name,s.remote_id FROM auth_app_assignments a
   JOIN auth_group_members m ON m.group_id=a.principal_id AND m.person_id=?
   JOIN auth_scim_connectors c ON c.app_id=a.app_id AND c.push_groups=1
   JOIN auth_apps p ON p.id=a.app_id LEFT JOIN auth_scim_accounts s
    ON s.app_id=a.app_id AND s.subject_type='group' AND s.subject_id=a.principal_id
   WHERE a.principal_type='group' AND ${exists}`,id,personId,id),
  statement(`INSERT INTO auth_timing_apps(episode_id,app_id,channel,app_name)
   SELECT ?,c.id,'backchannel',c.name FROM auth_clients c JOIN auth_grants x ON x.client_id=c.id
   WHERE x.person_id=? AND ${exists}`,id,personId,id),
  statement(`UPDATE auth_provisioning SET state='superseded' WHERE subject_type='person' AND subject_id=?
   AND state IN ('pending','failed','blocked') AND ${exists}`,personId,id),
  statement(`INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at)
   SELECT 'timing:'||episode_id||':scim:'||app_id,app_id,'person',?,'person_terminated',?,'pending',?
   FROM auth_timing_apps WHERE episode_id=? AND channel='scim'`,personId,at,at,id),
  statement(`INSERT INTO auth_timing_work(work_id,channel,episode_id)
   SELECT 'timing:'||episode_id||':scim:'||app_id,'scim',episode_id FROM auth_timing_apps WHERE episode_id=? AND channel='scim'`,id),
  statement(`UPDATE auth_provisioning SET state='superseded' WHERE subject_type='group' AND state IN ('pending','failed','blocked')
   AND EXISTS(SELECT 1 FROM auth_timing_apps a WHERE a.episode_id=? AND a.app_id=auth_provisioning.app_id
    AND a.channel='scim-group:'||auth_provisioning.subject_id)`,id),
  statement(`INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at)
   SELECT 'timing:'||episode_id||':'||channel||':'||app_id,app_id,'group',substr(channel,length('scim-group:')+1),
    'person_terminated',?,'pending',? FROM auth_timing_apps WHERE episode_id=? AND channel LIKE 'scim-group:%'`,at,at,id),
  statement(`INSERT INTO auth_logout_deliveries(id,client_id,person_id,event,jti,next_attempt_at,created_at)
   SELECT 'timing:'||a.episode_id||':backchannel:'||c.id,c.id,?,?,lower(hex(randomblob(16))),?,?
   FROM auth_timing_apps a JOIN auth_clients c ON c.id=a.app_id
   WHERE a.episode_id=? AND a.channel='backchannel' AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL`,personId,FENCE,at,at,id),
  statement(`INSERT INTO auth_timing_work(work_id,channel,episode_id)
   SELECT 'timing:'||a.episode_id||':backchannel:'||c.id,'backchannel',a.episode_id
   FROM auth_timing_apps a JOIN auth_clients c ON c.id=a.app_id
   WHERE a.episode_id=? AND a.channel='backchannel' AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL`,id),
  statement(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at)
   SELECT ?,'lifecycle_timing_committed',?,? WHERE ${exists}`,actorId,personId,at,id),
  statement(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${exists}`,
   JSON.stringify({episodeId:id,personId,eventAt:at,localDenialAt:at,observation:'guarded inactive-state commit'}),id),
 ];
}

export const newEpisode=ctx=>({id:random(),at:ctx.now()});
export const endEpisodes=(ctx,g,personId)=>ctx.db.prepare(`UPDATE auth_timing_episodes SET ended_at=? WHERE person_id=? AND ended_at IS NULL AND ${g.clause}`).bind(ctx.now(),personId,...g.args);

// A later profile update can replace the work queue, but keeps the exact
// termination episode. Rehire ends the correlation, even when clocks coincide.
export const currentEpisode=`(SELECT e.id FROM auth_timing_episodes e JOIN oa_operators p ON p.id=e.person_id
 JOIN auth_people d ON d.person_id=p.id WHERE e.person_id=? AND p.status='inactive'
 AND e.ended_at IS NULL AND d.terminated_at=e.event_at ORDER BY e.event_at DESC LIMIT 1)`;

function observationAudit(ctx,episodeId,appId,channel,evidenceId) {
 const exists=`EXISTS(SELECT 1 FROM auth_timing_episodes e JOIN auth_timing_apps a ON a.episode_id=e.id
  WHERE e.id=? AND a.app_id=? AND a.channel=? AND a.connector_retired=0 AND ${liveEpisode})`;
 return [
  ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at)
   SELECT NULL,'lifecycle_timing_observed',person_id,? FROM auth_timing_episodes WHERE id=? AND ${exists}`)
   .bind(ctx.now(),episodeId,episodeId,appId,channel),
  ctx.db.prepare(`INSERT INTO auth_activity_details(activity_id,detail)
   SELECT last_insert_rowid(),json_object('episodeId',e.id,'personId',e.person_id,'appId',a.app_id,'channel',a.channel,
    'eventAt',e.event_at,'localDenialAt',e.local_denial_at,'dispatchedAt',a.dispatched_at,
    'acceptedAt',a.accepted_at,'remoteVerifiedAt',a.verified_at,'evidenceId',?)
   FROM auth_timing_episodes e JOIN auth_timing_apps a ON a.episode_id=e.id
   WHERE e.id=? AND a.app_id=? AND a.channel=? AND a.connector_retired=0 AND ${liveEpisode}`).bind(evidenceId,episodeId,appId,channel),
 ];
}

export async function observeProvisioning(ctx,ob,{dispatchedAt,verifiedAt,operation,members=null}) {
 if(ob.subject_type==='group')return observeGroup(ctx,ob,{dispatchedAt,verifiedAt,members});
 if(!ob.timing_episode_id||ob.subject_type!=='person')return;
 await ctx.db.batch([ctx.db.prepare(`UPDATE auth_timing_apps SET dispatched_at=COALESCE(dispatched_at,?),
  verified_at=COALESCE(verified_at,CASE WHEN remote_id IS NOT NULL AND remote_id=(SELECT remote_id FROM auth_scim_accounts
   WHERE app_id=? AND subject_type='person' AND subject_id=?) THEN ? ELSE NULL END) WHERE episode_id=? AND app_id=? AND channel='scim'
  AND connector_retired=0
  AND ${liveEpisode}
  `).bind(dispatchedAt,ob.app_id,ob.subject_id,['delete','deactivate'].includes(operation)?verifiedAt:null,ob.timing_episode_id,ob.app_id),
  ...observationAudit(ctx,ob.timing_episode_id,ob.app_id,'scim',ob.id)]);
}

async function observeGroup(ctx,ob,{dispatchedAt,verifiedAt,members}) {
 const channel='scim-group:'+ob.subject_id;
 const episodes=await all(ctx,`SELECT a.episode_id,a.remote_id,
  (SELECT u.remote_id FROM auth_timing_apps u WHERE u.episode_id=a.episode_id AND u.app_id=a.app_id AND u.channel='scim') AS person_remote_id
  FROM auth_timing_apps a JOIN auth_timing_episodes e ON e.id=a.episode_id
  JOIN oa_operators p ON p.id=e.person_id JOIN auth_people d ON d.person_id=p.id
  WHERE a.app_id=? AND a.channel=? AND a.connector_retired=0 AND e.ended_at IS NULL AND p.status='inactive'
   AND d.terminated_at=e.event_at AND e.event_at<=?`,ob.app_id,channel,ob.event_at);
 if(!episodes.length)return;
 const held=await one(ctx,"SELECT remote_id FROM auth_scim_accounts WHERE app_id=? AND subject_type='group' AND subject_id=?",ob.app_id,ob.subject_id);
 for(const episode of episodes){
  // A newer group queue can prove earlier unresolved membership removals, but
  // only while those same leaver episodes remain current and their captured
  // managed accounts are absent from the actual group readback.
  const verified=verifiedAt!==null&&Array.isArray(members)&&episode.remote_id!==null&&held?.remote_id===episode.remote_id
   &&episode.person_remote_id!==null&&!members.includes(episode.person_remote_id);
  await ctx.db.batch([
   ctx.db.prepare(`UPDATE auth_timing_apps SET dispatched_at=COALESCE(dispatched_at,?),
    verified_at=COALESCE(verified_at,CASE WHEN remote_id=(SELECT remote_id FROM auth_scim_accounts
     WHERE app_id=? AND subject_type='group' AND subject_id=?) THEN ? ELSE NULL END)
    WHERE episode_id=? AND app_id=? AND channel=? AND connector_retired=0 AND ${liveEpisode}`)
    .bind(dispatchedAt,ob.app_id,ob.subject_id,verified?verifiedAt:null,episode.episode_id,ob.app_id,channel),
   ...observationAudit(ctx,episode.episode_id,ob.app_id,channel,ob.id),
  ]);
 }
}

export async function observeLogout(ctx,d,{dispatchedAt,acceptedAt=null}) {
 if(!d.timing_episode_id)return;
 // A back-channel HTTP receipt establishes acceptance, never remote readback.
 await ctx.db.batch([ctx.db.prepare(`UPDATE auth_timing_apps SET dispatched_at=COALESCE(dispatched_at,?),accepted_at=COALESCE(accepted_at,?)
  WHERE episode_id=? AND app_id=? AND channel='backchannel'
  AND ${liveEpisode}`).bind(dispatchedAt,acceptedAt,d.timing_episode_id,d.client_id),
  ...observationAudit(ctx,d.timing_episode_id,d.client_id,'backchannel',d.id)]);
}
