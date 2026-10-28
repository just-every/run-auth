import {scimBinding,logoutBinding} from './binding.mjs';
import {all,one,random} from '../core.mjs';

// Read before the preview digest. The epoch fences inventory changes between
// preview and the transaction. No credentials or remote identifiers are copied.
export async function leaverPreview(ctx,personId,actorId) {
 const epoch={inventory:(await one(ctx,'SELECT epoch FROM auth_lifecycle_epoch WHERE id=1'))?.epoch??0,person:(await one(ctx,'SELECT epoch FROM auth_lifecycle_person_epoch WHERE person_id=?',personId))?.epoch??0};
 const apps=await all(ctx,`SELECT DISTINCT a.id,a.name,a.disabled_at,c.base_url,c.sealed_token,c.created_by,c.created_at,c.deprovision,c.push_groups,
  EXISTS(SELECT 1 FROM auth_scim_accounts s WHERE s.app_id=a.id AND s.subject_type='person' AND s.subject_id=?) AS managed
  FROM auth_apps a LEFT JOIN auth_scim_connectors c ON c.app_id=a.id WHERE
  EXISTS(SELECT 1 FROM auth_app_assignments x LEFT JOIN auth_group_members m ON x.principal_type='group' AND m.group_id=x.principal_id WHERE x.app_id=a.id AND ((x.principal_type='person' AND x.principal_id=?) OR m.person_id=?))
  OR EXISTS(SELECT 1 FROM auth_scim_accounts s WHERE s.app_id=a.id AND s.subject_type='person' AND s.subject_id=?)
  OR EXISTS(SELECT 1 FROM auth_provisioning p WHERE p.app_id=a.id AND p.subject_type='person' AND p.subject_id=?)
  OR EXISTS(SELECT 1 FROM auth_saml_sessions s JOIN auth_sessions z ON z.id=s.session_id WHERE s.app_id=a.id AND z.person_id=?)
  OR EXISTS(SELECT 1 FROM auth_oidc_sessions s JOIN auth_oidc_clients c ON c.client_id=s.client_id JOIN auth_sessions z ON z.id=s.session_id WHERE c.app_id=a.id AND z.person_id=?)
  ORDER BY a.id`,...Array(7).fill(personId));
 const linked=await all(ctx,'SELECT c.id,c.name,c.sector_id,c.logout_uri,c.disabled_at FROM auth_clients c JOIN auth_grants g ON g.client_id=c.id WHERE g.person_id=? ORDER BY c.id',personId);
 const missing=await all(ctx,`SELECT DISTINCT app_id FROM auth_scim_accounts s WHERE subject_type='person' AND subject_id=? AND NOT EXISTS(SELECT 1 FROM auth_apps a WHERE a.id=s.app_id)
  UNION SELECT DISTINCT app_id FROM auth_provisioning p WHERE subject_type='person' AND subject_id=? AND NOT EXISTS(SELECT 1 FROM auth_apps a WHERE a.id=p.app_id) ORDER BY app_id`,personId,personId);
 const steps=[{appId:null,app:'Auth',kind:'native',operation:'deny_sessions_and_tokens',within:60000}];
 for(const app of apps) {
  steps.push({appId:app.id,app:app.name,kind:app.deprovision&&!app.disabled_at?'scim':'unsupported',binding:app.deprovision?await scimBinding(app):null,operation:app.deprovision??'remote_account_unknown',within:300000,escalateAfter:900000});
  // SCIM inactive readback proves the account flag, not every vendor's sessions.
  steps.push({appId:app.id,app:app.name,kind:'unsupported',operation:'remote_sessions_unverified'});
  if(app.push_groups)for(const g of await all(ctx,"SELECT DISTINCT a.principal_id AS id FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group' AND m.person_id=? ORDER BY a.principal_id",app.id,personId))steps.push({appId:app.id,app:app.name,kind:'scim_group',subjectId:g.id,binding:await scimBinding(app),operation:'remove_membership',within:300000,escalateAfter:900000});
 }
 for(const app of linked)steps.push({appId:app.id,app:app.name,kind:app.logout_uri&&!app.disabled_at?'logout':'unsupported',binding:await logoutBinding(app),operation:'identity_fence',within:60000,retryFor:86400000});
 const sessions=await all(ctx,`SELECT DISTINCT c.app_id,c.backchannel_logout_uri,a.name,z.id AS sid FROM auth_oidc_sessions s JOIN auth_sessions z ON z.id=s.session_id JOIN auth_oidc_clients c ON c.client_id=s.client_id JOIN auth_apps a ON a.id=c.app_id WHERE z.person_id=?
  UNION SELECT c.app_id,c.backchannel_logout_uri,a.name,f.id AS sid FROM auth_refresh_families f JOIN auth_oidc_clients c ON c.client_id=f.client_id JOIN auth_apps a ON a.id=c.app_id WHERE f.person_id=? AND f.revoked_at IS NULL ORDER BY c.app_id,sid`,personId,personId);
 for(const session of sessions) {
  const client=await one(ctx,'SELECT client_id,app_id,backchannel_logout_uri FROM auth_oidc_clients WHERE app_id=?',session.app_id);
  steps.push({appId:session.app_id,app:session.name,kind:session.backchannel_logout_uri?'oidc_logout':'unsupported',clientId:client.client_id,sid:session.sid,binding:await logoutBinding(client,true),operation:'end_app_session',within:60000,retryFor:86400000});
 }
 for(const app of missing)steps.push({appId:app.app_id,app:'Removed application',kind:'unsupported',operation:'removed_app_unverified'});
 return {epoch,custodianId:actorId,credentialActions:['End native sessions','Revoke native refresh grants','Refuse native app tokens','Preserve factors and person identity'],steps};
}

// Allocate each work id once, then insert it with the plan in the existing
// guarded directory transaction. Restart only resumes these original queues.
export function prepareLeaver(ctx,entry,digest,actorId,version) {
 if(entry.state?.kind!=='terminate'||!entry.lifecycle)return null;
 const id=random(),now=ctx.now(),steps=entry.lifecycle.steps.map(s=>({...s,id:random(),workId:['scim','scim_group','logout','oidc_logout'].includes(s.kind)?random():null}));
 const held={clause:'EXISTS(SELECT 1 FROM auth_lifecycle_plans WHERE id=?)',args:[id]};
 return {id,held,statements(g) {
  const q=(sql,...args)=>ctx.db.prepare(sql).bind(...args),statements=[q(`INSERT INTO auth_lifecycle_plans(id,person_id,actor_id,custodian_id,preview_digest,plan,created_at,denial_at)
   SELECT ?,?,?,?,?,?,?,? WHERE ${g.clause} AND COALESCE((SELECT epoch FROM auth_lifecycle_epoch WHERE id=1),0)=?
   AND COALESCE((SELECT epoch FROM auth_lifecycle_person_epoch WHERE person_id=?),0)=?
   AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status IN ('active','inactive'))`,id,entry.personId,actorId,entry.lifecycle.custodianId,digest,JSON.stringify(entry),now,now,...g.args,entry.lifecycle.epoch.inventory,entry.personId,entry.lifecycle.epoch.person,entry.personId,version)];
  for(const s of steps) {
   statements.push(q(`INSERT INTO auth_lifecycle_steps(id,plan_id,person_id,app_id,app_label,kind,work_id,binding,operation,deadline_at,escalate_at,state,outcome,verified_at)
    SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ${held.clause}`,s.id,id,entry.personId,s.appId,s.app,s.kind,s.workId,s.binding??null,s.operation,s.within?now+s.within:null,s.escalateAfter?now+s.escalateAfter:null,s.kind==='native'?'verified':s.kind==='unsupported'?'unknown':'unstarted',s.kind==='native'?'native_access_ended':s.kind==='unsupported'?s.operation:null,s.kind==='native'?now:null,...held.args));
   if(s.kind==='logout')statements.push(q(`INSERT INTO auth_logout_deliveries(id,client_id,person_id,event,jti,next_attempt_at,created_at) SELECT ?,?,?,'https://runeditrun.com/events/identity-fence',?,?,? WHERE ${held.clause}`,s.workId,s.appId,entry.personId,random(),now,now,...held.args));
   if(s.kind==='oidc_logout')statements.push(q(`INSERT INTO auth_oidc_logouts(id,client_id,person_id,sid,jti,next_attempt_at,created_at) SELECT ?,?,?,?,?,?,? WHERE ${held.clause}`,s.workId,s.clientId,entry.personId,s.sid,random(),now,now,...held.args));
   if(s.kind==='scim'||s.kind==='scim_group') {
    const type=s.kind==='scim'?'person':'group',subject=s.subjectId??entry.personId;
    statements.push(q(`UPDATE auth_provisioning SET state='superseded' WHERE app_id=? AND subject_type=? AND subject_id=? AND state IN ('pending','failed','blocked') AND ${held.clause}`,s.appId,type,subject,...held.args));
    statements.push(q(`INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at) SELECT ?,?,?,?,'person_terminated',?,'pending',? WHERE ${held.clause}`,s.workId,s.appId,type,subject,now,now,...held.args));
   }
  }
  statements.push(q(`UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND revoked_at IS NULL AND ${held.clause}`,now,entry.personId,...held.args));
  statements.push(q(`UPDATE auth_refresh_families SET revoked_at=?,reason='person_terminated' WHERE person_id=? AND revoked_at IS NULL AND ${held.clause}`,now,entry.personId,...held.args));
  statements.push(q(`UPDATE auth_refresh_families SET logout_queued_at=COALESCE(logout_queued_at,?) WHERE person_id=? AND ${held.clause}`,now,entry.personId,...held.args));
  return statements;
 }};
}
