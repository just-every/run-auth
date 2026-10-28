import {one,all,run} from '../core.mjs';
import {liveSourceGuard} from './store.mjs';

export const isDirectoryObligation=ob=>ob.source_id?.startsWith('directory-source:');
export async function directoryBinding(ctx,ob) {
 return ob.directory_source_id?{source_id:ob.directory_source_id,episode:ob.episode}:ob.id?one(ctx,'SELECT source_id,episode FROM auth_directory_source_obligations WHERE obligation_id=?',ob.id):null;
}
export async function directorySourceCandidates(ctx) {
 return (await all(ctx,`SELECT s.* FROM auth_directory_sources s JOIN oa_operators p ON p.id=s.created_by
  WHERE s.kind='scim' AND s.mode='pull' AND s.disabled_at IS NULL AND p.status='active' AND p.role IN ('owner','admin') AND p.version=s.owner_version
  AND (s.last_error IS NOT NULL OR COALESCE(s.last_read_at,s.created_at)+15*60000<=?)`,ctx.now()))
  .map(s=>({kind:'app_setup',source_id:'directory-source:'+s.id+':'+s.observation_version,directory_source_id:s.id,episode:s.observation_version,owner_id:s.created_by,created_at:s.last_failure_at??(s.last_read_at??s.created_at)+15*60000,next_due_at:s.last_failure_at??(s.last_read_at??s.created_at)+15*60000}));
}
export async function directorySourceState(ctx,ob) {
 if(!isDirectoryObligation(ob))return null;
 const binding=await directoryBinding(ctx,ob),source=binding&&await one(ctx,'SELECT * FROM auth_directory_sources WHERE id=?',binding.source_id);
 if(!source)return {state:'cancelled',action:'directory_source_unavailable',error:'directory_source_unavailable'};
 if(source.disabled_at!==null)return {state:'cancelled',action:'directory_source_disabled',error:'directory_source_disabled'};
 const guard=liveSourceGuard(source);
 if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))return {state:'cancelled',action:'directory_source_custody_lost',error:'directory_source_authority_changed'};
 if(source.observation_version!==binding.episode)return {state:'completed',action:'directory_source_observation_restored'};
 return {state:'open',action:'check_source_credentials_and_connection_then_read_directory',error:source.last_error??'directory_source_poll_overdue'};
}
export async function directorySourceHolder(ctx,ob,personId) {
 const binding=await directoryBinding(ctx,ob),source=binding&&await one(ctx,'SELECT * FROM auth_directory_sources WHERE id=? AND created_by=?',binding.source_id,personId);
 if(!source)return false;
 const guard=liveSourceGuard(source);return Boolean(await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args));
}
export async function recordDirectoryFailure(ctx,source,error) {
 const guard=liveSourceGuard(source);
 // A delayed failed read cannot overwrite a newer authenticated observation.
 await run(ctx,`UPDATE auth_directory_sources SET last_error=?,last_failure_at=COALESCE(last_failure_at,?),next_poll_at=? WHERE id=? AND revision=? AND ${guard.clause}`,error,ctx.now(),ctx.now()+15*60000,source.id,source.revision,...guard.args);
}
export async function directorySourceHealth(ctx,source) {
 if(source.kind!=='scim'||source.mode!=='pull')return null;
 const custodian=await one(ctx,'SELECT display_name FROM oa_operators WHERE id=?',source.created_by);
 const guard=liveSourceGuard(source),live=Boolean(await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args));
 return {state:source.disabled_at!==null?'disabled':!live?'custody_lost':source.last_error?'failed':(source.last_read_at??source.created_at)+15*60000<=ctx.now()?'overdue':'current',custodianId:source.created_by,custodianName:custodian?.display_name??source.created_by,nextReadAt:source.next_poll_at};
}
