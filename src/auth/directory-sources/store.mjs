import {one,all,hash,random,fail,json,requireSession,auditDetail} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {object,identifier,LIMITS} from './network.mjs';
import {text,user,group} from './normalize.mjs';

export const DIRECTORY_SOURCES='/api/auth/directory-sources';
export const LIMITATIONS=['Every imported change requires an exact human preview and fresh administrator approval.','Destructive and incomplete observations stay held until separately confirmed.','Missing full-snapshot records never imply departures.','No recurring approval, outbound invitation or reminder consent is granted.','Timing, nested group membership and live provider qualification remain unproved.'];
export async function administrator(ctx,request,write=false){const session=await requireSession(ctx,request,true);if(!['owner','admin'].includes(session.role))fail('administrator_required',403);if(write)requireLocalEmail(ctx,session);return session;}
export function liveSourceGuard(source) {
 return {clause:"EXISTS(SELECT 1 FROM auth_directory_sources ds JOIN oa_operators custodian ON custodian.id=ds.created_by WHERE ds.id=? AND ds.disabled_at IS NULL AND custodian.status='active' AND custodian.role IN ('owner','admin') AND custodian.version=ds.owner_version)",args:[source.id]};
}
export const combine=(...guards)=>({clause:guards.map(g=>'('+g.clause+')').join(' AND '),args:guards.flatMap(g=>g.args)});
export async function sourceOf(ctx,id){const source=await one(ctx,'SELECT * FROM auth_directory_sources WHERE id=?',String(id??''));if(!source)fail('directory_source_not_found',404);return source;}
export async function requireLiveSource(ctx,source){const guard=liveSourceGuard(source);if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail('directory_source_authority_changed',403);return guard;}
export const nativeSourceId=async(sourceId,externalId)=>sourceId+':'+await hash(identifier(externalId));
export function publicSource(source){return {id:source.id,kind:source.kind,mode:source.mode,name:source.name,baseUrl:source.base_url,organizationBinding:source.organization_binding,fields:JSON.parse(source.fields),createdAt:source.created_at,lastReadAt:source.last_read_at,nextPollAt:source.next_poll_at,lastError:source.last_error,disabled:source.disabled_at!==null,limitations:LIMITATIONS};}
export function canonicalSnapshot(payload) {
 if(!object(payload)||typeof payload.complete!=='boolean'||!Array.isArray(payload.users)||!Array.isArray(payload.groups)||payload.users.length>LIMITS.users||payload.groups.length>LIMITS.groups)fail('directory_source_invalid_snapshot');
 const userIds=new Set(),groupIds=new Set();let members=0;
 const users=payload.users.map(row=>{
  if(!object(row)||typeof row.active!=='boolean'||!object(row.fields??{}))fail('directory_source_invalid_snapshot');
  const id=identifier(row.sourceId);if(userIds.has(id))fail('directory_source_duplicate_id');userIds.add(id);
  const entry=user({id},{email:row.email,name:row.name,active:row.active,profile:row.fields??{}});
  return {...entry,...(row.deleted===true?{deleted:true}:{})};
 }).sort((a,b)=>a.sourceId.localeCompare(b.sourceId));
 const groups=payload.groups.map(row=>{
  if(!object(row)||!Array.isArray(row.memberIds)||row.memberIds.length>LIMITS.members)fail('directory_source_invalid_snapshot');
  const id=identifier(row.sourceId);if(groupIds.has(id))fail('directory_source_duplicate_id');groupIds.add(id);
  const entry=group({id},row.name,row.memberIds,{countMembers(count){members+=count;if(members>LIMITS.members)fail('directory_source_limit',413);}});
  entry.memberIds.sort();return {...entry,...(row.deleted===true?{deleted:true}:{})};
 }).sort((a,b)=>a.sourceId.localeCompare(b.sourceId));
 return {complete:payload.complete,users,groups};
}
async function refreshObservation(ctx,source,guard) {
 const changed=await ctx.db.prepare(`UPDATE auth_directory_sources SET revision=revision+1,observation_version=observation_version+1,last_read_at=?,next_poll_at=CASE WHEN mode='pull' THEN ? ELSE NULL END,last_error=NULL,last_failure_at=NULL WHERE id=? AND revision=? AND ${guard.clause}`).bind(ctx.now(),ctx.now()+15*60000,source.id,source.revision,...guard.args).run();
 if(!changed.meta.changes)fail('directory_source_changed',409);
}
export async function stageSnapshot(ctx,source,payload,guard,{resource}={}) {
 const canonical=canonicalSnapshot(payload),serialized=JSON.stringify(canonical),digest=await hash(serialized);
 if(new TextEncoder().encode(serialized).length>LIMITS.snapshotBytes)fail('directory_source_limit',413);
 const existing=await one(ctx,'SELECT id,state,reasons FROM auth_directory_snapshots WHERE source_id=? AND digest=?',source.id,digest);
 if(existing){await refreshObservation(ctx,source,guard);return {snapshotId:existing.id,state:existing.state,reasons:JSON.parse(existing.reasons),replayed:true};}
 const reasons=[];if(!canonical.complete)reasons.push('incomplete_snapshot');if(!canonical.users.length&&!canonical.groups.length)reasons.push('empty_snapshot');
 if(canonical.users.some(row=>!row.active)||canonical.groups.some(row=>row.deleted))reasons.push('destructive_change');
 const id=random(),marker={clause:'EXISTS(SELECT 1 FROM auth_directory_snapshots WHERE id=?)',args:[id]};
 const statements=[ctx.db.prepare(`INSERT INTO auth_directory_snapshots(id,source_id,digest,payload,complete,state,reasons,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${guard.clause} AND EXISTS(SELECT 1 FROM auth_directory_sources WHERE id=? AND revision=?)`).bind(id,source.id,digest,serialized,canonical.complete?1:0,reasons.length?'held':'staged',JSON.stringify(reasons),ctx.now(),...guard.args,source.id,source.revision)];
 const resources=resource?[resource]:[...canonical.users.map(row=>({type:'Users',id:row.sourceId,document:row})),...canonical.groups.map(row=>({type:'Groups',id:row.sourceId,document:row}))];
 for(const row of resources)statements.push(ctx.db.prepare(`INSERT INTO auth_directory_resources(source_id,resource_type,external_id,document,deleted) SELECT ?,?,?,?,? WHERE ${marker.clause} ON CONFLICT(source_id,resource_type,external_id) DO UPDATE SET document=excluded.document,deleted=excluded.deleted`).bind(source.id,row.type,row.id,JSON.stringify(row.document),row.document.deleted?1:0,id));
 statements.push(ctx.db.prepare(`UPDATE auth_directory_sources SET revision=revision+1,observation_version=observation_version+1,last_failure_at=NULL,last_read_at=?,next_poll_at=CASE WHEN mode='pull' THEN ? ELSE NULL END,last_error=NULL WHERE id=? AND ${marker.clause}`).bind(ctx.now(),ctx.now()+15*60000,source.id,id));
 let done;try{done=await ctx.db.batch(statements);}catch(error){if(/UNIQUE/.test(String(error?.message))){const prior=await one(ctx,'SELECT id,state,reasons FROM auth_directory_snapshots WHERE source_id=? AND digest=?',source.id,digest);if(prior){await refreshObservation(ctx,source,guard);return {snapshotId:prior.id,state:prior.state,reasons:JSON.parse(prior.reasons),replayed:true};}}throw error;}
 if(!done[0].meta.changes)fail('directory_source_changed',409);
 await auditDetail(ctx,null,'directory_source_observed',source.id,{snapshotId:id,complete:canonical.complete,users:canonical.users.length,groups:canonical.groups.length,reasons});
 return {snapshotId:id,state:reasons.length?'held':'staged',reasons,replayed:false};
}
