import {one,all,hash,fail} from '../core.mjs';
import {invokeHooks} from '../hooks/index.mjs';
import {loadDirectory} from '../workforce/people/load.mjs';
import {planEdit,planEdits} from '../workforce/people/plan.mjs';
import {requireAccountRank} from '../ranks.mjs';
import {sourceOf,nativeSourceId} from './store.mjs';

export const epochOf=async ctx=>(await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1')).epoch;
export async function importedRow(ctx,source,raw) {
 const sourceId=await nativeSourceId(source.id,raw.sourceId);
 const hook=await invokeHooks(ctx,'user_import',{sourceId,email:raw.email,name:raw.name});
 const row={...raw,fields:{...raw.fields,...(hook.profile?.name?{name:hook.profile.name}:{})}};
 row.fields=Object.fromEntries(JSON.parse(source.fields).map(key=>[key,row.fields[key]??null]));
 return row;
}
export async function nativePersonPlan(ctx,source,raw,actorId,dir) {
 const row=await importedRow(ctx,source,raw),sourceId=await nativeSourceId(source.id,row.sourceId);
 const personId=dir.sources.get('directory:'+sourceId),person=dir.people.get(personId);
 let plan;
 if(person){
  await requireAccountRank(ctx,{actorId},personId,{clause:'1',args:[]});
  plan=await planEdits(ctx,dir,[{personId,source:'directory',set:row.fields,email:row.email,state:row.active&&!row.deleted?'active':'suspended'}],actorId);
 }else{
  const refusals=[];
  if(dir.byEmail.has(row.email))refusals.push('identity_collision_review_required');
  if(!row.active||row.deleted)refusals.push('unknown_inactive_person');
  const probe={id:'directory-preview:'+sourceId,email:row.email,name:row.name,role:'member',status:'invited',state:'invited',version:1,fields:new Map()};
  const prospective={...dir,people:new Map(dir.people).set(probe.id,probe),byEmail:new Map(dir.byEmail).set(probe.email,probe)};
  const set={...row.fields};delete set.name;
  const entry=await planEdit(ctx,prospective,{personId:probe.id,source:'directory',set,email:row.email,bind:{source:'directory',sourceId}},actorId);
  entry.refusals.push(...refusals);plan={entries:[entry],ok:!entry.refusals.length,digest:await hash(JSON.stringify(entry))};
 }
 return {row,sourceId,personId:personId??null,plan,signature:plan.digest};
}
const touches=e=>e.writes.length||e.state||e.emailChange||e.nameChange||e.bind||e.groups.added.length||e.groups.removed.length;
export async function reviewSnapshot(ctx,actorId,snapshotId) {
 const snapshot=await one(ctx,'SELECT * FROM auth_directory_snapshots WHERE id=?',String(snapshotId??''))||fail('directory_snapshot_not_found',404);
 const source=await sourceOf(ctx,snapshot.source_id),epoch=await epochOf(ctx),dir=await loadDirectory(ctx),payload=JSON.parse(snapshot.payload);
 const changes=[],refusals=[],emails=new Set(),nativeUsers=new Map();
 for(const raw of payload.users){
  const native=await nativePersonPlan(ctx,source,raw,actorId,dir);
  if(emails.has(raw.email))refusals.push('duplicate_email:'+raw.email);emails.add(raw.email);
  for(const reason of native.plan.entries.flatMap(e=>e.refusals))refusals.push(raw.sourceId+':'+reason);
  nativeUsers.set(raw.sourceId,native);
  if(!native.personId||touches(native.plan.entries[0]))changes.push({kind:'person',externalId:raw.sourceId,raw,row:native.row,personId:native.personId,signature:native.signature,plan:native.plan});
 }
 const owned=await all(ctx,'SELECT m.external_id,m.group_id,g.name,g.rule FROM auth_directory_source_groups m JOIN auth_groups g ON g.id=m.group_id WHERE source_id=?',source.id);
 const sourcePeople=new Map();
 for(const person of dir.people.values()){
  const binding=dir.sourceIds.get('directory:'+person.id);if(binding?.startsWith(source.id+':'))sourcePeople.set(person.id,binding);
 }
 for(const row of payload.groups){
  const existing=owned.find(g=>g.external_id===row.sourceId),name=(source.name+': '+row.name);
  if(name.length>80){refusals.push(row.sourceId+':group_name_too_long');continue;}
  if(existing?.rule){refusals.push(row.sourceId+':source_group_has_native_rule');continue;}
  if(!existing&&!row.deleted){
   if(dir.groups.some(g=>g.name===name)){refusals.push(row.sourceId+':group_name_collision');continue;}
   changes.push({kind:'group_create',externalId:row.sourceId,name});
  }else if(existing&&!row.deleted&&existing.name!==name){
   if(dir.groups.some(g=>g.name===name&&g.id!==existing.group_id)){refusals.push(row.sourceId+':group_name_collision');continue;}
   changes.push({kind:'group_rename',externalId:row.sourceId,groupId:existing.group_id,name});
  }
  const wanted=new Set(),members=dir.members.get(existing?.group_id)??new Map();
  for(const externalId of row.deleted?[]:row.memberIds){
   const binding=await nativeSourceId(source.id,externalId),personId=dir.sources.get('directory:'+binding),incoming=nativeUsers.get(externalId);
   if((!personId&&!incoming)||incoming&&(!incoming.row.active||incoming.row.deleted)){refusals.push(row.sourceId+':unresolved_member:'+externalId);continue;}
   wanted.add(binding);
   if(!personId||!members.has(personId))changes.push({kind:'member_add',externalId:row.sourceId,userExternalId:externalId});
  }
  for(const personId of members.keys())if(row.deleted||!wanted.has(sourcePeople.get(personId)))changes.push({kind:'member_remove',externalId:row.sourceId,personId});
  if(existing&&row.deleted)changes.push({kind:'group_delete',externalId:row.sourceId,groupId:existing.group_id,name:existing.name});
 }
 const reasons=JSON.parse(snapshot.reasons);
 if(changes.some(c=>['member_remove','group_delete'].includes(c.kind))&&!reasons.includes('destructive_change'))reasons.push('destructive_change');
 if(epoch!==await epochOf(ctx))fail('directory_preview_changed',409);
 const digest=await hash(JSON.stringify({sourceId:source.id,snapshotId:snapshot.id,snapshotDigest:snapshot.digest,sourceRevision:source.revision,epoch,actorId,changes,refusals,reasons}));
 return {source,snapshot,epoch,sourceId:source.id,snapshotId:snapshot.id,digest,held:reasons.length>0,reasons,changes,refusals,ok:!refusals.length};
}
export const publicReview=({source,snapshot,epoch,...review})=>review;
