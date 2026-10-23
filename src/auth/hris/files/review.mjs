import {one,all,hash,fail} from '../../core.mjs';
import {invokeHooks} from '../../hooks/index.mjs';
import {loadDirectory} from '../../workforce/people/load.mjs';
import {planEdit,planEdits} from '../../workforce/people/plan.mjs';

export async function reviewFile(ctx,s,fileId) {
 const file=await one(ctx,'SELECT * FROM auth_hr_files WHERE id=?',fileId)||fail('hr_file_not_found',404);
 const feed=await one(ctx,'SELECT * FROM auth_hr_feeds WHERE id=?',file.feed_id)||fail('hr_feed_not_found',404);
 const epoch=(await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1')).epoch;
 const raw=(await all(ctx,'SELECT idx,record,applied_at FROM auth_hr_file_rows WHERE file_id=? ORDER BY idx',file.id));
 const records=[];
 for(const stored of raw) {
  const row={...JSON.parse(stored.record),idx:stored.idx,appliedAt:stored.applied_at};
  if(!row.appliedAt&&row.effectiveAt<=ctx.now()) {
   const hook=await invokeHooks(ctx,'user_import',{sourceId:feed.id+':'+row.sourceId,email:row.email,name:row.fields.name});
   if(hook.profile?.name)row.fields={...row.fields,name:hook.profile.name};
  }
  records.push(row);
 }
 const dir=await loadDirectory(ctx),edits=[],outcomes=[],newPlans=[];
 for(const row of records) {
  const sourceId=feed.id+':'+row.sourceId,personId=dir.sources.get('hr:'+sourceId);
  if(row.appliedAt){outcomes.push({idx:row.idx,sourceId:row.sourceId,outcome:'locally_applied',personId});continue;}
  if(row.effectiveAt>ctx.now()||row.fields.start_date&&row.fields.start_date>new Date(ctx.now()).toISOString().slice(0,10)) {
   outcomes.push({idx:row.idx,sourceId:row.sourceId,outcome:'future_effective',effectiveAt:row.effectiveAt});continue;
  }
  if(personId) {
   const person=dir.people.get(personId);
   if(person.email!==row.email){outcomes.push({idx:row.idx,sourceId:row.sourceId,outcome:'identity_changed_review_required'});continue;}
   edits.push({personId,source:'hr',set:row.fields,state:row.state});
   outcomes.push({idx:row.idx,sourceId:row.sourceId,personId,outcome:'review_existing'});
  }else if(dir.byEmail.has(row.email))outcomes.push({idx:row.idx,sourceId:row.sourceId,outcome:'identity_collision_review_required',email:row.email});
  else if(row.state!=='active')outcomes.push({idx:row.idx,sourceId:row.sourceId,outcome:'unknown_worker_refused',email:row.email});
  else {
   const probe={id:'hr-preview:'+file.id+':'+row.idx,email:row.email,name:row.fields.name??row.email,role:'member',status:'invited',state:'invited',version:1,fields:new Map()};
   const prospective={...dir,people:new Map(dir.people).set(probe.id,probe),byEmail:new Map(dir.byEmail).set(probe.email,probe)};
   const fields={...row.fields};delete fields.name;
   const plan=await planEdit(ctx,prospective,{personId:probe.id,source:'hr',set:fields,email:row.email,bind:{source:'hr',sourceId}},s.person_id);
   newPlans.push({idx:row.idx,plan});
   outcomes.push({idx:row.idx,sourceId:row.sourceId,outcome:'new_hire_review_required',email:row.email,fields:row.fields});
  }
 }
 const plan=edits.length?await planEdits(ctx,dir,edits,s.person_id):null;
 if(epoch!==(await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1')).epoch)fail('hr_preview_changed',409);
 const digest=await hash(JSON.stringify({fileId:file.id,fileDigest:file.digest,epoch,records,outcomes,plan,newPlans}));
 return {file:{...file,reasons:JSON.parse(file.reasons)},feed,records,outcomes,edits,plan,newPlans,digest,
  gap:'Explicit current-time approval only. Future rows require a new review at their due time; automatic routine/effective-date lifecycle and outbound reminder consent remain unimplemented.'};
}
