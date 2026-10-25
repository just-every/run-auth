import {one,all,run,hash,fail,json,AuthError,random,auditDetail} from '../../core.mjs';
import {authority,requireAuthority} from '../../local-email.mjs';
import {loadDirectory} from '../../workforce/people/load.mjs';
import {planEdits,planEdit} from '../../workforce/people/plan.mjs';
import {applyAuthorizedPlan,onboardAuthorizedPerson} from '../../workforce/people/apply.mjs';
import {personChanged,groupChanged} from '../../provisioning/obligations.mjs';
import {fencePerson} from '../../links/logout.mjs';
import {reviewFile} from './review.mjs';

// One row's signature includes the current target, source binding and full native
// plan. Time passing alone does not change it; target and policy drift do.
async function rowPlan(ctx,review,row,actorId) {
 const dir=await loadDirectory(ctx),sourceId=review.feed.id+':'+row.sourceId;
 const personId=dir.sources.get('hr:'+sourceId);
 let plan,signature;
 if(personId){
  if(dir.people.get(personId)?.email!==row.email)fail('hr_target_changed',409);
  plan=await planEdits(ctx,dir,[{personId,source:'hr',set:row.fields,state:row.state}],actorId);
  signature=plan.digest;
 }else{
  if(dir.byEmail.has(row.email)||row.state!=='active')fail('hr_target_changed',409);
  const probe={id:'hr-preview:'+review.file.id+':'+row.idx,email:row.email,name:row.fields.name??row.email,role:'member',status:'invited',state:'invited',version:1,fields:new Map()};
  dir.people.set(probe.id,probe);dir.byEmail.set(probe.email,probe);
  const fields={...row.fields};delete fields.name;
  const entry=await planEdit(ctx,dir,{personId:probe.id,source:'hr',set:fields,email:row.email,bind:{source:'hr',sourceId}},actorId);
  plan={entries:[entry],ok:!entry.refusals.length};signature=await hash(JSON.stringify(entry));
 }
 if(!plan.ok)fail('hr_row_refused',409);
 return {dir,plan,personId:personId??null,signature};
}
export async function applyHrFile(ctx,request,s,data,{scheduled=false}={}) {
 if(data.confirm!==true||typeof data.digest!=='string'||!Array.isArray(data.rows)||!data.rows.length||data.rows.length>200||
    data.rows.some(idx=>!Number.isInteger(idx)||idx<0)||new Set(data.rows).size!==data.rows.length)fail('explicit_hr_preview_required',403);
 const review=await reviewFile(ctx,s,String(data.fileId??''));
 if(review.feed.id!==data.feedId||review.feed.disabled_at!==null||review.file.state==='reviewed')fail('hr_file_not_applicable',409);
 if(review.digest!==data.digest)fail('hr_preview_changed',409);
 if(review.file.reasons.some(reason=>reason!=='termination_threshold_exceeded'))fail('malformed_hr_file_cannot_apply',409);
 if(review.file.reasons.includes('termination_threshold_exceeded')&&data.confirmHeld!==true)fail('explicit_destructive_hr_confirmation_required',403);
 const selected=data.rows.map(idx=>review.outcomes.find(row=>row.idx===idx)||fail('hr_row_not_found',404));
 if(selected.some(row=>!['review_existing','new_hire_review_required',...(scheduled?['future_effective']:[])].includes(row.outcome)))fail('hr_row_requires_review',409);
 const guard=authority(ctx,s,['owner','admin']),statements=[];
 guard.clause+=' AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)';guard.args.push(review.epoch);
 guard.clause+=" AND EXISTS(SELECT 1 FROM auth_hr_feeds f JOIN oa_operators p ON p.id=f.created_by WHERE f.id=? AND f.disabled_at IS NULL AND f.token_hash=? AND p.status='active' AND p.role IN ('owner','admin') AND p.version=f.owner_version)";guard.args.push(review.feed.id,review.feed.token_hash);
 for(const outcome of selected){
  const row=review.records.find(row=>row.idx===outcome.idx),native=await rowPlan(ctx,review,row,s.person_id);
  const due=Math.max(row.effectiveAt,row.fields.start_date?Date.parse(row.fields.start_date+'T00:00:00Z'):0);
  statements.push(ctx.db.prepare(`INSERT INTO auth_hr_approved_rows(file_id,idx,id,approved_by,approver_version,approved_at,approved_digest,file_digest,record,plan_digest,target_id,due_at)
   SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}
   ON CONFLICT(file_id,idx) DO UPDATE SET id=excluded.id,approved_by=excluded.approved_by,approver_version=excluded.approver_version,approved_at=excluded.approved_at,approved_digest=excluded.approved_digest,file_digest=excluded.file_digest,record=excluded.record,plan_digest=excluded.plan_digest,target_id=excluded.target_id,due_at=excluded.due_at,state='pending',error=NULL WHERE auth_hr_approved_rows.state IN ('pending','review_required')`)
   .bind(review.file.id,row.idx,random(),s.person_id,s.person_version,ctx.now(),review.digest,review.file.digest,JSON.stringify(row),native.signature,native.personId,due,...guard.args));
 }
 const done=await ctx.db.batch(statements);await requireAuthority(ctx,s,guard);
 if(done.some(r=>!r.meta.changes))fail('hr_row_already_applied',409);
 await auditDetail(ctx,s.person_id,'hr_file_approved',review.file.id,{digest:review.digest,fileDigest:review.file.digest,rows:data.rows,scheduled});
 if(scheduled)return json({fileId:review.file.id,approved:true,rows:data.rows,remote:'unverified'});
 await executeHrRows(ctx,{fileId:review.file.id,sessionGuard:authority(ctx,s,['owner','admin'])});
 const completed=await all(ctx,"SELECT idx,target_id AS personId FROM auth_hr_approved_rows WHERE file_id=? AND state='completed'",review.file.id);
 return json({fileId:review.file.id,locallyApplied:completed.filter(row=>data.rows.includes(row.idx)),remote:'unverified',futureRowsRequireNewReview:false});
}
function liveGuard(ctx,job,feed) {
 return {clause:`EXISTS(SELECT 1 FROM auth_hr_approved_rows a JOIN auth_hr_files f ON f.id=a.file_id JOIN auth_hr_feeds feed ON feed.id=f.feed_id JOIN oa_operators approver ON approver.id=a.approved_by JOIN oa_operators custodian ON custodian.id=feed.created_by
  WHERE a.id=? AND a.state IN ('pending','effects_pending') AND f.state!='reviewed' AND f.digest=a.file_digest AND feed.disabled_at IS NULL AND feed.token_hash=? AND custodian.status='active' AND custodian.role IN ('owner','admin') AND custodian.version=feed.owner_version AND approver.status='active' AND approver.role IN ('owner','admin') AND approver.version=a.approver_version)`,args:[job.id,feed.token_hash]};
}
async function reconcile(ctx,job,entry) {
 const person=await one(ctx,'SELECT status FROM oa_operators WHERE id=?',job.target_id);
 if(person?.status==='inactive')await fencePerson(ctx,job.target_id);
 await personChanged(ctx,job.target_id,'hr_file_applied');
 for(const group of [...entry.groups.added,...entry.groups.removed])await groupChanged(ctx,group.id,[job.target_id],'hr_file_applied');
 await run(ctx,"UPDATE auth_hr_approved_rows SET state='completed',error=NULL WHERE id=? AND state='effects_pending'",job.id);
}
export async function executeHrRows(ctx,{fileId,sessionGuard}={}) {
 const jobs=await all(ctx,`SELECT * FROM auth_hr_approved_rows WHERE state IN ('pending','effects_pending') AND due_at<=? ${fileId?'AND file_id=?':''} ORDER BY due_at,file_id,idx LIMIT 200`,ctx.now(),...(fileId?[fileId]:[]));
 for(const job of jobs){
  try{
   const stored=JSON.parse(job.record);
   if(job.state==='effects_pending'){await reconcile(ctx,job,stored.appliedEntry);continue;}
   const feed=await one(ctx,'SELECT feed.* FROM auth_hr_feeds feed JOIN auth_hr_files file ON file.feed_id=feed.id WHERE file.id=?',job.file_id)||fail('hr_file_not_found',404);
   const guard=liveGuard(ctx,job,feed);
   if(sessionGuard){guard.clause+=` AND (${sessionGuard.clause})`;guard.args.push(...sessionGuard.args);}
   const assertAuthority=async()=>{if(!(await one(ctx,`SELECT ${guard.clause} AS held`,...guard.args)).held)fail('hr_approval_authority_changed',409);};
   await assertAuthority();
   const review=await reviewFile(ctx,{person_id:job.approved_by},job.file_id,{rowIndex:job.idx});
   const row=review.records.find(row=>row.idx===job.idx);
   if(!row||row.appliedAt||review.file.digest!==job.file_digest||JSON.stringify(row)!==job.record)fail('hr_approved_content_changed',409);
   const native=await rowPlan(ctx,review,row,job.approved_by);
   if(native.signature!==job.plan_digest||native.personId!==job.target_id)fail('hr_target_changed',409);
   // Fence a concurrent directory or policy edit between planning and commit.
   const epoch=review.epoch;
   const operation=random(),claim={...guard,args:[...guard.args]};
   guard.clause+=' AND EXISTS(SELECT 1 FROM auth_role_operations WHERE id=?)';guard.args.push(operation);
   const pending={clause:`(${guard.clause}) AND EXISTS(SELECT 1 FROM auth_hr_approved_rows WHERE id=? AND state='pending')`,args:[...guard.args,job.id]};
   const entry=native.plan.entries[0];
   const actor={actorId:job.approved_by,assertAuthority:async()=>{
    const current=await one(ctx,"SELECT state FROM auth_hr_approved_rows WHERE id=?",job.id);
    if(!current||!['effects_pending','completed'].includes(current.state))await assertAuthority();
   },receiptStatements:(g,personId)=>[
    ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'hr_file_row_applied',?,? WHERE ${g.clause}`).bind(job.approved_by,personId,ctx.now(),...g.args),
    ctx.db.prepare(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${g.clause}`).bind(JSON.stringify({fileId:job.file_id,row:job.idx,approver:job.approved_by,digest:job.approved_digest,fileDigest:job.file_digest,local:true,remote:'unverified'}),...g.args),
    ctx.db.prepare(`UPDATE auth_hr_file_rows SET applied_at=? WHERE file_id=? AND idx=? AND ${g.clause}`).bind(ctx.now(),job.file_id,job.idx,...g.args),
    ctx.db.prepare(`UPDATE auth_hr_approved_rows SET state='effects_pending',target_id=?,applied_at=?,record=? WHERE id=? AND ${g.clause}`).bind(personId,ctx.now(),JSON.stringify({...row,appliedEntry:entry}),job.id,...g.args),
   ],commit:async statements=>{const results=await ctx.db.batch([
    ctx.db.prepare(`INSERT INTO auth_role_operations(id,actor_id,session_id,permission,subject_id,detail,created_at) SELECT ?,?,?,'hr.approved',?,'{}',? WHERE ${claim.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?) AND EXISTS(SELECT 1 FROM auth_hr_approved_rows WHERE id=? AND state='pending')`).bind(operation,job.approved_by,job.id,job.file_id,ctx.now(),...claim.args,epoch,job.id),
    ...statements]);if(!results[0].meta.changes||!results.at(-1).meta.changes)fail('hr_row_concurrently_claimed',409);return results.slice(1);}};
   if(native.personId&&!entry.writes.length&&!entry.state&&!entry.emailChange&&!entry.nameChange&&!entry.bind&&!entry.groups.added.length&&!entry.groups.removed.length)await actor.commit(actor.receiptStatements(pending,native.personId));
   else if(native.personId)await applyAuthorizedPlan(ctx,actor,pending,native.dir,native.plan,{bulk:true});
   else{
    // Remove the preview-only identity before calling the native onboard door.
    native.dir.people.delete(entry.personId);native.dir.byEmail.delete(row.email);
    const made=await onboardAuthorizedPerson(ctx,actor,pending,native.dir,{email:row.email,name:row.fields.name??row.email,source:'hr',sourceId:review.feed.id+':'+row.sourceId,set:row.fields,invite:false},()=>{});
    if(made.refused)fail('hr_row_refused',409);
   }
   const applied=await one(ctx,'SELECT * FROM auth_hr_approved_rows WHERE id=?',job.id);
   if(applied.state==='effects_pending')await reconcile(ctx,applied,entry);
  }catch(error){
   if(!(error instanceof AuthError))throw error;
   await run(ctx,"UPDATE auth_hr_approved_rows SET state=?,error=? WHERE id=? AND state='pending'",error.status===503?'pending':'review_required',error.message,job.id);
   if(fileId)throw error;
  }
 }
}
