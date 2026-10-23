import {one,run,fail,json,auditDetail,requireSession} from '../../core.mjs';
import {requireLocalEmail} from '../../local-email.mjs';
import {directoryAction} from '../../workforce/people/routes.mjs';
import {personChanged,groupChanged} from '../../provisioning/obligations.mjs';
import {fencePerson} from '../../links/logout.mjs';
import {reviewFile} from './review.mjs';
export async function applyHrFile(ctx,request,s,data) {
 if(data.confirm!==true||typeof data.digest!=='string'||!Array.isArray(data.rows)||!data.rows.length||data.rows.length>200||
    data.rows.some(idx=>!Number.isInteger(idx)||idx<0)||new Set(data.rows).size!==data.rows.length)fail('explicit_hr_preview_required',403);
 const review=await reviewFile(ctx,s,String(data.fileId??''));
 if(review.feed.id!==data.feedId||review.feed.disabled_at!==null||review.file.state==='reviewed')fail('hr_file_not_applicable',409);
 if(review.digest!==data.digest)fail('hr_preview_changed',409);
 if(review.file.reasons.some(reason=>reason!=='termination_threshold_exceeded'))fail('malformed_hr_file_cannot_apply',409);
 if(review.file.reasons.includes('termination_threshold_exceeded')&&data.confirmHeld!==true)fail('explicit_destructive_hr_confirmation_required',403);
 const selected=data.rows.map(idx=>review.outcomes.find(row=>row.idx===idx)||fail('hr_row_not_found',404));
 if(selected.some(row=>!['review_existing','new_hire_review_required'].includes(row.outcome)))fail('hr_row_requires_review',409);
 if(review.plan&&!review.plan.ok||review.newPlans.some(row=>data.rows.includes(row.idx)&&row.plan.refusals.length))fail('hr_row_refused',409);
 // The same native public commands retain hardware/fresh-email, rank, typed
 // source fields, rule effects and optimistic preview checks. No feed token
 // can reach this door or substitute for this human session.
 const existing=selected.filter(row=>row.outcome==='review_existing');
 const completed=[];
 if(existing.length) {
  const edits=review.edits.filter(edit=>existing.some(row=>row.personId===edit.personId));
  const {loadDirectory}=await import('../../workforce/people/load.mjs');
  const {planEdits}=await import('../../workforce/people/plan.mjs');
  const plan=await planEdits(ctx,await loadDirectory(ctx),edits,s.person_id);
  // If the selected native plan differs from the approved entries, do not
  // silently accept a concurrent change while preparing the native request.
  for(const entry of plan.entries)if(JSON.stringify(entry)!==JSON.stringify(review.plan.entries.find(prior=>prior.personId===entry.personId)))fail('hr_preview_changed',409);
  const reply=await directoryAction(ctx,request,'/directory/apply',{edits,digest:plan.digest},{notify:()=>{}});
  if(!reply.ok)return reply;
  completed.push(...existing.map(row=>({idx:row.idx,personId:row.personId})));
 }
 for(const outcome of selected.filter(row=>row.outcome==='new_hire_review_required')) {
  const current=await requireSession(ctx,request,true);requireLocalEmail(ctx,current);
  const row=review.records.find(row=>row.idx===outcome.idx),sourceId=review.feed.id+':'+row.sourceId;
  // Native onboard refuses every email/source collision and creates only an
  // invited member; normal browser-bound email proof and factor enrollment
  // remain mandatory. Invitations are a separate explicit action.
  const reply=await directoryAction(ctx,request,'/directory/onboard',{email:row.email,name:row.fields.name??row.email,source:'hr',sourceId,set:row.fields,invite:false},{notify:()=>{}});
  if(!reply.ok)return reply;
  const made=await reply.json();completed.push({idx:row.idx,personId:made.id});
 }
 for(const item of completed) {
  // Reconcile desired native effects before recording local completion.
  // A lost response/restart can be reviewed again using the stable HR source;
  // it cannot silently create another person or fabricate remote completion.
  const person=await one(ctx,'SELECT status FROM oa_operators WHERE id=?',item.personId);
  if(person?.status==='inactive')await fencePerson(ctx,item.personId);
  await personChanged(ctx,item.personId,'hr_file_applied');
  const groups=review.plan?.entries.find(row=>row.personId===item.personId)?.groups;
  for(const group of [...(groups?.added??[]),...(groups?.removed??[])])await groupChanged(ctx,group.id,[item.personId],'hr_file_applied');
  await run(ctx,'UPDATE auth_hr_file_rows SET applied_at=? WHERE file_id=? AND idx=? AND applied_at IS NULL',ctx.now(),review.file.id,item.idx);
  await auditDetail(ctx,s.person_id,'hr_file_row_applied',item.personId,{fileId:review.file.id,feedId:review.feed.id,row:item.idx,local:true,remote:'unverified'});
 }
 return json({fileId:review.file.id,locallyApplied:completed,remote:'unverified',futureRowsRequireNewReview:true});
}
