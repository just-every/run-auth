import {one,all,fail,random} from '../core.mjs';
import {assignment} from '../workforce/directory.mjs';
import {queue} from '../provisioning/obligations.mjs';
import {itemDrift} from './snapshot.mjs';

export async function reviewTarget(ctx,s,{targetId,operation}) {
 if(!['certify','revoke'].includes(operation))fail('review_decision_not_available');
 const item=await one(ctx,'SELECT i.*,r.status AS review_status FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id WHERE i.id=?',targetId)??fail('review_item_not_found',404);
 if(item.review_status!=='open'||item.decision)fail('review_item_already_decided',409);
 if(item.reviewer_id!==s.person_id)fail('reviewer_required',403);
 if(item.subject_id===s.person_id)fail('self_approval_refused',403);
 if(await itemDrift(ctx,item))fail('review_access_changed',409);
 // Certifying and revoking existing access do not grant privilege. The
 // administrator gate still follows the actor's own administrator roles.
 return {snapshot:{item},personId:item.subject_id,privileged:false};
}
export function reviewStatements(ctx,s,target,operationId,won,p) {
 const item=target.snapshot.item,now=ctx.now();
 return [
  p(`UPDATE auth_review_items SET decision=?,reason=?,decided_by=?,decided_at=?,operation_id=? WHERE id=? AND decision IS NULL AND ${won.clause}`,target.operation,target.reason,s.person_id,now,operationId,item.id,...won.args),
  ...(target.operation==='revoke'?[p(`INSERT INTO auth_app_denials(app_id,person_id,operation_id,created_at) SELECT ?,?,?,? WHERE ${won.clause} ON CONFLICT(app_id,person_id) DO NOTHING`,item.app_id,item.subject_id,operationId,now,...won.args)]:[]),
  p(`INSERT INTO auth_review_events(id,review_id,item_id,actor_id,event,detail,created_at) SELECT ?,?,?,?,?,?,? WHERE ${won.clause}`,random(),item.review_id,item.id,s.person_id,target.operation,JSON.stringify({reason:target.reason,operationId}),now,...won.args),
 ];
}
export async function finishRemediation(ctx,itemId) {
 const item=await one(ctx,'SELECT * FROM auth_review_items WHERE id=?',itemId);
 if(item?.decision==='revoke')await queue(ctx,item.app_id,[['person',item.subject_id]],'review_revocation');
}
export async function remediation(ctx,item) {
 if(!item.decision)return {state:'awaiting_decision',complete:false};
 if(item.decision==='certify')return {state:'certified',complete:true};
 if(await assignment(ctx,item.app_id,item.subject_id))return {state:'local_access_still_present',complete:false};
 const connector=await one(ctx,'SELECT 1 FROM auth_scim_connectors WHERE app_id=?',item.app_id);
 const account=await one(ctx,"SELECT state FROM auth_scim_accounts WHERE app_id=? AND subject_type='person' AND subject_id=?",item.app_id,item.subject_id);
 const latest=await one(ctx,"SELECT id,state,last_error,verified_at FROM auth_provisioning WHERE app_id=? AND subject_type='person' AND subject_id=? AND reason='review_revocation' ORDER BY event_at DESC,id DESC LIMIT 1",item.app_id,item.subject_id);
 if(!connector)return {state:'remote_removal_unverified',detail:'No connector can verify downstream access. Local access is denied.',complete:false};
 const complete=latest?.state==='verified'&&['inactive','deleted'].includes(account?.state);
 return {state:complete?'verified_removed':latest?.state??'remediation_pending',detail:latest?.last_error??null,provisioning:latest?.id??null,verifiedAt:latest?.verified_at??null,complete};
}
export async function reviewView(ctx,s,review,canManage=false) {
 const rows=await all(ctx,'SELECT * FROM auth_review_items WHERE review_id=? ORDER BY id',review.id),items=[];
 for(const row of rows) {
  const snap=JSON.parse(row.snapshot);
  if(!canManage&&row.reviewer_id!==s.person_id)continue;
  items.push({...row,snapshot:snap,subject_name:snap.identity.name,app_name:snap.assignment.app,drift:await itemDrift(ctx,row),remediation:await remediation(ctx,row),canDecide:review.status==='open'&&!row.decision&&row.reviewer_id===s.person_id&&row.subject_id!==s.person_id});
 }
 const allResults=await Promise.all(rows.map(row=>remediation(ctx,row))),decided=rows.filter(i=>i.decision).length,unfinished=allResults.filter(r=>!r.complete).length;
 return {...review,overdue:review.status==='open'&&review.due_at<=ctx.now(),items,completion:{decided,total:rows.length,unfinished,complete:decided===rows.length&&unfinished===0}};
}
