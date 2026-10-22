import {validateReduction,reductionStatements,getRoleOrder} from './reductions.mjs';
import {one,all,fail,random} from '../core.mjs';
import {assignment} from '../workforce/directory.mjs';
import {queue} from '../provisioning/obligations.mjs';
import {itemDrift} from './snapshot.mjs';

export async function reviewTarget(ctx,s,{targetId,operation,newRole}) {
 if(!['certify','revoke','reduce'].includes(operation))fail('review_decision_not_available');
 const item=await one(ctx,'SELECT i.*,r.status AS review_status FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id WHERE i.id=?',targetId)??fail('review_item_not_found',404);
 if(item.review_status!=='open'||item.decision)fail('review_item_already_decided',409);
 if(item.reviewer_id!==s.person_id)fail('reviewer_required',403);
 if(item.subject_id===s.person_id)fail('self_approval_refused',403);
 if(operation==='certify'&&await itemDrift(ctx,item))fail('review_access_changed',409);
 const reduction=operation==='reduce'?await validateReduction(ctx,item,newRole):null;
 // Certifying and revoking existing access do not grant privilege. The
 // administrator gate still follows the actor's own administrator roles.
 return {snapshot:{item,...(reduction?{reduction}:{})},personId:item.subject_id,privileged:false};
}
export function reviewStatements(ctx,s,target,operationId,won,p) {
 const item=target.snapshot.item,now=ctx.now();
 return [
  p(`UPDATE auth_review_items SET decision=?,reason=?,decided_by=?,decided_at=?,operation_id=? WHERE id=? AND decision IS NULL AND ${won.clause}`,target.operation,target.reason,s.person_id,now,operationId,item.id,...won.args),
  ...(target.operation==='reduce'?reductionStatements(ctx,{...item,reduction:target.snapshot.reduction},target.newRole,operationId,won,p):[]),
  ...(target.operation==='revoke'?[p(`INSERT INTO auth_app_denials(app_id,person_id,operation_id,created_at) SELECT ?,?,?,? WHERE ${won.clause} ON CONFLICT(app_id,person_id) DO NOTHING`,item.app_id,item.subject_id,operationId,now,...won.args)]:[]),
  p(`INSERT INTO auth_review_events(id,review_id,item_id,actor_id,event,detail,created_at) SELECT ?,?,?,?,?,?,? WHERE ${won.clause}`,random(),item.review_id,item.id,s.person_id,target.operation,JSON.stringify({reason:target.reason,operationId}),now,...won.args),
 ];
}
export async function finishRemediation(ctx,itemId) {
 const item=await one(ctx,'SELECT * FROM auth_review_items WHERE id=?',itemId);
 if(['revoke','reduce'].includes(item?.decision))await queue(ctx,item.app_id,[['person',item.subject_id]],item.decision==='reduce'?'review_reduction':'review_revocation');
}
export async function remediation(ctx,item) {
 if(!item.decision)return {state:'awaiting_decision',complete:false};
 if(item.decision==='certify')return {state:'certified',complete:true};
 const effective=await assignment(ctx,item.app_id,item.subject_id);
 if(item.decision==='revoke'&&effective)return {state:'local_access_still_present',complete:false};
 const connector=await one(ctx,'SELECT 1 FROM auth_scim_connectors WHERE app_id=?',item.app_id);
 const account=await one(ctx,"SELECT state FROM auth_scim_accounts WHERE app_id=? AND subject_type='person' AND subject_id=?",item.app_id,item.subject_id);
 const latest=await one(ctx,"SELECT id,state,last_error,verified_at FROM auth_provisioning WHERE app_id=? AND subject_type='person' AND subject_id=? AND reason=? ORDER BY event_at DESC,id DESC LIMIT 1",item.app_id,item.subject_id,item.decision==='reduce'?'review_reduction':'review_revocation');
 if(!connector)return {state:item.decision==='reduce'?'remote_reduction_unverified':'remote_removal_unverified',detail:item.decision==='reduce'?'Local access is capped. No connector can verify the downstream role.':'No connector can verify downstream access. Local access is denied.',complete:false};
 const cap=item.decision==='reduce'?await one(ctx,'SELECT role FROM auth_app_reductions WHERE app_id=? AND person_id=?',item.app_id,item.subject_id):null;
 const complete=latest?.state==='verified'&&(item.decision==='reduce'?account?.state==='active'&&effective?.role===cap?.role:['inactive','deleted'].includes(account?.state));
 return {state:complete?(item.decision==='reduce'?'verified_reduced':'verified_removed'):latest?.state??'remediation_pending',detail:latest?.last_error??null,provisioning:latest?.id??null,verifiedAt:latest?.verified_at??null,complete};
}
export async function reviewView(ctx,s,review,canManage=false) {
 const rows=await all(ctx,'SELECT * FROM auth_review_items WHERE review_id=? ORDER BY id',review.id),items=[];
 for(const row of rows) {
  const snap=JSON.parse(row.snapshot);
  if(!canManage&&row.reviewer_id!==s.person_id)continue;
  const order=await getRoleOrder(ctx,row.app_id),current=await assignment(ctx,row.app_id,row.subject_id),level=order.roles.find(r=>r.role===current?.role)?.level;
  const lowerRoles=level===undefined?[]:order.roles.filter(r=>r.level<level).map(r=>r.role);
  items.push({...row,lowerRoles,snapshot:snap,reviewer_name:row.reviewer_id===s.person_id?'You':(await one(ctx,'SELECT display_name FROM oa_operators WHERE id=?',row.reviewer_id))?.display_name??'Assigned reviewer',subject_name:snap.identity.name,app_name:snap.assignment.app,drift:await itemDrift(ctx,row),remediation:await remediation(ctx,row),canDecide:review.status==='open'&&!row.decision&&row.reviewer_id===s.person_id&&row.subject_id!==s.person_id});
 }
 const allResults=await Promise.all(rows.map(row=>remediation(ctx,row))),decided=rows.filter(i=>i.decision).length,unfinished=allResults.filter((r,i)=>rows[i].decision&&!r.complete).length;
 return {...review,overdue:review.status==='open'&&review.due_at<=ctx.now(),items,completion:{decided,total:rows.length,unfinished,complete:decided===rows.length&&unfinished===0}};
}
