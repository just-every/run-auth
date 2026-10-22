import {one,all,fail,random,json,requireSession} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {commit} from '../roles/commit.mjs';
import {assignment} from '../workforce/directory.mjs';
import {queue} from '../provisioning/obligations.mjs';

const validRole=role=>typeof role==='string'&&role.length>0&&role.length<=120&&role.trim()===role&&!/[\u0000-\u001f\u007f]/.test(role);
export async function getRoleOrder(ctx,appId) {
 const rows=await all(ctx,'SELECT role,level,revision FROM auth_app_role_order WHERE app_id=? ORDER BY level,role',appId);
 return {revision:rows[0]?.revision??null,roles:rows.map(({role,level})=>({role,level}))};
}
async function adminWrite(ctx,request,appId) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const epoch=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 if(!await one(ctx,'SELECT 1 FROM auth_apps WHERE id=? AND disabled_at IS NULL',appId))fail('app_not_found',404);
 const g=authority(ctx,s,['owner','admin']);
 return {s,g:{clause:`${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,args:[...g.args,epoch.epoch]}};
}

export async function roleOrderAction(ctx,request,data) {
 const appId=String(data.appId??''),{s,g}=await adminWrite(ctx,request,appId),roles=data.roles;
 if(!Array.isArray(roles)||!roles.length||roles.length>100||roles.some(r=>!r||!validRole(r.role)||!Number.isSafeInteger(r.level)||Math.abs(r.level)>1000000)||new Set(roles.map(r=>r.role)).size!==roles.length)fail('invalid_app_role_order');
 const ordered=roles.map(({role,level})=>({role,level})).sort((a,b)=>a.level-b.level||a.role.localeCompare(b.role)),revision=random(),now=ctx.now();
 const previous=await getRoleOrder(ctx,appId);
 await commit(ctx,s,g,'reviews.role_order.published',appId,{appId,revision,previousRevision:previous.revision,roles:ordered},(won,p)=>[
  p(`DELETE FROM auth_app_role_order WHERE app_id=? AND ${won.clause}`,appId,...won.args),
  ...ordered.map(r=>p(`INSERT INTO auth_app_role_order(app_id,role,level,revision,published_by,published_at) SELECT ?,?,?,?,?,? WHERE ${won.clause}`,appId,r.role,r.level,revision,s.person_id,now,...won.args)),
 ]);
 // A changed hierarchy invalidates old caps, so reconcile downstream accounts
 // against the resulting fail-closed local assignment as well.
 const capped=await all(ctx,'SELECT person_id FROM auth_app_reductions WHERE app_id=?',appId);
 if(capped.length)await queue(ctx,appId,capped.map(r=>['person',r.person_id]),'review_role_order_changed');
 return json({ok:true,appId,revision,roles:ordered});
}

export async function clearReductionAction(ctx,request,data) {
 const appId=String(data.appId??''),personId=String(data.personId??''),{s,g}=await adminWrite(ctx,request,appId);
 const cap=await one(ctx,'SELECT * FROM auth_app_reductions WHERE app_id=? AND person_id=?',appId,personId)??fail('review_reduction_not_found',404);
 const reason=String(data.reason??'').trim();if(!reason||reason.length>500)fail('decision_reason_required');
 if(personId===s.person_id)fail('self_approval_refused',403);
 await commit(ctx,s,g,'reviews.reduction.cleared',personId,{appId,personId,reason,cap},(won,p)=>[
  p(`DELETE FROM auth_app_reductions WHERE app_id=? AND person_id=? AND ${won.clause}`,appId,personId,...won.args),
 ]);
 await queue(ctx,appId,[['person',personId]],'review_reduction_cleared');
 return json({ok:true});
}

// This wraps an existing grant; a cap never creates access. No published order
// is needed for ordinary, uncapped assignments. A stale or unknown cap denies.
export async function effectiveRole(ctx,appId,personId,current) {
 if(!current)return null;
 const cap=await one(ctx,'SELECT role,order_revision FROM auth_app_reductions WHERE app_id=? AND person_id=?',appId,personId);
 if(!cap)return current;
 const order=await getRoleOrder(ctx,appId),levels=new Map(order.roles.map(r=>[r.role,r.level]));
 if(order.revision!==cap.order_revision||!levels.has(current.role)||!levels.has(cap.role))return null;
 return {...current,role:levels.get(current.role)<=levels.get(cap.role)?current.role:cap.role};
}

export async function validateReduction(ctx,item,newRole) {
 if(!validRole(newRole))fail('invalid_reduction_role');
 const current=await assignment(ctx,item.app_id,item.subject_id);
 if(!current)fail('review_access_changed',409);
 const order=await getRoleOrder(ctx,item.app_id),levels=new Map(order.roles.map(r=>[r.role,r.level]));
 if(!order.revision||!levels.has(current.role)||!levels.has(newRole))fail('published_role_order_required',409);
 if(newRole===current.role||levels.get(newRole)>=levels.get(current.role))fail('review_role_must_be_lower');
 return {newRole,currentRole:current.role,orderRevision:order.revision};
}

export function reductionStatements(ctx,item,newRole,operationId,won,p) {
 const revision=item.reduction?.orderRevision;
 if(!revision||item.reduction.newRole!==newRole)fail('review_reduction_snapshot_required',409);
 return [p(`INSERT INTO auth_app_reductions(app_id,person_id,role,order_revision,operation_id,created_at)
  SELECT ?,?,?,?,?,? WHERE ${won.clause}
  AND EXISTS(SELECT 1 FROM auth_app_role_order WHERE app_id=? AND role=? AND revision=?)
  ON CONFLICT(app_id,person_id) DO UPDATE SET role=excluded.role,order_revision=excluded.order_revision,operation_id=excluded.operation_id,created_at=excluded.created_at`,
  item.app_id,item.subject_id,newRole,revision,operationId,ctx.now(),...won.args,item.app_id,newRole,revision)];
}
