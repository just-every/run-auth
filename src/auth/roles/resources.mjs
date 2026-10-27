import {requireRecoveryEmployee} from '../recovery-cases/eligibility.mjs';
import {json,random,fail} from '../core.mjs';
import {requireRolePermission,assertPermission} from './policy.mjs';
import {commit} from './commit.mjs';
import {groupChanged,queueApp} from '../provisioning/obligations.mjs';
import {emit,personSubject} from '../events/store.mjs';

export async function editApp(ctx,s,data) {
 const appId=String(data.appId??''),guard=await requireRolePermission(ctx,s,'apps.edit',{appId,write:true}),app=guard.state.apps.find(a=>a.id===appId);
 if(!app)fail('app_not_found',404);
 if(data.name===undefined&&data.enabled===undefined)fail('invalid_app_edit');
 if(data.enabled!==undefined&&typeof data.enabled!=='boolean')fail('invalid_app_edit');
 const name=data.name===undefined?app.name:String(data.name).trim();
 if(!name||name.length>160)fail('invalid_app_name');
 const disabled=data.enabled===undefined?app.disabled_at:data.enabled?null:ctx.now();
 const {operationId}=await commit(ctx,s,guard,'roles.app.edit',appId,{before:app,after:{name,disabledAt:disabled}},(g,q)=>[
  q(`UPDATE auth_apps SET name=?,disabled_at=?,version=version+1,updated_at=? WHERE id=? AND ${g.clause}`,name,disabled,ctx.now(),appId,...g.args),
 ]);
 await queueApp(ctx,appId,'app_updated');
 return json({ok:true,operationId});
}
export async function editGroup(ctx,s,data) {
 const groupId=String(data.groupId??''),personId=String(data.personId??''),guard=await requireRolePermission(ctx,s,'groups.edit',{groupId,personId,write:true}),{state}=guard;
 const group=state.dir.groups.find(g=>g.id===groupId);
 if(!group)fail('group_not_found',404);
 if(!['add','remove'].includes(data.action))fail('invalid_group_action');
 // The destination group itself must be inside this same holder's edit scope.
 const add=data.action==='add';
 const {operationId}=await commit(ctx,s,guard,'roles.group.'+data.action,groupId,{personId,source:'manual'},(g,q)=>add?[
  q(`DELETE FROM auth_group_exclusions WHERE group_id=? AND person_id=? AND ${g.clause}`,groupId,personId,...g.args),
  q(`INSERT INTO auth_group_members(group_id,person_id,added_by,added_at,source) SELECT ?,?,?,?,'manual' WHERE ${g.clause} ON CONFLICT(group_id,person_id) DO UPDATE SET source='manual',added_by=excluded.added_by,added_at=excluded.added_at`,groupId,personId,s.person_id,ctx.now(),...g.args),
 ]:[
  q(`DELETE FROM auth_group_members WHERE group_id=? AND person_id=? AND ${g.clause}`,groupId,personId,...g.args),
  ...(group.rule?[q(`INSERT INTO auth_group_exclusions(group_id,person_id,reason,set_by,set_at) SELECT ?,?,?,?,? WHERE ${g.clause} ON CONFLICT(group_id,person_id) DO UPDATE SET reason=excluded.reason,set_by=excluded.set_by,set_at=excluded.set_at`,groupId,personId,'Scoped administrator removed membership',s.person_id,ctx.now(),...g.args)]:[]),
 ]);
 await groupChanged(ctx,groupId,[personId],add?'group_member_added':'group_member_removed');
 await emit(ctx,add?'group.member_added':'group.member_removed',await personSubject(ctx,personId),{group:groupId,via:'manual'});
 return json({ok:true,operationId});
}
export async function recoveryCase(ctx,s,data) {
 data={...data,action:data.caseAction??data.action};
 if(data.action==='open') {
  const personId=String(data.personId??''),guard=await requireRolePermission(ctx,s,'cases.open',{personId,write:true}),reason=String(data.reason??'').trim();
  await requireRecoveryEmployee(ctx,guard.state,personId);
  if(!reason||reason.length>500)fail('case_reason_required');
  const id=random();
  const {operationId}=await commit(ctx,s,guard,'roles.case.open',id,{personId,reason},(g,q)=>[
   q(`INSERT INTO auth_role_cases(id,person_id,reason,state,opened_by,created_at,updated_at) SELECT ?,?,?,'open',?,?,? WHERE ${g.clause}`,id,personId,reason,s.person_id,ctx.now(),ctx.now(),...g.args),
  ]);
  return json({ok:true,caseId:id,operationId},201);
 }
 const caseId=String(data.caseId??''),guard=await requireRolePermission(ctx,s,'cases.verify',{caseId,write:true}),review=guard.state.cases.find(c=>c.id===caseId);
 if(!review||review.state==='closed')fail('case_unavailable',404);
 await requireRecoveryEmployee(ctx,guard.state,review.person_id);
 if(review.person_id===s.person_id)fail('distinct_administrator_required',403);
 if(!['verify','close'].includes(data.action))fail('invalid_case_action');
 if(data.action==='verify')assertPermission(guard.state,'recovery.approve',{caseId,write:true});
 if(data.action==='verify')fail('manager_attestation_required',403);
 const verification=review.verification?JSON.parse(review.verification):null;
 const {operationId}=await commit(ctx,s,guard,'roles.case.'+data.action,caseId,{personId:review.person_id,verification},(g,q)=>[
  q(`UPDATE auth_role_cases SET state=?,verification=?,verified_by=?,verified_session_id=?,updated_at=? WHERE id=? AND ${g.clause}`,data.action==='verify'?'verified':'closed',verification?JSON.stringify(verification):null,data.action==='verify'?s.person_id:review.verified_by,data.action==='verify'?s.id:review.verified_session_id,ctx.now(),caseId,...g.args),
 ]);
 return json({ok:true,operationId});
}
