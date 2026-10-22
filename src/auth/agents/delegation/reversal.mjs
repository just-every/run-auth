import {one,json,fail,random,auditDetail} from '../../core.mjs';
import {browserData,exact,id,organization,consentingSession,personSessionGuard,both} from './common.mjs';
import {taskRow,employerGuard,held} from './state.mjs';

export const reversalRow=(ctx,grantId)=>one(ctx,'SELECT * FROM auth_delegation_reversals WHERE grant_id=? AND organization_id=?',grantId,organization(ctx));
export function reversalView(row) {
 if(!row)return null;
 return {id:row.id,state:row.state,createdAt:row.created_at,appId:row.app_id,
  executionId:row.execution_id,completedAt:row.completed_at,before:{role:row.before_role},
  assignmentAtRequest:row.assignment_present?{role:row.assignment_role,createdBy:row.assignment_created_by,createdAt:row.assignment_created_at}:null};
}
export const canRequestReversal=(task,s,request)=>!request&&task.accountable_id===s.person_id&&task.completed_at!==null&&Boolean(task.execution_id)&&JSON.parse(s.amr).includes('hwk');

export async function requestReversal(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['grantId']);
 const s=await consentingSession(ctx,request),task=await taskRow(ctx,id(data.grantId))||fail('delegation_not_found',404);
 ctx.delegationActor={actorId:s.person_id};
 if(task.accountable_id!==s.person_id||task.organization_id!==organization(ctx))fail('delegation_person_refused',403);
 if(task.completed_at===null||!task.execution_id)fail('delegation_not_completed',409);
 const guard=both(personSessionGuard(ctx,s),employerGuard(ctx)),requestId=random(),now=ctx.now();
 // Snapshot the actual assignment in the same statement as the live person and
 // employer checks. No agent, token, task or assignment authority is modified.
 const marker={clause:'EXISTS(SELECT 1 FROM auth_delegation_reversals WHERE id=?)',args:[requestId]};
 const detail=JSON.stringify({agentId:task.agent_id,accountablePersonId:s.person_id,approvedBy:task.approved_by,grantId:task.id,effectDigest:task.effect_digest,executionId:task.execution_id});
 const results=await ctx.db.batch([
  ctx.db.prepare(`INSERT OR IGNORE INTO auth_delegation_reversals(id,grant_id,organization_id,requested_by,app_id,effect_digest,execution_id,completed_at,before_role,assignment_present,assignment_role,assignment_created_by,assignment_created_at,state,created_at)
   SELECT ?,dt.id,dt.organization_id,dt.accountable_id,dt.app_id,dt.effect_digest,dt.execution_id,dt.completed_at,dt.before_role,aa.app_id IS NOT NULL,aa.role,aa.created_by,aa.created_at,'requested',?
   FROM auth_delegated_tasks dt JOIN auth_apps app ON app.id=dt.app_id
   LEFT JOIN auth_app_assignments aa ON aa.app_id=dt.app_id AND aa.principal_type='person' AND aa.principal_id=dt.accountable_id
   WHERE dt.id=? AND dt.accountable_id=? AND dt.organization_id=? AND dt.execution_id=? AND dt.completed_at IS NOT NULL AND ${guard.clause}`).bind(requestId,now,task.id,s.person_id,organization(ctx),task.execution_id,...guard.args),
  ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'delegation_reversal_requested',?,? WHERE ${marker.clause}`).bind(s.person_id,task.id,now,...marker.args),
  ctx.db.prepare(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${marker.clause}`).bind(detail,...marker.args),
 ]);
 if(!results[0].meta.changes)await held(ctx,guard);
 const row=await reversalRow(ctx,task.id)||fail('delegation_reversal_unavailable',409);
 if(!results[0].meta.changes)await auditDetail(ctx,s.person_id,'delegation_reversal_requested',task.id,{...JSON.parse(detail),existingRequest:true});
 return json({grantId:task.id,reversalRequest:reversalView(row),assignmentChanged:false,authorityGranted:false});
}
