import {run,json,fail,auditDetail,requireSession} from '../../core.mjs';
import {browserData,exact,id,personSessionGuard,ownerSession,ownerGuard,both} from './common.mjs';
import {taskRow,employerGuard,held} from './state.mjs';

export async function revokeDelegation(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['grantId']);
 const s=await requireSession(ctx,request),task=await taskRow(ctx,id(data.grantId))||fail('delegation_not_found',404);
 let guard;
 if(task.accountable_id===s.person_id)guard=personSessionGuard(ctx,s);
 else {const owner=await ownerSession(ctx,request);guard=ownerGuard(ctx,owner);}
 guard=both(guard,employerGuard(ctx));
 const result=await run(ctx,`UPDATE auth_delegated_tasks SET state='revoked',revoked_at=?,revoked_by=?,ended_reason='explicit_revocation',revision=revision+1 WHERE id=? AND state IN ('requested','consented','approved') AND ${guard.clause}`,ctx.now(),s.person_id,task.id,...guard.args);
 if(!result.meta.changes){await held(ctx,guard);fail('delegation_already_ended',409);}
 await auditDetail(ctx,s.person_id,'delegation_revoked',task.id,{accountablePersonId:task.accountable_id,effectDigest:task.effect_digest});
 return json({grantId:task.id,state:'revoked',localAuthorityEnded:true,completedAssignmentsUndone:false});
}
