import {all,one} from '../core.mjs';
import {agentForTask,taskCurrent} from '../agents/delegation/state.mjs';
export const taskCandidates=ctx=>all(ctx,"SELECT 'delegated_assignment' AS kind,id AS source_id,accountable_id AS owner_id,accountable_id AS person_id,app_id,created_at FROM auth_delegated_tasks");
export async function taskSourceState(ctx,ob) {
 const task=await one(ctx,'SELECT * FROM auth_delegated_tasks WHERE id=?',ob.source_id);
 if(!task||['revoked','rejected'].includes(task.state))return {state:'cancelled'};
 // Native execution and assignment update commit in one guarded D1 batch.
 // This says the native assignment effect completed, not downstream access.
 if(task.state==='completed')return {state:'completed'};
 if(task.expires_at<=ctx.now())return {state:'expired'};
 if(!await taskCurrent(ctx,await agentForTask(ctx,task),task))return {state:'expired',error:'delegated_assignment_authority_ended'};
 return {state:'open',action:{requested:'obtain_accountable_person_passkey_consent',consented:'obtain_independent_administrator_passkey_approval',approved:'await_exact_authorized_assignment_execution'}[task.state],expiresAt:task.expires_at};
}
