import {one,fail} from '../core.mjs';

export async function submissionTarget(ctx,s,{targetId,operation,reason,role,durationMs}) {
 if(operation!=='request')fail('invalid_request_decision');
 const policy=await one(ctx,'SELECT p.*,a.disabled_at FROM auth_request_policies p JOIN auth_apps a ON a.id=p.app_id WHERE app_id=?',targetId)??fail('request_policy_required',403);
 if(policy.disabled_at!==null)fail('app_unavailable',403);
 if(policy.decider_id===s.person_id)fail('self_approval_refused',403);
 const duration=Number(durationMs),requestedRole=role==null||role===''?null:String(role).trim();
 if(requestedRole?.length>80)fail('invalid_request_role');
 if(!Number.isSafeInteger(duration)||duration<60000||duration>policy.max_duration_ms)fail('invalid_request_duration');
 if(await one(ctx,"SELECT 1 FROM auth_access_requests WHERE app_id=? AND person_id=? AND (state='pending' OR (state='approved' AND (expires_at IS NULL OR expires_at>?)))",targetId,s.person_id,ctx.now()))fail('request_state_changed',409);
 const person=await one(ctx,"SELECT id,version FROM oa_operators WHERE id=? AND status='active'",s.person_id)??fail('requester_unavailable',403);
 return {snapshot:{policy,person,purpose:reason,role:requestedRole,durationMs:duration},role:requestedRole,durationMs:duration,personId:s.person_id};
}
export function submissionStatements(ctx,s,target,id,won,p) {
 const {policy,role,purpose,durationMs}=target.snapshot;
 return [p(`INSERT INTO auth_access_requests(id,app_id,person_id,role,purpose,duration_ms,decider_id,policy_revision,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${won.clause}`,id,policy.app_id,s.person_id,role,purpose,durationMs,policy.decider_id,policy.revision,ctx.now(),...won.args)];
}
