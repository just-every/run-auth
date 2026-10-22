import {one,all,requireSession,json,fail} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {privilegedApp} from '../decisions/privilege.mjs';
import {queue} from '../provisioning/obligations.mjs';

export const REQUESTS_READ='/api/auth/requests';
export const isRequestAction=p=>['/requests/policy','/requests/cancel'].includes(p);
export async function requestsRead(ctx,request) {
 const s=await requireSession(ctx,request),admin=['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk');
 return json({requests:await all(ctx,`SELECT r.*,a.name AS app_name,p.display_name AS requester_name,p.email AS requester_email FROM auth_access_requests r JOIN auth_apps a ON a.id=r.app_id JOIN oa_operators p ON p.id=r.person_id ${admin?'':'WHERE r.person_id=? OR r.decider_id=?'} ORDER BY r.created_at DESC,r.id`,...(admin?[]:[s.person_id,s.person_id])),policies:await all(ctx,'SELECT p.app_id,p.max_duration_ms,a.name FROM auth_request_policies p JOIN auth_apps a ON a.id=p.app_id WHERE a.disabled_at IS NULL')});
}
export async function requestAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request),now=ctx.now();
 if(path==='/requests/policy') {
  await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
  const app=await one(ctx,'SELECT id FROM auth_apps WHERE id=? AND disabled_at IS NULL',String(data.appId??''))??fail('app_not_found',404),decider=await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active'",String(data.deciderId??''))??fail('decider_not_found');
  const duration=Number(data.maxDurationMs);if(!Number.isSafeInteger(duration)||duration<60000||duration>30*86400000)fail('invalid_request_duration');
  const g=authority(ctx,s,['owner','admin']),result=await ctx.db.prepare(`INSERT INTO auth_request_policies(app_id,decider_id,max_duration_ms,updated_by,updated_at) SELECT ?,?,?,?,? WHERE ${g.clause} ON CONFLICT(app_id) DO UPDATE SET decider_id=excluded.decider_id,max_duration_ms=excluded.max_duration_ms,updated_by=excluded.updated_by,updated_at=excluded.updated_at,revision=auth_request_policies.revision+1`).bind(app.id,decider.id,duration,s.person_id,now,...g.args).run();
  if(!result.meta.changes)fail('session_authority_changed',403);return json({ok:true});
 }
 if(!JSON.parse(s.amr).some(m=>['hwk','passkey'].includes(m)))fail('employee_passkey_required',403);
 const result=await ctx.db.prepare("UPDATE auth_access_requests SET state='cancelled',reason='cancelled_by_requester' WHERE id=? AND person_id=? AND state='pending'").bind(String(data.id??''),s.person_id).run();
 if(!result.meta.changes)fail('pending_request_not_found',404);return json({ok:true});
}

export async function requestTarget(ctx,s,{targetId,operation}) {
 if(!['approve','deny'].includes(operation))fail('invalid_request_decision');
 const row=await one(ctx,'SELECT r.*,p.revision AS current_revision,p.decider_id AS current_decider,a.disabled_at FROM auth_access_requests r JOIN auth_request_policies p ON p.app_id=r.app_id JOIN auth_apps a ON a.id=r.app_id WHERE r.id=?',targetId)??fail('request_not_found',404);
 if(row.state!=='pending'||row.policy_revision!==row.current_revision||row.disabled_at!==null)fail('request_state_changed',409);
 if(row.person_id===s.person_id)fail('self_approval_refused',403);
 if(row.decider_id!==s.person_id||row.current_decider!==s.person_id)fail('request_decider_required',403);
 const person=await one(ctx,"SELECT id,version FROM oa_operators WHERE id=? AND status='active'",row.person_id)??fail('requester_unavailable',403);
 const existing=await one(ctx,"SELECT * FROM auth_app_assignments WHERE app_id=? AND principal_type='person' AND principal_id=?",row.app_id,row.person_id);
 // A temporary request may not overwrite a standing assignment.
 if(operation==='approve'&&existing)fail('existing_access_requires_review',409);
 const privileged=await privilegedApp(ctx,row.app_id,row.role);
 return {snapshot:{request:row,person,existing},personId:row.person_id,privileged};
}
export function requestStatements(ctx,s,target,operationId,won,p) {
 const row=target.snapshot.request,now=ctx.now();
 return [p(`UPDATE auth_access_requests SET state=?,decided_by=?,decided_at=?,reason=?,operation_id=?,expires_at=? WHERE id=? AND state='pending' AND ${won.clause}`,target.operation==='approve'?'approved':'denied',s.person_id,now,target.reason,operationId,target.operation==='approve'?now+row.duration_ms:null,row.id,...won.args),
 ...(target.operation==='approve'?[
  p(`INSERT INTO auth_app_assignments(app_id,principal_type,principal_id,role,created_by,created_at) SELECT ?,'person',?,?,?,? WHERE ${won.clause}`,row.app_id,row.person_id,row.role,s.person_id,now,...won.args),
  p(`DELETE FROM auth_app_denials WHERE app_id=? AND person_id=? AND ${won.clause}`,row.app_id,row.person_id,...won.args),
 ]:[])];
}
export async function finishRequest(ctx,id) {
 const row=await one(ctx,"SELECT * FROM auth_access_requests WHERE id=? AND state='approved'",id);if(row)await queue(ctx,row.app_id,[['person',row.person_id]],'request_approved');
}
export async function maintainRequests(ctx) {
 for(const row of await all(ctx,"SELECT * FROM auth_access_requests WHERE state='approved' AND expires_at<=?",ctx.now())) {
  // Only remove the exact temporary assignment this approval created. A later
  // independent administrator change is retained as an explicit exception.
  const results=await ctx.db.batch([
   ctx.db.prepare("UPDATE auth_access_requests SET state='revocation_pending',expired_at=? WHERE id=? AND state='approved'").bind(ctx.now(),row.id),
   ctx.db.prepare("DELETE FROM auth_app_assignments WHERE app_id=? AND principal_type='person' AND principal_id=? AND created_by=? AND created_at=? AND role IS ? AND EXISTS(SELECT 1 FROM auth_access_requests WHERE id=? AND state='revocation_pending')").bind(row.app_id,row.person_id,row.decided_by,row.decided_at,row.role,row.id),
  ]);
  if(results[0].meta.changes)await queue(ctx,row.app_id,[['person',row.person_id]],'request_expired');
 }
 for(const row of await all(ctx,"SELECT * FROM auth_access_requests WHERE state='revocation_pending'")) {
  const remaining=await one(ctx,"SELECT 1 FROM auth_app_assignments a LEFT JOIN auth_group_members m ON a.principal_type='group' AND a.principal_id=m.group_id WHERE a.app_id=? AND ((a.principal_type='person' AND a.principal_id=?) OR m.person_id=?)",row.app_id,row.person_id,row.person_id);
  const verified=await one(ctx,"SELECT 1 FROM auth_provisioning p JOIN auth_scim_accounts a ON a.app_id=p.app_id AND a.subject_type='person' AND a.subject_id=p.subject_id WHERE p.app_id=? AND p.subject_id=? AND p.reason='request_expired' AND p.state='verified' AND a.state IN ('inactive','deleted')",row.app_id,row.person_id);
  if(!remaining&&verified)await ctx.db.prepare("UPDATE auth_access_requests SET state='expired_verified' WHERE id=? AND state='revocation_pending'").bind(row.id).run();
 }
}
