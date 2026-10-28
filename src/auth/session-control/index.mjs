import {all,fail,json,one,random,requireSession} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {assertPermission,permitted,requireHardware,requireRolePermission} from '../roles/policy.mjs';
import {commit} from '../roles/commit.mjs';
import {deliverLogouts} from '../links/logout.mjs';
import {deliverGenericLogouts} from '../oidc-apps/session.mjs';
import {endSessionStatements} from './statements.mjs';

const PERMISSION='people.sessions.end';
async function deliverySummary(ctx,operationId,unavailable=0) {
 // Read live and retained totals in one snapshot so concurrent expiry cannot
 // omit or count the same outcome twice.
 const prefix=operationId+':%',rows=await all(ctx,`SELECT finished_at,outcome,1 AS amount FROM auth_logout_deliveries WHERE id LIKE ?
  UNION ALL SELECT finished_at,outcome,1 FROM auth_oidc_logouts WHERE id LIKE ?
  UNION ALL SELECT 1,'delivered',COALESCE(json_extract(detail,'$.retainedLogout.delivered'),0) FROM auth_role_operations WHERE id=?
  UNION ALL SELECT 1,'failed',COALESCE(json_extract(detail,'$.retainedLogout.failed'),0) FROM auth_role_operations WHERE id=?`,prefix,prefix,operationId,operationId);
 const summary={pending:0,delivered:0,failed:0,unavailable};
 for(const row of rows)summary[row.finished_at===null?'pending':row.outcome==='delivered'?'delivered':'failed']+=row.amount;
 return summary;
}
async function operationView(ctx,row) {
 const detail=JSON.parse(row.detail);
 return {id:row.id,actorId:row.actor_id,reason:detail.reason,createdAt:row.created_at,
  nativeSessionsEnded:detail.nativeSessionsEnded,refreshGrantsEnded:detail.refreshGrantsEnded,
  logout:await deliverySummary(ctx,row.id,detail.unavailable)};
}
async function assertRead(ctx,s,state) {
 if(!await one(ctx,`SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1
  WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?`,s.id,s.person_id,s.amr,ctx.now(),state.epoch))fail('role_authority_changed',409);
}
export async function sessionControlModel(ctx,s,personIds=null) {
 requireHardware(s);
 const state=await roleState(ctx,s);
 if(personIds===null)assertPermission(state,PERMISSION,{write:true});
 const ids=(personIds??[...state.dir.people.keys()]).filter(personId=>permitted(state,PERMISSION,{personId,write:true}));
 const people=[];
 // Bound both SQL bindings and per-person history. Empty inventories do not
 // incur one query for every employee on the directory page.
 for(let offset=0;offset<ids.length;offset+=50) {
  const selected=ids.slice(offset,offset+50),rows=await all(ctx,`SELECT * FROM (
   SELECT *,row_number() OVER (PARTITION BY subject_id ORDER BY created_at DESC,id DESC) AS ordinal
   FROM auth_role_operations WHERE permission='roles.sessions.end' AND subject_id IN (${selected.map(()=>'?').join(',')})
  ) WHERE ordinal<=20 ORDER BY created_at DESC,id DESC`,...selected);
  for(const personId of selected)people.push({personId,operations:await Promise.all(rows.filter(row=>row.subject_id===personId).map(row=>operationView(ctx,row)))});
 }
 await assertRead(ctx,s,state);
 return {people};
}
export async function sessionControlRead(ctx,request) {
 const s=await requireSession(ctx,request),personId=new URL(request.url).searchParams.get('personId');
 if(!personId)fail('person_required');
 requireHardware(s);
 const state=await roleState(ctx,s);assertPermission(state,PERMISSION,{personId,write:true});
 const model=await sessionControlModel(ctx,s,[personId]);
 // The first snapshot authorized the requested person, not merely the endpoint.
 await assertRead(ctx,s,state);
 return json({operations:model.people[0]?.operations??[]});
}
export async function endPersonSessions(ctx,s,data) {
 const personId=String(data.personId??'').trim();
 if(!personId)fail('person_required');
 const guard=await requireRolePermission(ctx,s,PERMISSION,{personId,write:true});
 const reason=String(data.reason??'').trim();
 if(!reason||reason.length>500||/[\r\n]/.test(reason))fail('session_end_reason_required');
 const operationId=random();
 await commit(ctx,s,guard,'roles.sessions.end',personId,{reason,trigger:'help_desk',retained:['active_state','factors','assignments']},
  (g,q)=>endSessionStatements(ctx,personId,operationId,g,q),operationId);
 const linked=await all(ctx,'SELECT id FROM auth_logout_deliveries WHERE id LIKE ?',operationId+':%');
 const generic=await all(ctx,'SELECT id FROM auth_oidc_logouts WHERE id LIKE ?',operationId+':%');
 const work=Promise.all([
  ...(linked.length?[deliverLogouts(ctx,linked.slice(0,50).map(row=>row.id))]:[]),
  ...(generic.length?[deliverGenericLogouts(ctx,generic.slice(0,50).map(row=>row.id))]:[]),
 ]);
 if(ctx.waitUntil)ctx.waitUntil(work);else await work;
 const row=await one(ctx,'SELECT * FROM auth_role_operations WHERE id=?',operationId),view=await operationView(ctx,row);
 return json({ok:true,operationId,nativeSessionsEnded:view.nativeSessionsEnded,refreshGrantsEnded:view.refreshGrantsEnded,logout:view.logout});
}
