import {random,fail} from '../core.mjs';
import {assertGuard} from './policy.mjs';

// build receives a marker guard valid only after the guarded first statement
// has won, and only used in this atomic D1 batch.
export async function commit(ctx,s,guard,event,subject,detail,build=()=>[],operationId=null) {
 const id=operationId??random(),now=ctx.now(),stored=JSON.stringify(detail);
 const won={clause:'EXISTS(SELECT 1 FROM auth_role_operations WHERE id=?)',args:[id]};
 const prepare=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const results=await ctx.db.batch([
  prepare(`INSERT INTO auth_role_operations(id,actor_id,session_id,permission,subject_id,detail,created_at) SELECT ?,?,?,?,?,?,? WHERE ${guard.clause}`,id,s.person_id,s.id,event,subject,stored,now,...guard.args),
  ...build(won,prepare),
  prepare(`INSERT INTO auth_role_events(operation_id,actor_id,session_id,event,subject_id,detail,created_at) SELECT ?,?,?,?,?,?,? WHERE ${won.clause}`,id,s.person_id,s.id,event,subject,stored,now,...won.args),
  prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,?,?,? WHERE ${won.clause}`,s.person_id,event,subject,now,...won.args),
  prepare(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${won.clause}`,stored,...won.args),
 ]);
 if(!results[0].meta.changes){await assertGuard(ctx,guard);fail('role_state_changed',409);}
 return {operationId:id,results};
}
