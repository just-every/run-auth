import {random,fail} from '../core.mjs';
import {requireAuthority} from '../local-email.mjs';
export async function factorCommit(ctx,s,guard,kind,statements) {
 const id=random(),q=(sql,...args)=>ctx.db.prepare(sql).bind(...args),held='EXISTS(SELECT 1 FROM auth_factor_operations WHERE id=?)';
 // A transaction receipt lets later statements revoke the acting session
 // without turning the remaining writes into silent no-ops.
 const prepared=(sql,...args)=>q(sql,...args,id);
 const [inserted]=await ctx.db.batch([
  q(`INSERT INTO auth_factor_operations(id,person_id,session_id,kind,created_at) SELECT ?,?,?,?,? WHERE ${guard.clause}`,id,s.person_id,s.id,kind,ctx.now(),...guard.args),
  ...statements(prepared,held),
  q(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT person_id,kind,id,created_at FROM auth_factor_operations WHERE id=?`,id),
 ]);
 if(!inserted.meta.changes){await requireAuthority(ctx,s,guard);fail('factor_changed',409);}
 return id;
}
export function endSessions(ctx,s,q,held) {
 return [q(`UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE person_id=? AND ${held}`,ctx.now(),s.person_id)];
}
