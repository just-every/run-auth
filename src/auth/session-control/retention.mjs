// Keep anonymous delivery totals with the longer-lived operation receipt. The
// caller uses the deletion's exact eligibility and snapshot guard, in its batch.
export function retainLogoutOutcomes(ctx,entry,condition,args) {
 if(!['auth_logout_deliveries','auth_oidc_logouts'].includes(entry.table))return [];
 return [ctx.db.prepare(`WITH expiring AS (
  SELECT substr(t.id,1,instr(t.id,':')-1) AS operation_id,t.outcome
  FROM ${entry.table} t WHERE ${condition}
 ), totals AS (
  SELECT operation_id,sum(CASE WHEN outcome='delivered' THEN 1 ELSE 0 END) AS delivered,
   sum(CASE WHEN outcome='delivered' THEN 0 ELSE 1 END) AS failed
  FROM expiring GROUP BY operation_id
 ) UPDATE auth_role_operations SET detail=json_set(detail,
  '$.retainedLogout.delivered',COALESCE(json_extract(detail,'$.retainedLogout.delivered'),0)+(SELECT delivered FROM totals WHERE operation_id=auth_role_operations.id),
  '$.retainedLogout.failed',COALESCE(json_extract(detail,'$.retainedLogout.failed'),0)+(SELECT failed FROM totals WHERE operation_id=auth_role_operations.id))
 WHERE permission='roles.sessions.end' AND id IN (SELECT operation_id FROM totals)`).bind(...args)];
}
