// Terminal delivery counts belong to the accountable receipt, whose retention
// period is independent of the transient delivery queue. The unfinished-row
// guard and the queue transition share one transaction, so retries or competing
// workers cannot count the same terminal result twice.
export async function recordLogoutAttempt(ctx,table,delivery,{attempts,next,finishedAt,outcome}) {
 if(!['auth_logout_deliveries','auth_oidc_logouts'].includes(table))throw new Error('unknown_logout_queue');
 const update=ctx.db.prepare(`UPDATE ${table} SET attempts=?,next_attempt_at=?,finished_at=?,outcome=? WHERE id=? AND finished_at IS NULL`).bind(attempts,next,finishedAt,outcome,delivery.id);
 if(finishedAt===null){await update.run();return;}
 const operationId=delivery.id.split(':')[0],delivered=outcome==='delivered'?1:0;
 await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_role_operations SET detail=json_set(detail,
   '$.logoutOutcomes.delivered',json_extract(detail,'$.logoutOutcomes.delivered')+?,
   '$.logoutOutcomes.failed',json_extract(detail,'$.logoutOutcomes.failed')+?)
   WHERE id=? AND permission='roles.sessions.end' AND json_type(detail,'$.logoutOutcomes')='object'
    AND EXISTS(SELECT 1 FROM ${table} WHERE id=? AND finished_at IS NULL)`)
   .bind(delivered,1-delivered,operationId,delivery.id),
  update,
 ]);
}
