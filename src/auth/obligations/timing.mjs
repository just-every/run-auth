import {all,one,run,random} from '../core.mjs';

export const TIMING_ESCALATE_AFTER=900000;
const LEASE=120000;
// This occurrence is independent of the business reminder schedule. A durable
// history marker closes only the escalation, never the downstream obligation.
const eligible=`o.kind='provisioning' AND o.state='open'
 AND EXISTS(SELECT 1 FROM auth_provisioning p WHERE p.id=o.source_id
  AND p.state IN ('pending','failed','blocked') AND p.event_at+${TIMING_ESCALATE_AFTER}<=?)
 AND EXISTS(SELECT 1 FROM auth_followup_settings s WHERE s.id=1 AND json_extract(s.policy,'$.enabled')=1)
 AND NOT EXISTS(SELECT 1 FROM auth_obligation_history h WHERE h.id='timing:'||o.id)`;

export function dueTiming(ctx) {
 return all(ctx,`SELECT o.*,p.event_at+${TIMING_ESCALATE_AFTER} AS timing_due_at,
  'timing:'||o.source_id AS timing_occurrence
  FROM auth_obligations o JOIN auth_provisioning p ON p.id=o.source_id
  WHERE ${eligible} AND COALESCE(o.claimed_until,0)<=?
  ORDER BY timing_due_at,o.id LIMIT 50`,ctx.now(),ctx.now());
}

export async function claimTiming(ctx,ob) {
 const claim=random(),now=ctx.now();
 const claimed=await run(ctx,`UPDATE auth_obligations AS o SET claim_id=?,claimed_until=?
  WHERE o.id=? AND o.source_id=? AND ${eligible} AND COALESCE(o.claimed_until,0)<=?`,
 claim,now+LEASE,ob.id,ob.source_id,now,now);
 return claimed.meta.changes?claim:null;
}

// Dispatch must also recheck each recipient's live policy and authority. This
// check protects the source and claim immediately before its durable attempt.
export async function timingCurrent(ctx,ob,claim) {
 const now=ctx.now();
 return !!await one(ctx,`SELECT 1 FROM auth_obligations o WHERE o.id=? AND o.source_id=?
  AND o.claim_id=? AND o.claimed_until>? AND ${eligible}`,ob.id,ob.source_id,claim,now,now);
}

// Call after processing the occurrence, including redacted delivery failures.
// Per-recipient attempt IDs must include timing_occurrence, rather than the
// normal next_due_at, so an interrupted transport is never retried on restart.
export async function finishTiming(ctx,ob,claim,error=null) {
 const now=ctx.now();
 const [marked]=await ctx.db.batch([
  ctx.db.prepare(`INSERT OR IGNORE INTO auth_obligation_history(id,obligation_id,event,created_at,error)
   SELECT 'timing:'||o.id,o.id,?,?,? FROM auth_obligations o
   WHERE o.id=? AND o.source_id=? AND o.claim_id=? AND o.claimed_until>? AND ${eligible}`)
   .bind(error?'timing_escalation_failed':'timing_escalated',now,error,ob.id,ob.source_id,claim,now,now),
  ctx.db.prepare(`UPDATE auth_obligations SET claim_id=NULL,claimed_until=NULL,delivery_error=?
   WHERE id=? AND claim_id=?`).bind(error,ob.id,claim),
 ]);
 return !!marked.meta.changes;
}
