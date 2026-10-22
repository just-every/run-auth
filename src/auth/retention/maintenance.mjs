import {expiryStatements} from './expiry.mjs';
import {one,random} from '../core.mjs';
import {retentionPolicy,PREVIEW_WINDOW} from './policy.mjs';
import {CATALOG,tableQuote,entryId} from './catalog.mjs';
import {retentionPlan,eligibility,matchSnapshot,snapshotColumns} from './plan.mjs';
export async function queueRetention(ctx,policy=undefined,guard=null) {
 policy??=await retentionPolicy(ctx);
 const existing=await one(ctx,"SELECT * FROM auth_retention_runs WHERE status='queued'");if(existing)return existing;
 const plan=await retentionPlan(ctx,policy);if(!plan.total)return null;
 const id=random();
 await ctx.db.prepare(`INSERT OR IGNORE INTO auth_retention_runs(id,status,policy_revision,created_at,delete_after,plan,summary) SELECT ?,'queued',?,?,?,?,? WHERE COALESCE((SELECT revision FROM auth_retention_policy WHERE id=1),0)=? AND ${guard?guard.clause:'1'}`).bind(id,policy.revision,ctx.now(),ctx.now()+PREVIEW_WINDOW,JSON.stringify(plan.entries),JSON.stringify(plan.summary),policy.revision,...(guard?.args??[])).run();
 return one(ctx,"SELECT * FROM auth_retention_runs WHERE status='queued'");
}
export async function maintainRetention(ctx) {
 const policy=await retentionPolicy(ctx),pending=await one(ctx,"SELECT * FROM auth_retention_runs WHERE status='queued'");
 if(!pending){await queueRetention(ctx,policy);return;}
 if(pending.policy_revision!==policy.revision) {
  await ctx.db.prepare("UPDATE auth_retention_runs SET status='cancelled',completed_at=?,plan=NULL WHERE id=? AND status='queued'").bind(ctx.now(),pending.id).run();
  await queueRetention(ctx,policy);return;
 }
 if(pending.delete_after>ctx.now())return;
 const claim=random(),latch="EXISTS(SELECT 1 FROM auth_retention_runs WHERE id=? AND status='queued' AND claim_id=?)";
 const statements=[ctx.db.prepare("UPDATE auth_retention_runs SET claim_id=? WHERE id=? AND status='queued' AND delete_after<=? AND COALESCE((SELECT revision FROM auth_retention_policy WHERE id=1),0)=?").bind(claim,pending.id,ctx.now(),policy.revision)];
 for(const planned of JSON.parse(pending.plan)) {
  const known=CATALOG.find(e=>entryId(e)===planned.id);if(!known)throw new Error('unknown_retention_plan_store');
  const entry={...known,snapshotColumns:await snapshotColumns(ctx,known)},match=matchSnapshot(entry),table=tableQuote(entry.table);
  // The policy is applied as of the preview, so later aging never silently
  // widens this exact candidate set. Holds and unfinished work are live reads.
  const condition=`${latch} AND ${eligibility(entry,policy,pending.created_at)} AND ${match}`;
  const json=JSON.stringify(planned.records);
  if(entry.operation==='anonymize') {
   const identity=entry.key.map(c=>`t.${tableQuote(c)} IS json_extract(candidate.value,'$.row.${c}')`).join(' AND ');
   statements.push(ctx.db.prepare(`UPDATE ${table} AS t SET email=(SELECT json_extract(candidate.value,'$.expiredEmail') FROM json_each(?) candidate WHERE ${identity}),display_name='Expired profile' WHERE ${condition}`).bind(json,pending.id,claim,json));
  }else {
   statements.push(...await expiryStatements(ctx,entry,planned,condition,[pending.id,claim,json],pending.id));
   statements.push(ctx.db.prepare(`DELETE FROM ${table} AS t WHERE ${condition}`).bind(pending.id,claim,json));
  }
  statements.push(ctx.db.prepare(`UPDATE auth_retention_runs SET result=json_set(result,?,changes()) WHERE id=? AND status='queued' AND claim_id=?`).bind('$.'+entryId(entry),pending.id,claim));
 }
 statements.push(ctx.db.prepare("UPDATE auth_retention_runs SET status='completed',completed_at=?,plan=NULL WHERE id=? AND status='queued' AND claim_id=?").bind(ctx.now(),pending.id,claim));
 statements.push(ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT NULL,'retention_cleanup_completed',?,? WHERE EXISTS(SELECT 1 FROM auth_retention_runs WHERE id=? AND status='completed' AND claim_id=?)").bind(pending.id,ctx.now(),pending.id,claim));
 await ctx.db.batch(statements);
 // The run's anonymous per-store counts commit with deletion, even when a
 // Worker dies before returning. A competing invocation cannot claim it twice.
}
