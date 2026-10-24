import {all,one} from '../core.mjs';
import {itemDrift} from '../reviews/snapshot.mjs';
import {businessDue} from './calendar.mjs';

// These reserved source prefixes are created only by the obligation engine.
// Existing employer namespaces keep their installed schema and history.
export const decisionKind=ob=>ob.kind==='app_setup'?(ob.source_id.startsWith('access-request:')?'access_request':ob.source_id.startsWith('review-item:')?'review_item':null):null;
export const reviewSourceId=ob=>ob.source_id.slice(ob.source_id.indexOf(':')+1);
export async function decisionCandidates(ctx) {
 return all(ctx,`SELECT 'app_setup' AS kind,'access-request:'||id AS source_id,decider_id AS owner_id,person_id,app_id,created_at FROM auth_access_requests WHERE state='pending'
 UNION ALL SELECT 'app_setup','review-item:'||i.id,i.reviewer_id,i.subject_id,i.app_id,r.created_at FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id WHERE r.status='open' AND i.decision IS NULL`);
}
export async function decisionSource(ctx,ob) {
 const kind=decisionKind(ob);if(!kind)return null;
 if(kind==='access_request') {
  const row=await one(ctx,'SELECT r.*,p.decider_id AS current_decider,p.revision AS current_revision,a.id AS current_app,a.disabled_at FROM auth_access_requests r LEFT JOIN auth_request_policies p ON p.app_id=r.app_id LEFT JOIN auth_apps a ON a.id=r.app_id WHERE r.id=?',reviewSourceId(ob));
  if(!row||row.state==='cancelled')return {state:'cancelled'};
  if(row.state!=='pending')return {state:'completed'};
  if(!row.current_app||row.policy_revision!==row.current_revision||row.decider_id!==row.current_decider||row.disabled_at!==null)return {state:'expired',error:'request_authority_changed'};
  return {state:'open',action:'decide_access_request',deciderId:row.decider_id,personId:row.person_id};
 }
 const item=await one(ctx,'SELECT i.*,r.status,r.due_at FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id WHERE i.id=?',reviewSourceId(ob));
 if(!item)return {state:'cancelled'};
 if(item.decision||item.status!=='open')return {state:'completed'};
 return {state:'open',action:'decide_access_review_item',deciderId:item.reviewer_id,deadlineAt:item.due_at};
}
export async function decisionHolder(ctx,ob,id) {
 const source=await decisionSource(ctx,ob);
 if(source?.state!=='open'||source.deciderId!==id||!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active'",id))return false;
 if(decisionKind(ob)==='access_request')return source.personId!==id&&Boolean(await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active'",source.personId));
 const item=await one(ctx,'SELECT * FROM auth_review_items WHERE id=?',reviewSourceId(ob));
 return item.subject_id!==id&&!await itemDrift(ctx,item);
}
export async function syncReviewHistory(ctx,ob,p) {
 if(decisionKind(ob)!=='review_item')return;
 const id=reviewSourceId(ob);
 // Preserve the qualified review scheduler's source and dispatch guards while
 // exposing its durable attempts through the common follow-up ledger.
 await ctx.db.prepare(`INSERT OR IGNORE INTO auth_obligation_history(id,obligation_id,event,recipient_id,created_at)
 SELECT 'followup:'||id,?,event,(SELECT id FROM oa_operators WHERE id=json_extract(detail,'$.recipientId')),created_at FROM auth_review_events WHERE item_id=? AND event LIKE 'review_%'`).bind(ob.id,id).run();
 const last=await one(ctx,"SELECT created_at,detail FROM auth_review_events WHERE item_id=? AND event='review_reminder_occurrence' ORDER BY created_at DESC,id DESC LIMIT 1",id);
 const changed=await one(ctx,"SELECT created_at FROM auth_obligation_history WHERE obligation_id=? AND event='schedule_changed' ORDER BY created_at DESC LIMIT 1",ob.id);
 if(last&&(!changed||changed.created_at<last.created_at))await ctx.db.prepare("UPDATE auth_obligations SET next_due_at=?,reminders_stopped_at=? WHERE id=? AND state='open'").bind(businessDue(Math.max(last.created_at,JSON.parse(last.detail).scheduledDue),p.reminderBusinessDays,JSON.parse(ob.calendar)),p.escalation==='stop_at_deadline'&&last.created_at>=ob.deadline_at?last.created_at:null,ob.id).run();
}
