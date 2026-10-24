import {all,one,hash} from '../core.mjs';
import {policy} from '../obligations/policy.mjs';
import {businessDue,deliveryWindow} from '../obligations/calendar.mjs';
import {itemDrift} from './snapshot.mjs';

const sourceSql=`SELECT i.*,r.status AS review_status,r.created_at,r.due_at
 FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id
 WHERE i.id=? AND i.decision IS NULL AND r.status='open'`;
const sourceKey=row=>JSON.stringify(row);
const sourceGuard=`EXISTS(SELECT 1 FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id
 WHERE i.id=? AND i.review_id=? AND i.reviewer_id=? AND i.subject_id=? AND i.snapshot=?
 AND i.decision IS NULL AND r.status='open' AND r.created_at=? AND r.due_at=?)`;
const sourceArgs=i=>[i.id,i.review_id,i.reviewer_id,i.subject_id,i.snapshot,i.created_at,i.due_at];
const policyGuard='EXISTS(SELECT 1 FROM auth_followup_settings WHERE id=1 AND policy=?)';
const epochGuard='EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)';
const activeAdmin=p=>p?.status==='active'&&['owner','admin'].includes(p.role);
const person=(ctx,id)=>one(ctx,'SELECT id,email,role,status,version FROM oa_operators WHERE id=?',id);

async function consent(ctx) {
 const settings=await policy(ctx);
 if(!settings.enabled)return null;
 const row=await one(ctx,'SELECT policy FROM auth_followup_settings WHERE id=1');
 // No settings row is never consent. Keep the precise saved bytes in every
 // committing guard so a concurrent policy edit invalidates this occurrence.
 if(!row||!JSON.parse(row.policy).enabled)return null;
 return {settings:JSON.parse(row.policy),raw:row.policy};
}
async function current(ctx,item,approved) {
 const epoch=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 const [source,saved]=await Promise.all([one(ctx,sourceSql,item.id),consent(ctx)]);
 if(!source||sourceKey(source)!==sourceKey(item)||saved?.raw!==approved.raw)return null;
 return {epoch:epoch.epoch};
}
async function update(ctx,id,event,detail) {
 // Outcome appends are immutable too: an in-flight mail response must never
 // change a row an erasure journal already committed to.
 await ctx.db.prepare('INSERT OR IGNORE INTO auth_review_events(id,review_id,item_id,event,detail,created_at) SELECT ?,review_id,item_id,?,?,? FROM auth_review_events WHERE id=?')
  .bind(id+':outcome',event,JSON.stringify(detail),ctx.now(),id).run();
}

async function dispatch(ctx,item,approved,slot,recipientId,kind,earlyCurrent) {
 if(earlyCurrent&&!await earlyCurrent())return 'stopped';
 const live=await current(ctx,item,approved);if(!live)return 'stopped';
 const {settings}=approved,target=await person(ctx,recipientId),escalation=kind!=='reminder';
 const eligible=escalation?settings.escalationRecipients.includes(recipientId)&&activeAdmin(target):
  settings.recipients.includes('decider')&&target?.status==='active'&&target.id===item.reviewer_id&&target.id!==item.subject_id&&!await itemDrift(ctx,item);
 if(!eligible)return 'unavailable';
 const id='review-dispatch:'+await hash(JSON.stringify([item.review_id,item.id,slot.scheduledDue,recipientId]));
 const detail={scheduledDue:slot.scheduledDue,recipientId,kind,attemptedAt:ctx.now()};
 const started=await ctx.db.prepare(`INSERT OR IGNORE INTO auth_review_events(id,review_id,item_id,event,detail,created_at)
  SELECT ?,?,?,?,?,? WHERE ${sourceGuard} AND ${policyGuard} AND ${epochGuard}`)
  .bind(id,item.review_id,item.id,escalation?'review_escalation_dispatching':'review_reminder_dispatching',JSON.stringify(detail),ctx.now(),...sourceArgs(item),approved.raw,live.epoch).run();
 if(!started.meta.changes)return 'stopped';
 // The durable per-recipient attempt precedes transport. Its unknown outcome
 // is consumed forever; a Worker restart cannot retry this scheduled slot.
 const again=await current(ctx,item,approved),recipient=await person(ctx,recipientId);
 if(earlyCurrent&&!await earlyCurrent()||!again||again.epoch!==live.epoch||JSON.stringify(recipient)!==JSON.stringify(target)||
  !await one(ctx,`SELECT 1 WHERE ${sourceGuard} AND ${policyGuard} AND ${epochGuard}`,...sourceArgs(item),approved.raw,live.epoch)) {
  await update(ctx,id,'review_dispatch_skipped',{...detail,reason:'authority_or_source_changed'});
  return again?'unavailable':'stopped';
 }
 try {
  if(!ctx.mail)throw new Error('mail_not_configured');
  await ctx.mail({to:recipient.email,
   subject:escalation?(kind==='overdue'?'Auth access review is overdue':'Auth access review reviewer unavailable'):'Auth access review is due',
   text:`An Auth access review item is awaiting a decision. ${escalation?'Reassign or complete the review.':'Review the assigned access.'} Sign in to Auth: ${ctx.origin}${ctx.basePath??''}${['owner','admin'].includes(recipient.role)?'/app/activity':'/app/account'}\nReference: ${item.review_id}\nEmail delivery does not certify or revoke access.`,
   html:'<p>An Auth access review awaits a decision. Sign in to Auth and open Access reviews. Email delivery does not certify or revoke access.</p>'});
  await update(ctx,id,escalation?'review_escalation_accepted':'review_reminder_accepted',{...detail,acceptedAt:ctx.now()});
 } catch {
  await update(ctx,id,'review_delivery_failed',{...detail,reason:'mail_delivery_failed_check_transport'});
 }
 return 'attempted';
}

export async function maintainReviewReminders(ctx,{itemId=null,early=false,earlyCurrent=null}={}) {
 const approved=await consent(ctx);if(!approved)return;
 const p=approved.settings;

 const items=await all(ctx,`SELECT i.*,r.status AS review_status,r.created_at,r.due_at
  FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id
  WHERE i.decision IS NULL AND r.status='open' ORDER BY r.created_at,i.id`);
 for(const item of items) {
  if(itemId&&item.id!==itemId||earlyCurrent&&!await earlyCurrent())continue;
  const obligation=await one(ctx,"SELECT * FROM auth_obligations WHERE kind='app_setup' AND source_id=?",'review-item:'+item.id);
  const calendar=obligation?JSON.parse(obligation.calendar):p.calendar;
  if(obligation?.reminders_stopped_at||!early&&!deliveryWindow(ctx.now(),calendar))continue;
  const last=await one(ctx,"SELECT detail,created_at FROM auth_review_events WHERE item_id=? AND event='review_reminder_occurrence' ORDER BY created_at DESC,id DESC LIMIT 1",item.id);
  const previous=last&&JSON.parse(last.detail);
  if(early&&previous?.scheduledDue>ctx.now())continue;
  if(p.escalation==='stop_at_deadline'&&previous?.kind==='overdue')continue;
  const deadline=Math.min(item.due_at,obligation?.deadline_at??businessDue(item.created_at,p.deadlineBusinessDays,calendar));
  const changed=obligation&&await one(ctx,"SELECT created_at FROM auth_obligation_history WHERE obligation_id=? AND event='schedule_changed' ORDER BY created_at DESC LIMIT 1",obligation.id);
  const scheduledDue=changed&&(!last||changed.created_at>=last.created_at)?obligation.next_due_at:businessDue(last?Math.max(last.created_at,previous.scheduledDue):item.created_at,p.reminderBusinessDays,calendar);
  const overdue=ctx.now()>=deadline;
  // A declared review deadline can fall before the next ordinary reminder.
  if(!early&&ctx.now()<scheduledDue&&(!overdue||last?.created_at>=deadline))continue;
  const reviewer=await person(ctx,item.reviewer_id);
  let kind=overdue?'overdue':reviewer?.status!=='active'||reviewer.id===item.subject_id||await itemDrift(ctx,item)?'reviewer_unavailable':'reminder';
  if(kind==='reminder'&&!p.recipients.includes('decider'))continue;
  const slot={scheduledDue:overdue&&scheduledDue>deadline&&(!last||last.created_at<deadline)?deadline:scheduledDue,kind};
  const live=await current(ctx,item,approved);if(!live)continue;
  const id='review-occurrence:'+await hash(JSON.stringify([item.review_id,item.id,slot.scheduledDue]));
  const claimed=await ctx.db.prepare(`INSERT OR IGNORE INTO auth_review_events(id,review_id,item_id,event,detail,created_at)
   SELECT ?,?,?,'review_reminder_occurrence',?,? WHERE ${sourceGuard} AND ${policyGuard} AND ${epochGuard}`)
   .bind(id,item.review_id,item.id,JSON.stringify(slot),ctx.now(),...sourceArgs(item),approved.raw,live.epoch).run();
  if(!claimed.meta.changes)continue;
  if(kind==='reminder') {
   const result=await dispatch(ctx,item,approved,slot,item.reviewer_id,kind,earlyCurrent);
   if(result!=='unavailable')continue;
   kind='reviewer_unavailable';
  }
  for(const recipientId of p.escalationRecipients) {
   if(await dispatch(ctx,item,approved,slot,recipientId,kind,earlyCurrent)==='stopped')break;
  }
 }
}
