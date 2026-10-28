import {all,one,run,random,hash} from '../core.mjs';
import {notificationPolicy} from './policy.mjs';
import {notificationContext,notificationMessage} from './messages.mjs';
import {reportToken} from './tokens.mjs';

// The existing positive administrator rank classifies both built-in and custom
// grants. The operation marker, grant and intent share the same guarded batch.
export function roleNoticeIntent(ctx,plan,operationId,guard,prepare) {
 if(plan.kind!=='grant'||plan.role.rank<=0)return [];
 return [prepare(`INSERT INTO auth_security_notice_intents(id,person_id,grant_id,recipient_email,context,created_at,state)
 SELECT ?,p.id,?,CASE WHEN e.person_id IS NOT NULL THEN p.email END,?,?,'pending'
 FROM oa_operators p LEFT JOIN auth_emails e ON e.person_id=p.id AND e.proof_kind='work'
 WHERE p.id=? AND ${guard.clause} AND EXISTS(SELECT 1 FROM auth_role_grants WHERE id=?)`,
 operationId,plan.id,JSON.stringify(notificationContext(ctx,{factor:plan.role.name})),ctx.now(),plan.personId,...guard.args,plan.id)];
}

export async function deliverNoticeIntent(ctx,id) {
 const intent=await one(ctx,"SELECT * FROM auth_security_notice_intents WHERE id=? AND (state='pending' OR (state='blocked' AND last_error='notification_channel_setup_required'))",id);
 if(!intent)return;
 const policy=await notificationPolicy(ctx);
 if(!policy.emailEnabled) {
  await run(ctx,"UPDATE auth_security_notice_intents SET state='blocked',last_error='notification_channel_setup_required' WHERE id=? AND state IN ('pending','blocked')",id);return;
 }
 const live=await one(ctx,"SELECT p.id FROM oa_operators p JOIN auth_emails e ON e.person_id=p.id AND e.proof_kind='work' WHERE p.id=? AND p.email=? AND p.status='active'",intent.person_id,intent.recipient_email);
 if(!live) {
  await run(ctx,"UPDATE auth_security_notice_intents SET state='refused',last_error='verified_work_address_changed_or_unavailable' WHERE id=? AND state IN ('pending','blocked')",id);return;
 }
 const nonce=random(),noticeId=random(),expiresAt=ctx.now()+7*86400000,token=await reportToken(ctx,nonce,expiresAt);
 // Persist the token digest and the one attempt together. A second maintainer
 // cannot win, and an interrupted or uncertain attempt is never sent again.
 const results=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_security_notifications(id,person_id,event,source_id,context,token_hash,expires_at,created_at,delivery_state)
   SELECT ?,i.person_id,'administrator_role_granted',i.id,i.context,?,?,?,'dispatching' FROM auth_security_notice_intents i
   JOIN oa_operators p ON p.id=i.person_id JOIN auth_emails e ON e.person_id=p.id AND e.proof_kind='work'
   WHERE i.id=? AND i.state IN ('pending','blocked') AND i.recipient_email=p.email AND p.status='active'
   AND EXISTS(SELECT 1 FROM auth_notification_policy WHERE id=1 AND policy=?)`)
   .bind(noticeId,await hash(nonce),expiresAt,intent.created_at,id,JSON.stringify(policy)),
  ctx.db.prepare(`UPDATE auth_security_notice_intents SET state='dispatching',last_error='security_mail_outcome_unknown',notification_id=?
   WHERE id=? AND state IN ('pending','blocked') AND EXISTS(SELECT 1 FROM auth_security_notifications WHERE id=?)`).bind(noticeId,id,noticeId),
 ]);
 if(!results[1].meta.changes)return;
 // Recheck consent and the bound, still verified work address at dispatch.
 const current=await notificationPolicy(ctx),recipient=await one(ctx,"SELECT p.email FROM oa_operators p JOIN auth_emails e ON e.person_id=p.id AND e.proof_kind='work' WHERE p.id=? AND p.email=? AND p.status='active'",intent.person_id,intent.recipient_email);
 let state='refused',error='notification_consent_or_recipient_changed';
 if(current.emailEnabled&&recipient) {
  try {
   if(!ctx.mail)throw new Error('mail_not_configured');
   const link=`${ctx.origin}${ctx.basePath??''}/api/auth/notifications/report?token=${encodeURIComponent(token)}`;
   const outcome=await ctx.mail({to:recipient.email,...notificationMessage(ctx,{event:'administrator_role_granted',context:intent.context},link)});
   state=outcome?.status&&outcome.status!=='accepted'?'failed':'accepted';error=state==='accepted'?null:'security_mail_not_accepted';
  }catch {state='failed';error='security_mail_failed_or_unknown';}
 }
 await ctx.db.batch([
  ctx.db.prepare("UPDATE auth_security_notice_intents SET state=?,last_error=? WHERE id=? AND state='dispatching'").bind(state,error,id),
  ctx.db.prepare("UPDATE auth_security_notifications SET delivery_state=? WHERE id=? AND delivery_state='dispatching'").bind(state,noticeId),
 ]);
}

export async function maintainNoticeIntents(ctx) {
 for(const intent of await all(ctx,"SELECT id FROM auth_security_notice_intents WHERE state='pending' OR (state='blocked' AND last_error='notification_channel_setup_required') ORDER BY created_at,id LIMIT 50"))await deliverNoticeIntent(ctx,intent.id);
}
