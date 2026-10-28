import {one,run,random,all} from '../core.mjs';
import {maintainFamilies,endFamily} from '../tokens/lifecycle.mjs';
import {fencePerson} from '../links/logout.mjs';
import {syncObligations} from '../obligations/sources.mjs';
import {notificationPolicy} from './policy.mjs';
import {notificationSourceId} from './followup.mjs';
import {maintainNoticeIntents} from './intents.mjs';

async function history(ctx,report,event,error=null) {
 const ob=await one(ctx,"SELECT id FROM auth_obligations WHERE kind='app_setup' AND source_id=?",notificationSourceId(report.id));
 if(ob)await run(ctx,'INSERT INTO auth_obligation_history(id,obligation_id,event,recipient_id,created_at,error) VALUES(?,?,?,?,?,?)',random(),ob.id,event,report.owner_id,ctx.now(),error);
}
export async function finishReport(ctx,report) {
 const p=JSON.parse(report.policy),notice=await one(ctx,'SELECT person_id FROM auth_security_notifications WHERE id=?',report.notification_id);
 if(p.endSessionsOnReport&&notice?.person_id&&report.sessions_state!=='ended') {
  // The sessions were revoked in the same transaction as report consumption.
  // Queued back-channel deliveries and refresh revocations retain their normal engine.
  await maintainFamilies(ctx,{personId:notice.person_id,reason:'suspicious_activity_report'});
  for(const family of await all(ctx,"SELECT id FROM auth_refresh_families WHERE person_id=? AND reason='suspicious_activity_report' AND logout_queued_at IS NULL",notice.person_id))await endFamily(ctx,family.id,'suspicious_activity_report');
  await fencePerson(ctx,notice.person_id);
  await run(ctx,"UPDATE auth_suspicious_reports SET sessions_state='ended' WHERE id=?",report.id);
 }
 await syncObligations(ctx);
 if(!p.slackEnabled||report.slack_state!=='pending')return;
 const current=await notificationPolicy(ctx),owner=await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND version=? AND status='active' AND role IN ('owner','admin')",report.owner_id,report.owner_version);
 if(!owner||!current.slackEnabled||current.securityOwnerId!==report.owner_id||!ctx.notificationSlackWebhook) {
  await run(ctx,"UPDATE auth_suspicious_reports SET slack_state='refused' WHERE id=? AND slack_state='pending'",report.id);await history(ctx,report,'security_slack_refused','security_owner_or_consent_changed');return;
 }
 // A persisted single attempt prevents duplicate external escalation after restart.
 const claimed=await run(ctx,"UPDATE auth_suspicious_reports SET slack_state='dispatching' WHERE id=? AND slack_state='pending' AND resolved_at IS NULL",report.id);
 if(!claimed.meta.changes)return;
 await history(ctx,report,'security_slack_dispatching');
 const latest=await notificationPolicy(ctx),stillOwner=await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status='active' AND role IN ('owner','admin')",report.owner_id,report.owner_version);
 if(!stillOwner||!latest.slackEnabled||latest.securityOwnerId!==report.owner_id) {await run(ctx,"UPDATE auth_suspicious_reports SET slack_state='refused' WHERE id=?",report.id);await history(ctx,report,'security_slack_refused','security_owner_or_consent_changed');return;}
 try {
  const uri=new URL(ctx.notificationSlackWebhook);
  if(uri.protocol!=='https:'||uri.hostname!=='hooks.slack.com'||uri.username||uri.password)throw new Error('invalid_slack_webhook');
  const response=await (ctx.notificationFetch??fetch)(uri.href,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/json'},body:JSON.stringify({text:`Auth suspicious activity reported. Security owner: ${report.owner_id}. Review Activity: ${ctx.origin}${ctx.basePath??''}/app/activity\nReport reference: ${report.id}`})});
  await response.body?.cancel();if(!response.ok)throw new Error('slack_refused');
  await run(ctx,"UPDATE auth_suspicious_reports SET slack_state='accepted' WHERE id=?",report.id);await history(ctx,report,'security_slack_accepted');
 }catch {await run(ctx,"UPDATE auth_suspicious_reports SET slack_state='failed' WHERE id=?",report.id);await history(ctx,report,'security_slack_failed','slack_delivery_failed');}
}
export async function maintainNotifications(ctx) {
 await maintainNoticeIntents(ctx);
 for(const report of await all(ctx,"SELECT * FROM auth_suspicious_reports WHERE resolved_at IS NULL AND (sessions_state='pending' OR slack_state='pending') LIMIT 50"))await finishReport(ctx,report);
}
