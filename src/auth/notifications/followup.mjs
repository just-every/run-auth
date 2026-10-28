import {all,one} from '../core.mjs';
export const notificationSourceId=id=>'security-report:'+id;
export async function notificationCandidates(ctx) {
 return all(ctx,`SELECT 'app_setup' AS kind,'security-report:'||id AS source_id,owner_id,NULL AS person_id,NULL AS app_id,created_at FROM auth_suspicious_reports WHERE resolved_at IS NULL
 UNION ALL SELECT 'app_setup','security-notice:'||id,NULL,person_id,NULL,created_at FROM auth_security_notice_intents WHERE state!='accepted'`);
}
export async function notificationSource(ctx,ob) {
 if(ob.kind==='app_setup'&&ob.source_id?.startsWith('security-notice:')) {
  const intent=await one(ctx,'SELECT state,last_error FROM auth_security_notice_intents WHERE id=?',ob.source_id.slice('security-notice:'.length));
  if(!intent)return {state:'cancelled'};
  if(intent.state==='accepted')return {state:'completed'};
  return {state:'open',action:intent.last_error==='notification_channel_setup_required'?'configure_security_notifications_and_review_required_notice':'review_required_security_notice_delivery_without_resending',error:intent.last_error??'security_notice_pending'};
 }
 if(ob.kind!=='app_setup'||!ob.source_id?.startsWith('security-report:'))return null;
 const report=await one(ctx,'SELECT * FROM auth_suspicious_reports WHERE id=?',ob.source_id.slice('security-report:'.length));
 if(!report)return {state:'cancelled'};
 if(report.resolved_at)return {state:'completed'};
 return {state:'open',action:'investigate_suspicious_activity_and_review_factors',error:report.slack_state==='failed'?'security_slack_delivery_failed':report.slack_state==='dispatching'?'security_slack_outcome_unknown':null};
}
// Security escalation is limited to its explicitly selected current custodian.
export async function notificationRecipient(ctx,ob,id,selectors) {
 // A delivery obligation is visible work, never consent for additional mail.
 if(ob.source_id?.startsWith('security-notice:'))return null;
 if(!ob.source_id?.startsWith('security-report:'))return undefined;
 const report=await one(ctx,'SELECT * FROM auth_suspicious_reports WHERE id=? AND resolved_at IS NULL',ob.source_id.slice('security-report:'.length));
 if(!report||report.owner_id!==id||!selectors.includes(id))return null;
 return one(ctx,"SELECT id,email,role,status FROM oa_operators WHERE id=? AND version=? AND status='active' AND role IN ('owner','admin')",id,report.owner_version);
}
