import {one,all,random,requireSession,json,fail,auditDetail,input,AuthError} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {framedPage,FRAME_SOURCES} from '../page-frame.mjs';
import {emit} from '../events/store.mjs';
import {notificationPolicy,validateNotificationPolicy,MANDATORY} from './policy.mjs';
import {verifiedNotification} from './tokens.mjs';
import {finishReport} from './delivery.mjs';
export const NOTIFICATIONS_READ='/api/auth/notifications';
export const NOTIFICATION_REPORT='/api/auth/notifications/report';
export const isNotificationAction=path=>['/notifications/settings','/notifications/resolve'].includes(path);
export async function notificationsModel(ctx,request) {
 const s=await requireSession(ctx,request),canManage=['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk'),p=await notificationPolicy(ctx);
 const reports=canManage?await all(ctx,`SELECT r.id,r.notification_id,r.owner_id,r.created_at,r.resolved_at,r.sessions_state,r.slack_state,n.event,n.source_id FROM auth_suspicious_reports r JOIN auth_security_notifications n ON n.id=r.notification_id ORDER BY r.created_at DESC LIMIT 100`):[];
 return {canManage,policy:canManage?p:{emailEnabled:p.emailEnabled,newDevice:p.newDevice,factorEnrolled:p.factorEnrolled},mandatory:MANDATORY,reports,eligibleOwners:canManage?await all(ctx,"SELECT id,email,display_name AS name FROM oa_operators WHERE status='active' AND role IN ('owner','admin') ORDER BY email"):[],slackConfigured:canManage&&Boolean(ctx.notificationSlackWebhook),limitations:['Email covers new browsers, passkey enrollment, recovery, help-desk factor resets, direct administrator promotion and explicit scoped administrator role grants.','Mobile push, password and temporary access pass notices are pending.','Report responses currently support ending Auth sessions and supported back-channel logout; connected vendor session revocation and other response policies are pending.']};
}
export const notificationRead=async(ctx,request)=>json(await notificationsModel(ctx,request));
export async function notificationAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);const guard=authority(ctx,s,['owner','admin']);
 if(path==='/notifications/settings') {
  const p=await validateNotificationPolicy(ctx,data),owner=p.securityOwnerId?await one(ctx,"SELECT id,version FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",p.securityOwnerId):null;
  if(p.emailEnabled&&!owner)fail('notification_owner_changed',409);
  const changed=await ctx.db.prepare(`INSERT INTO auth_notification_policy(id,policy,updated_by,updated_at) SELECT 1,?,?,? WHERE ${guard.clause} AND (? IS NULL OR EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status='active' AND role IN ('owner','admin'))) ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,updated_by=excluded.updated_by,updated_at=excluded.updated_at`).bind(JSON.stringify(p),s.person_id,ctx.now(),...guard.args,owner?.id??null,owner?.id??null,owner?.version??null).run();
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('notification_owner_changed',409);}
  await auditDetail(ctx,s.person_id,'notification_policy_changed',null,{...p,consent:true});return json({ok:true,policy:p});
 }
 if(path!=='/notifications/resolve')fail('not_found',404);
 if(data.confirm!==true)fail('notification_explicit_consent_required');
 const result=await ctx.db.prepare(`UPDATE auth_suspicious_reports SET resolved_at=? WHERE id=? AND resolved_at IS NULL AND ${guard.clause}`).bind(ctx.now(),String(data.reportId??''),...guard.args).run();
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('notification_report_unavailable',409);}
 await auditDetail(ctx,s.person_id,'suspicious_activity_reviewed',data.reportId,{resolution:'review_completed'});return json({ok:true});
}
function reportPage(title,body,status=200) {
 return new Response(framedPage(title,body),{status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`}});
}
export async function notificationReport(ctx,request) {
 try {
  if(!['GET','POST'].includes(request.method))fail('method_not_allowed',405);
  const data=request.method==='POST'?await input(ctx,request):null,token=data?.token??new URL(request.url).searchParams.get('token'),notice=await verifiedNotification(ctx,token);
  const p=await notificationPolicy(ctx),owner=await one(ctx,"SELECT id,version FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",p.securityOwnerId);
  if(!p.emailEnabled||!owner)fail('notification_security_owner_unavailable',409);
  const id=random(),now=ctx.now();
  const results=await ctx.db.batch([
   ctx.db.prepare(`UPDATE auth_security_notifications SET reported_at=? WHERE id=? AND reported_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_notification_policy WHERE id=1 AND policy=?) AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status='active' AND role IN ('owner','admin'))`).bind(now,notice.id,now,JSON.stringify(p),owner.id,owner.version),
   ctx.db.prepare(`INSERT INTO auth_suspicious_reports(id,notification_id,owner_id,owner_version,policy,created_at,sessions_state,slack_state) SELECT ?,?,?,?,?,?,?,? WHERE changes()>0`).bind(id,notice.id,owner.id,owner.version,JSON.stringify(p),now,p.endSessionsOnReport?'pending':'not_requested',p.slackEnabled?'pending':'not_requested'),
   ctx.db.prepare('UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM auth_suspicious_reports WHERE id=? AND sessions_state=?)').bind(now,notice.person_id,id,'pending'),
   ctx.db.prepare("UPDATE auth_refresh_families SET revoked_at=?,reason='suspicious_activity_report' WHERE person_id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM auth_suspicious_reports WHERE id=? AND sessions_state='pending')").bind(now,notice.person_id,id),
   ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT NULL,'suspicious_activity_reported',?,? WHERE EXISTS(SELECT 1 FROM auth_suspicious_reports WHERE id=?)").bind(id,now,id),
   ctx.db.prepare("INSERT INTO auth_activity_details(activity_id,detail) SELECT id,? FROM auth_activity WHERE event='suspicious_activity_reported' AND subject_id=?").bind(JSON.stringify({notificationId:notice.id,triggerEvent:notice.event,sourceId:notice.source_id,personId:notice.person_id,endSessions:p.endSessionsOnReport}),id),
  ]);
  if(!results[0].meta.changes)fail('notification_report_unavailable',410);
  await emit(ctx,'security.suspicious_activity_reported',{type:'person',id:notice.person_id},{notificationId:notice.id,sourceId:notice.source_id,triggerEvent:notice.event,reportId:id});
  await finishReport(ctx,await one(ctx,'SELECT * FROM auth_suspicious_reports WHERE id=?',id));
  return reportPage('Suspicious activity reported','<h1>Suspicious activity reported</h1><p>Your report has been recorded for the security owner. Sign in to Auth to review your account.</p>');
 }catch(error) {
  if(!(error instanceof AuthError))throw error;
  return reportPage('Report unavailable','<h1>Report unavailable</h1><p>This report link may have expired or already been used. Sign in to Auth or contact your employer’s security owner.</p>',error.status);
 }
}
