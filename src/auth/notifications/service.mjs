import {one,run,hash,random,cookies,cookie,scopedCookieName,auditDetail} from '../core.mjs';
import {notificationPolicy,EVENTS} from './policy.mjs';
import {reportToken} from './tokens.mjs';
import {notificationContext,notificationMessage} from './messages.mjs';
const WEEK=7*86400000;

// Only successful source doors call this hook, with their committed source ID.
// No caller-supplied mailbox or sign-in authority enters notification transport.
export async function notifySecurity(ctx,{personId,event,sourceId,request,app,factor}) {
 if(!EVENTS.includes(event))throw new Error('unsupported_security_notification');
 if(!sourceId)throw new Error('notification_source_required');
 const p=await notificationPolicy(ctx);
 if(!p.emailEnabled||event==='new_device'&&!p.newDevice||event==='factor_enrolled'&&!p.factorEnrolled)return null;
 const person=await one(ctx,"SELECT p.id,p.email FROM oa_operators p JOIN auth_emails e ON e.person_id=p.id WHERE p.id=? AND p.status='active'",personId);
 if(!person)return null;
 const nonce=random(),id=random(),expiresAt=ctx.now()+WEEK,token=await reportToken(ctx,nonce,expiresAt),context=JSON.stringify(notificationContext(ctx,{request,app,factor}));
 const inserted=await run(ctx,`INSERT OR IGNORE INTO auth_security_notifications(id,person_id,event,source_id,context,token_hash,expires_at,created_at,delivery_state)
 SELECT ?,?,?,?,?,?,?,?,'dispatching' WHERE EXISTS(SELECT 1 FROM auth_notification_policy WHERE id=1 AND policy=?) AND EXISTS(SELECT 1 FROM oa_operators p JOIN auth_emails e ON e.person_id=p.id WHERE p.id=? AND p.email=? AND p.status='active')`,id,personId,event,String(sourceId),context,await hash(nonce),expiresAt,ctx.now(),JSON.stringify(p),personId,person.email);
 if(!inserted.meta.changes)return null;
 await auditDetail(ctx,null,'security_notification_created',id,{event,sourceId:String(sourceId),personId});
 const row={event,context},link=`${ctx.origin}${ctx.basePath??''}/api/auth/notifications/report?token=${encodeURIComponent(token)}`;
 try {
  // The persisted attempt is never retried automatically after an unknown send.
  const current=await notificationPolicy(ctx),live=await one(ctx,"SELECT email FROM oa_operators WHERE id=? AND email=? AND status='active'",personId,person.email);
  if(JSON.stringify(current)!==JSON.stringify(p)||!live) {await run(ctx,"UPDATE auth_security_notifications SET delivery_state='refused' WHERE id=?",id);return id;}
  if(!ctx.mail)throw new Error('mail_not_configured');
  await ctx.mail({to:person.email,...notificationMessage(ctx,row,link)});
  await run(ctx,"UPDATE auth_security_notifications SET delivery_state='accepted' WHERE id=?",id);
 }catch {await run(ctx,"UPDATE auth_security_notifications SET delivery_state='failed' WHERE id=?",id);await auditDetail(ctx,null,'security_notification_delivery_failed',id,{event});}
 return id;
}

// A browser marker is only a recognition signal. It conveys no authentication
// authority and cannot suppress mandatory notices or authorize a report.
export async function notifyNewDevice(ctx,{personId,sessionId,request,app}) {
 if(!request)return null;
 const active=await one(ctx,'SELECT id FROM auth_sessions WHERE id=? AND person_id=? AND revoked_at IS NULL AND expires_at>?',sessionId,personId,ctx.now());if(!active)return null;
 const name=scopedCookieName(ctx,ctx.local?'auth_device':'__Host-auth_device'),saved=cookies(request)[name];
 const marker=typeof saved==='string'&&/^[a-zA-Z0-9_-]{43}$/.test(saved)?saved:random(),digest=await hash(marker);
 const recognized=await one(ctx,'SELECT 1 FROM (SELECT device_hash FROM auth_notification_devices WHERE person_id=? ORDER BY created_at DESC,session_id DESC LIMIT 20) WHERE device_hash=?',personId,digest);
 const inserted=await run(ctx,'INSERT OR IGNORE INTO auth_notification_devices(person_id,session_id,device_hash,created_at) VALUES(?,?,?,?)',personId,sessionId,digest,ctx.now());
 await run(ctx,'DELETE FROM auth_notification_devices WHERE person_id=? AND session_id NOT IN (SELECT session_id FROM auth_notification_devices WHERE person_id=? ORDER BY created_at DESC,session_id DESC LIMIT 20)',personId,personId);
 if(inserted.meta.changes&&!recognized)await notifySecurity(ctx,{personId,event:'new_device',sourceId:sessionId,request,app});
 return cookie(ctx,name,marker,365*86400);
}
