import {one,fail} from '../core.mjs';
export const MANDATORY=['recovery_started','factor_reset','factor_removed','administrator_role_granted'];
export const EVENTS=['new_device','factor_enrolled',...MANDATORY];
export const DEFAULT_POLICY=Object.freeze({emailEnabled:false,newDevice:true,factorEnrolled:true,securityOwnerId:null,slackEnabled:false,endSessionsOnReport:false});
export async function notificationPolicy(ctx) {
 const row=await one(ctx,'SELECT policy FROM auth_notification_policy WHERE id=1');
 return row?JSON.parse(row.policy):DEFAULT_POLICY;
}
export async function validateNotificationPolicy(ctx,data) {
 if(data.confirm!==true)fail('notification_explicit_consent_required');
 for(const event of MANDATORY)if(data[event]===false||data.events?.[event]===false)fail('mandatory_notification_required');
 // Once mail is authorized, mandatory events cannot be disabled through a channel switch.
 const previous=await notificationPolicy(ctx);
 if(previous.emailEnabled&&data.emailEnabled===false)fail('mandatory_notification_required');
 for(const field of ['emailEnabled','newDevice','factorEnrolled','slackEnabled','endSessionsOnReport'])if(typeof data[field]!=='boolean')fail('invalid_notification_policy');
 if(!data.emailEnabled&&(data.slackEnabled||data.endSessionsOnReport))fail('notification_email_consent_required');
 const ownerId=typeof data.securityOwnerId==='string'?data.securityOwnerId:null;
 if(data.emailEnabled&&!await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",ownerId))fail('notification_security_owner_required');
 if(data.slackEnabled&&!ctx.notificationSlackWebhook)fail('notification_slack_not_configured');
 return {emailEnabled:data.emailEnabled,newDevice:data.newDevice,factorEnrolled:data.factorEnrolled,securityOwnerId:ownerId,slackEnabled:data.slackEnabled,endSessionsOnReport:data.endSessionsOnReport};
}
