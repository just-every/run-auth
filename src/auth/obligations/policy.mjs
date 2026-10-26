import {one,fail,auditDetail} from '../core.mjs';
import {calendar} from './calendar.mjs';
import {campaignPolicy} from '../migration/campaign-followup.mjs';
export const obligationPolicy=async(ctx,ob)=>await campaignPolicy(ctx,ob)??await policy(ctx);
export const DEFAULT_POLICY=Object.freeze({enabled:false,calendar:calendar(),reminderBusinessDays:1,deadlineBusinessDays:5,recipients:[],escalationRecipients:[],escalation:'repeat_until_resolved'});
export async function policy(ctx) {
 const row=await one(ctx,'SELECT policy FROM auth_followup_settings WHERE id=1');
 if(!row)return DEFAULT_POLICY;
 const saved=JSON.parse(row.policy);
 // Upgrade old consent without adding a person or address: these same named
 // administrators were already approved to receive this obligation's mail.
 if(saved.enabled&&!saved.escalationRecipients?.length&&saved.recipients?.length) {
  const upgraded={...saved,escalationRecipients:[...saved.recipients]};
  const [,changed]=await ctx.db.batch([
   ctx.db.prepare("UPDATE auth_obligations SET next_due_at=MIN(next_due_at,reminders_stopped_at),reminders_stopped_at=NULL WHERE state='open' AND reminders_stopped_at IS NOT NULL AND EXISTS(SELECT 1 FROM auth_followup_settings WHERE id=1 AND policy=?)").bind(row.policy),
   ctx.db.prepare('UPDATE auth_followup_settings SET policy=? WHERE id=1 AND policy=?').bind(JSON.stringify(upgraded),row.policy),
  ]);
  if(changed.meta.changes) {
   await auditDetail(ctx,null,'followup_legacy_policy_migrated',null,{recipients:upgraded.escalationRecipients,consent:'existing_approved_recipients_only'});
  }
  return policy(ctx);
 }
 return {...saved,escalationRecipients:saved.escalationRecipients??[]};
}
export async function validatePolicy(ctx,data) {
 if(typeof data.enabled!=='boolean'||!['repeat_until_resolved','stop_at_deadline'].includes(data.escalation))fail('invalid_followup_policy');
 for(const field of ['reminderBusinessDays','deadlineBusinessDays'])if(!Number.isInteger(data[field])||data[field]<1||data[field]>90)fail('invalid_followup_policy');
 const checked={enabled:data.enabled,calendar:calendar(data.calendar),reminderBusinessDays:data.reminderBusinessDays,deadlineBusinessDays:data.deadlineBusinessDays,escalation:data.escalation};
 for(const field of ['recipients','escalationRecipients']) {
  if(!Array.isArray(data[field])||data[field].length>20||data[field].some(id=>typeof id!=='string'||!id||id.length>200))fail('invalid_followup_recipients');
  checked[field]=[...new Set(data[field])];
  for(const id of checked[field])if(!(field==='recipients'&&['employee','help_desk','decider','source_owner'].includes(id))&&!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",id))fail('followup_recipient_requires_admin');
 }
 if(checked.enabled&&!checked.recipients.length)fail('followup_approved_recipient_required');
 if(checked.enabled&&!checked.escalationRecipients.length)fail('followup_escalation_recipient_required');
 return checked;
}
