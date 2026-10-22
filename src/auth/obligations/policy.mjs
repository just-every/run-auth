import {one,all,fail} from '../core.mjs';
import {calendar} from './calendar.mjs';
export const DEFAULT_POLICY=Object.freeze({enabled:false,calendar:calendar(),reminderBusinessDays:1,deadlineBusinessDays:5,recipients:[],escalationRecipients:[],escalation:'repeat_until_resolved'});
export async function policy(ctx) {
 const row=await one(ctx,'SELECT policy FROM auth_followup_settings WHERE id=1');
 return row?JSON.parse(row.policy):DEFAULT_POLICY;
}
export async function validatePolicy(ctx,data) {
 if(typeof data.enabled!=='boolean'||!['repeat_until_resolved','stop_at_deadline'].includes(data.escalation))fail('invalid_followup_policy');
 for(const field of ['reminderBusinessDays','deadlineBusinessDays'])if(!Number.isInteger(data[field])||data[field]<1||data[field]>90)fail('invalid_followup_policy');
 const checked={enabled:data.enabled,calendar:calendar(data.calendar),reminderBusinessDays:data.reminderBusinessDays,deadlineBusinessDays:data.deadlineBusinessDays,escalation:data.escalation};
 for(const field of ['recipients','escalationRecipients']) {
  if(!Array.isArray(data[field])||data[field].length>20||data[field].some(id=>typeof id!=='string'||!id||id.length>200))fail('invalid_followup_recipients');
  checked[field]=[...new Set(data[field])];
  for(const id of checked[field])if(!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",id))fail('followup_recipient_requires_admin');
 }
 if(checked.enabled&&!checked.recipients.length)fail('followup_approved_recipient_required');
 if(checked.enabled&&checked.escalation==='repeat_until_resolved'&&!checked.escalationRecipients.length)fail('followup_escalation_recipient_required');
 return checked;
}
export async function eligibleRecipients(ctx,ids) {
 const result=[];
 for(const id of ids)result.push(...await all(ctx,"SELECT id,email FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",id));
 return result;
}
