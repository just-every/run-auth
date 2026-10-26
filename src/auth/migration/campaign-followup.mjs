import {all,one} from '../core.mjs';
import {campaignCurrent,campaignPeople} from './campaign-state.mjs';
import {calendar} from '../obligations/calendar.mjs';

export async function campaignCandidates(ctx) {
 const candidates=[];
 for(const campaign of await all(ctx,'SELECT * FROM auth_campaigns WHERE cancelled_at IS NULL')) {
  if(!await campaignCurrent(ctx,campaign)||ctx.now()>=campaign.cutover_at)continue;
  for(const person of await campaignPeople(ctx,campaign))for(const duty of ['employee','manager','administrator']) {
   if(!campaign[duty+'_consent'])continue;
   const due=duty==='employee'?campaign.starts_at:duty==='manager'?Math.max(campaign.starts_at,campaign.deadline_at-3*86400000):campaign.deadline_at;
   candidates.push({kind:'enrollment',source_id:'campaign:'+campaign.id+':'+person.person_id+':'+duty,person_id:person.person_id,owner_id:campaign.created_by,created_at:campaign.created_at,campaign_id:campaign.id,duty,next_due_at:due,deadline_at:due});
  }
 }
 return candidates;
}
export async function campaignBinding(ctx,ob) {
 const ref=ob.id?await one(ctx,'SELECT * FROM auth_campaign_obligations WHERE obligation_id=?',ob.id):null;
 if(ref)return ref;
 if(!ob.campaign_id)return null;
 return {campaign_id:ob.campaign_id,person_id:ob.person_id,duty:ob.duty};
}
async function current(ctx,ob) {
 const binding=await campaignBinding(ctx,ob);if(!binding)return null;
 const campaign=await one(ctx,'SELECT * FROM auth_campaigns WHERE id=?',binding.campaign_id);
 const person=campaign&&(await campaignPeople(ctx,campaign)).find(row=>row.person_id===binding.person_id);
 return {binding,campaign,person};
}
export async function campaignSource(ctx,ob) {
 const item=await current(ctx,ob);if(!item)return null;
 const {campaign,person}=item;
 if(!campaign||!await campaignCurrent(ctx,campaign)||ctx.now()>=campaign.cutover_at||!person||person.state==='unavailable')return {state:'cancelled'};
 if(['exempt','passkey_ready'].includes(person.state))return {state:'completed'};
 return {state:'open',action:'complete_incumbent_proof_and_local_passkey'};
}
export async function campaignPolicy(ctx,ob) {
 const item=await current(ctx,ob);if(!item)return null;
 const {campaign,person,binding}=item;
 const id=binding.duty==='employee'?person?.person_id:binding.duty==='manager'?person?.manager_id:campaign?.created_by;
 const enabled=!!(campaign&&campaign[binding.duty+'_consent']&&id&&await campaignCurrent(ctx,campaign));
 return {enabled,calendar:calendar({timezone:'UTC',at:'00:00',weekdays:[0,1,2,3,4,5,6],holidays:[]}),reminderBusinessDays:1,deadlineBusinessDays:1,recipients:id?[id]:[],escalationRecipients:id?[id]:[],escalation:'stop_at_deadline'};
}
export async function campaignRecipient(ctx,ob,id) {
 const item=await current(ctx,ob);if(!item)return undefined;
 const p=await campaignPolicy(ctx,ob);
 if(!p.enabled||!p.recipients.includes(id)||(await campaignSource(ctx,ob)).state!=='open')return null;
 return one(ctx,"SELECT id,email,role,status FROM oa_operators WHERE id=? AND status IN ('active','invited')",id);
}
export async function campaignMessage(ctx,ob) {
 const item=await current(ctx,ob);if(!item)return null;
 const {campaign,person,binding}=item;
 return {subject:binding.duty==='administrator'?'Auth campaign enrollment overdue':binding.duty==='manager'?'Auth campaign manager reminder':'Enroll your Auth passkey before cutover',text:`${person.display_name} (${person.email}) has not completed incumbent proof and local passkey enrollment for ${campaign.name}. The enrollment deadline is ${new Date(campaign.deadline_at).toISOString()}. Sign in to Auth using the campaign provider: ${ctx.origin}${ctx.basePath??''}/signin\nA reminder does not grant access or confirm enrollment. Native authenticator enrollment is still required before a complete cutover.`,html:'<p>Auth campaign enrollment is still pending. Sign in to Auth and complete the required enrollment. This reminder does not grant access or confirm enrollment.</p>'};
}
