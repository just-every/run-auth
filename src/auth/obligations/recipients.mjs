import {isDirectoryObligation,directorySourceHolder} from '../directory-sources/followup.mjs';
import {notificationRecipient} from '../notifications/index.mjs';
import {decisionKind,decisionSource,decisionHolder} from './decision-sources.mjs';
import {releaseSource} from '../erasure/pair-erasure.mjs';
import {withCase} from './records.mjs';
import {one} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {permitted} from '../roles/policy.mjs';
import {campaignRecipient} from '../migration/campaign-followup.mjs';

export async function caseHolder(ctx,ob) {
 ob=await withCase(ctx,ob);
 if(!ob.case_id)return null;
 return one(ctx,"SELECT opened_by AS id FROM auth_role_cases WHERE id=? AND state!='closed'",ob.case_id);
}
export async function holdsCase(ctx,id,caseId) {
 const person=await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active'",id);
 if(!person)return false;
 const state=await roleState(ctx,{person_id:id});
 return permitted(state,'cases.verify',{caseId,write:true});
}
// Selectors name duties. The stored person IDs in older policies name only
// owner and administrator roles, and retain exactly their earlier consent.
export async function recipientIds(ctx,ob,selectors) {
 ob=await withCase(ctx,ob);
 if(releaseSource(ob))return selectors.includes(ob.owner_id)?[ob.owner_id]:[];
 const ids=[];
 for(const selector of selectors) {
  if(selector==='employee') {
   if(!ob.case_id&&['enrollment','recovery'].includes(ob.kind)&&ob.person_id)ids.push(ob.person_id);
  }else if(selector==='source_owner') {
   const feed=ob.id&&await one(ctx,'SELECT f.created_by FROM auth_hr_feed_obligations b JOIN auth_hr_feeds f ON f.id=b.feed_id WHERE b.obligation_id=?',ob.id);if(feed)ids.push(feed.created_by);
  }else if(selector==='decider') {
   const source=await decisionSource(ctx,ob);if(source?.state==='open')ids.push(source.deciderId);
  }else if(selector==='help_desk') {
   const holder=await caseHolder(ctx,ob);if(holder)ids.push(holder.id);
  }else ids.push(selector);
 }
 return [...new Set(ids)];
}
export async function recipient(ctx,ob,id,selectors,{escalation=false}={}) {
 ob=await withCase(ctx,ob);
 const campaign=await campaignRecipient(ctx,ob,id);if(campaign!==undefined)return selectors.includes(id)?campaign:null;
 const security=await notificationRecipient(ctx,ob,id,selectors);if(security!==undefined)return security;
 const feed=ob.id&&await one(ctx,'SELECT f.* FROM auth_hr_feed_obligations b JOIN auth_hr_feeds f ON f.id=b.feed_id WHERE b.obligation_id=?',ob.id);
 const person=await one(ctx,"SELECT id,email,role,status FROM oa_operators WHERE id=?",id);
 if(!person)return null;
 if(feed)return person.status==='active'&&['owner','admin'].includes(person.role)&&(escalation?selectors.includes(id):selectors.includes('source_owner')&&feed.created_by===id&&Boolean(await one(ctx,'SELECT 1 FROM oa_operators WHERE id=? AND version=?',feed.created_by,feed.owner_version)))?person:null;
 if(releaseSource(ob))return person.id===ob.owner_id&&person.role==='owner'&&person.status==='active'&&selectors.includes(person.id)?person:null;
 if(decisionKind(ob)&&!escalation)return selectors.includes('decider')&&await decisionHolder(ctx,ob,id)?person:null;
 if(selectors.includes(id)&&person.status==='active'&&['owner','admin'].includes(person.role))return person;
 if(escalation)return null;
 if(selectors.includes('employee')&&!ob.case_id&&['enrollment','recovery'].includes(ob.kind)&&ob.person_id===id&&['invited','active'].includes(person.status))return person;
 if(selectors.includes('help_desk')&&(await caseHolder(ctx,ob))?.id===id&&await holdsCase(ctx,id,ob.case_id))return person;
 return null;
}
export async function holdsObligation(ctx,s,ob) {
 ob=await withCase(ctx,ob);
 if(isDirectoryObligation(ob))return directorySourceHolder(ctx,ob,s.person_id);
 if(decisionKind(ob))return decisionHolder(ctx,ob,s.person_id);
 if(releaseSource(ob))return s.role==='owner'&&ob.owner_id===s.person_id;
 if(!ob.case_id&&['enrollment','recovery'].includes(ob.kind)&&ob.person_id===s.person_id)return true;
 const holder=await caseHolder(ctx,ob);
 if(holder?.id===s.person_id&&await holdsCase(ctx,s.person_id,ob.case_id))return true;
 if(ob.owner_id!==s.person_id)return false;
 const person=await one(ctx,"SELECT role,status FROM oa_operators WHERE id=?",s.person_id);
 if(person?.status!=='active')return false;
 if(['owner','admin'].includes(person.role))return true;
 if(ob.case_id)return holdsCase(ctx,s.person_id,ob.case_id);
 return ob.kind==='delegated_assignment'&&ob.person_id===s.person_id;
}
