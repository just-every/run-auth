import {withCase} from './records.mjs';
import {one} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {permitted} from '../roles/policy.mjs';

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
// owner/administrator roles, and retain exactly their earlier consent.
export async function recipientIds(ctx,ob,selectors) {
 ob=await withCase(ctx,ob);
 const ids=[];
 for(const selector of selectors) {
  if(selector==='employee') {
   if(!ob.case_id&&['enrollment','recovery'].includes(ob.kind)&&ob.person_id)ids.push(ob.person_id);
  }else if(selector==='help_desk') {
   const holder=await caseHolder(ctx,ob);if(holder)ids.push(holder.id);
  }else ids.push(selector);
 }
 return [...new Set(ids)];
}
export async function recipient(ctx,ob,id,selectors,{escalation=false}={}) {
 ob=await withCase(ctx,ob);
 const person=await one(ctx,"SELECT id,email,role,status FROM oa_operators WHERE id=?",id);
 if(!person)return null;
 if(selectors.includes(id)&&person.status==='active'&&['owner','admin'].includes(person.role))return person;
 if(escalation)return null;
 if(selectors.includes('employee')&&!ob.case_id&&['enrollment','recovery'].includes(ob.kind)&&ob.person_id===id&&['invited','active'].includes(person.status))return person;
 if(selectors.includes('help_desk')&&(await caseHolder(ctx,ob))?.id===id&&await holdsCase(ctx,id,ob.case_id))return person;
 return null;
}
export async function holdsObligation(ctx,s,ob) {
 ob=await withCase(ctx,ob);
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
