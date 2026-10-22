import {normalized} from './journal.mjs';

export const referenceColumns=new Set(['person_id','operator_id','owner_id','owner_person_id','actor_id','subject_id','created_by','updated_by','set_by','bound_by','added_by','approved_by','decided_by','requested_by','revoked_by','released_by','completed_by','claim_id','reviewer_id','decider_id','marked_by']);
const evidenceTables=new Set(['auth_decision_operations','auth_review_events','auth_activity','auth_activity_details','oa_auth_audit','auth_agent_proposals','auth_events','auth_role_events','auth_role_operations']);
export const isEvidence=name=>evidenceTables.has(name);
export function contains(value,identifiers) {
 if(value===null||value===undefined)return false;
 if(Array.isArray(value))return value.some(v=>contains(v,identifiers));
 if(value&&typeof value==='object')return Object.values(value).some(v=>contains(v,identifiers));
 if(typeof value!=='string')return false;
 const text=normalized(value);
 if([...identifiers].some(id=>text===normalized(id)))return true;
 try {const parsed=JSON.parse(value);if(parsed!==value&&contains(parsed,identifiers))return true;}catch{}
 return [...identifiers].some(id=>new RegExp('(^|[^a-z0-9_-])'+normalized(id).replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'($|[^a-z0-9_-])','i').test(text));
}
export function anonymous(value,identifiers,reference) {
 if(typeof value==='string') {
  let result=value;
  for(const id of [...identifiers].filter(Boolean).sort((a,b)=>b.length-a.length))result=result.replace(new RegExp(String(id).replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'gi'),reference);
  return result;
 }
 if(Array.isArray(value))return value.map(v=>anonymous(v,identifiers,reference));
 if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,anonymous(v,identifiers,reference)]));
 return value;
}
