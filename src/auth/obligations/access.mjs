import {caseProjection} from './records.mjs';
import {roleState} from '../roles/state.mjs';
import {permitted} from '../roles/policy.mjs';
import {holdsObligation} from './recipients.mjs';
import {all} from '../core.mjs';

export async function followupAccess(ctx,s) {
 const state=await roleState(ctx,s);
 const canManage=JSON.parse(s.amr).includes('hwk')&&permitted(state,'followup.manage',{write:true});
 const ids=[];
 if(!canManage)for(const ob of await all(ctx,`SELECT *,${caseProjection} FROM auth_obligations`)) {
  // Employees see their own enrollment/recovery. A case is visible only to
  // its current scoped holder or the explicitly assigned follow-up owner.
  if(!ob.case_id&&['enrollment','recovery'].includes(ob.kind)&&ob.person_id===s.person_id||await holdsObligation(ctx,s,ob))ids.push(ob.id);
 }
 return {state,canManage,filter:canManage?{clause:'1',args:[]}:{clause:`id IN (SELECT value FROM json_each(?))`,args:[JSON.stringify(ids)]}};
}
