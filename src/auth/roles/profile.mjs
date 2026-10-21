import {json,fail} from '../core.mjs';
import {requireRolePermission,personInScope} from './policy.mjs';
import {commit} from './commit.mjs';
import {planEdit} from '../workforce/people/plan.mjs';
import {setStatement,clearStatement,effective,written} from '../workforce/people/fields.mjs';
import {matches} from '../workforce/people/groups.mjs';
import {personChanged,groupChanged} from '../provisioning/obligations.mjs';
import {emit,personSubject} from '../events/store.mjs';

export async function editProfile(ctx,s,data) {
 const personId=String(data.personId??''),guard=await requireRolePermission(ctx,s,'people.profile.edit',{personId,write:true}),{state}=guard;
 if(!data.fields||typeof data.fields!=='object'||Array.isArray(data.fields)||!Object.keys(data.fields).length)fail('invalid_fields');
 const plan=await planEdit(ctx,state.dir,{personId,source:'manual',set:data.fields},s.person_id);
 if(plan.refusals.length)return json({error:'edit_refused',refusals:plan.refusals},409);
 const p=state.dir.people.get(personId);
 let fields=p.fields;
 for(const w of plan.writes)fields=written(fields,w.field,w.source,w.value);
 const values=effective(fields,state.dir.defs),after=new Set();
 for(const g of state.dir.groups) {
  const row=state.dir.members.get(g.id)?.get(personId);
  if(!state.dir.exclusions.has(g.id+':'+personId)&&(row?.source==='manual'||g.rule&&matches(g.rule,values)))after.add(g.id);
 }
 const next={...state,memberships:new Map(state.memberships).set(personId,after)};
 if(!state.entries.some(e=>e.role.permissions.includes('people.profile.edit')&&personInScope(next,e.resources.edit,personId,true)))fail('profile_moves_outside_edit_scope',403);
 // Compute rule additions/removals from the current values, rather than trusting
 // materialized rule rows to have caught up with the most recent source update.
 const added=[],removed=[];
 for(const g of state.dir.ruleGroups) {
  const row=state.dir.members.get(g.id)?.get(personId);
  if(after.has(g.id)&&!row)added.push(g);
  if(!after.has(g.id)&&row?.source==='rule')removed.push(g);
 }
 const {operationId}=await commit(ctx,s,guard,'roles.profile.edit',personId,{plan,groups:{added:added.map(g=>g.id),removed:removed.map(g=>g.id)}},(g,q)=>[
  ...plan.writes.map(w=>w.value===null?clearStatement(ctx,g,personId,w.field,'manual'):setStatement(ctx,g,personId,w.field,'manual',w.value,s.person_id)),
  ...(plan.nameChange?[q(`UPDATE oa_operators SET display_name=? WHERE id=? AND ${g.clause}`,plan.nameChange.to,personId,...g.args)]:[]),
  ...added.map(gr=>q(`INSERT INTO auth_group_members(group_id,person_id,added_by,added_at,source) SELECT ?,?,?,?,'rule' WHERE ${g.clause} ON CONFLICT DO NOTHING`,gr.id,personId,s.person_id,ctx.now(),...g.args)),
  ...removed.map(gr=>q(`DELETE FROM auth_group_members WHERE group_id=? AND person_id=? AND source='rule' AND ${g.clause}`,gr.id,personId,...g.args)),
 ]);
 await personChanged(ctx,personId,'person_profile_changed');
 const subject=await personSubject(ctx,personId);
 await emit(ctx,'person.updated',subject,{fields:plan.writes.map(w=>w.field),source:'manual'});
 for(const [groups,type,reason] of [[added,'group.member_added','group_member_added'],[removed,'group.member_removed','group_member_removed']])for(const g of groups){await groupChanged(ctx,g.id,[personId],reason);await emit(ctx,type,subject,{group:g.id,via:'rule'});}
 return json({ok:true,operationId});
}
