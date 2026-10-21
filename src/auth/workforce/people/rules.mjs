// Setting, previewing and clearing a group's rule, and its owners. A rule
// change is previewed with who joins and leaves, then applied with the group's
// provisioning to every app it is assigned to.
import {fail,auditDetail} from '../../core.mjs';
import {requireAuthority} from '../../local-email.mjs';
import {normalizeRule,matches,because,addRuleMember,dropRuleMember} from './groups.mjs';
import {groupChanged} from '../../provisioning/obligations.mjs';
import {emit} from '../../events/store.mjs';

// Who a rule (or none) would add to and remove from the group, from the directory as it is now.
export function ruleDelta(dir,group,rule) {
 const rows=dir.members.get(group.id),added=[],removed=[];
 for(const p of dir.people.values()) {
  const wanted=Boolean(rule)&&matches(rule,dir.values(p))&&!dir.exclusions.has(group.id+':'+p.id),row=rows.get(p.id);
  if(wanted&&!row)added.push({id:p.id,email:p.email,why:because(rule,dir.values(p))});
  else if(!wanted&&row?.source==='rule')removed.push({id:p.id,email:p.email});
 }
 return {added,removed};
}

export async function setRule(ctx,s,guard,dir,data) {
 const group=dir.groups.find(g=>g.id===String(data.groupId||''))??fail('group_not_found',404);
 const rule=data.rule===null||data.rule===undefined?null:normalizeRule(dir.defs,data.rule),delta=ruleDelta(dir,group,rule);
 if(data.preview===true)return {preview:true,rule,...delta};
 const statements=[ctx.db.prepare(`UPDATE auth_groups SET rule=? WHERE id=? AND ${guard.clause}`).bind(rule?JSON.stringify(rule):null,group.id,...guard.args),
  ...delta.added.map(p=>addRuleMember(ctx,guard,group.id,p.id,s.person_id)),...delta.removed.map(p=>dropRuleMember(ctx,guard,group.id,p.id))];
 const done=await ctx.db.batch(statements);
 if(!done[0].meta.changes){await requireAuthority(ctx,s,guard);fail('group_not_found',404);}
 await auditDetail(ctx,s.person_id,rule?'group_rule_set':'group_rule_cleared',group.id,{name:group.name,rule,added:delta.added.map(p=>p.email),removed:delta.removed.map(p=>p.email)});
 for(const p of delta.added)await emit(ctx,'group.member_added',{type:'person',id:p.id,email:p.email},{group:group.id,via:'rule'});
 for(const p of delta.removed)await emit(ctx,'group.member_removed',{type:'person',id:p.id,email:p.email},{group:group.id,via:'rule'});
 await groupChanged(ctx,group.id,[...delta.added,...delta.removed].map(p=>p.id),'group_rule_changed');
 return {rule,...delta};
}

export async function changeOwner(ctx,s,guard,dir,data,add) {
 const group=dir.groups.find(g=>g.id===String(data.groupId||''))??fail('group_not_found',404);
 const person=dir.people.get(String(data.personId||''))??(data.email?dir.byEmail.get(String(data.email).trim().toLowerCase()):null)??fail('person_not_found',404);
 if(add&&person.state!=='active'&&person.state!=='invited')fail('person_unavailable',409);
 const changed=add
  ?await ctx.db.prepare(`INSERT INTO auth_group_owners(group_id,person_id,added_by,added_at) SELECT ?,?,?,? WHERE ${guard.clause} ON CONFLICT DO NOTHING`).bind(group.id,person.id,s.person_id,ctx.now(),...guard.args).run()
  :await ctx.db.prepare(`DELETE FROM auth_group_owners WHERE group_id=? AND person_id=? AND ${guard.clause}`).bind(group.id,person.id,...guard.args).run();
 if(!changed.meta.changes){await requireAuthority(ctx,s,guard);return {changed:false};}
 await auditDetail(ctx,s.person_id,add?'group_owner_added':'group_owner_removed',group.id,{name:group.name,person:person.email});
 return {changed:true};
}
