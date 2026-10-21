// A person who became a member outside the directory doors (an invitation, a
// domain sign-up, a move-in admission) is put in the groups their values match
// when they activate, the moment they can hold access.
import {loadDirectory} from './load.mjs';
import {planEdit} from './plan.mjs';
import {addRuleMember,dropRuleMember} from './groups.mjs';
import {groupChanged} from '../../provisioning/obligations.mjs';
import {emit,personSubject} from '../../events/store.mjs';

export async function evaluatePerson(ctx,personId) {
 const dir=await loadDirectory(ctx);
 if(!dir.ruleGroups.length||!dir.people.has(personId))return;
 const {groups}=await planEdit(ctx,dir,{personId},null),always={clause:'1',args:[]};
 if(!groups.added.length&&!groups.removed.length)return;
 await ctx.db.batch([...groups.added.map(g=>addRuleMember(ctx,always,g.id,personId,'system')),...groups.removed.map(g=>dropRuleMember(ctx,always,g.id,personId))]);
 const subject=await personSubject(ctx,personId);
 for(const [list,type,reason] of [[groups.added,'group.member_added','group_member_added'],[groups.removed,'group.member_removed','group_member_removed']])
  for(const g of list){await emit(ctx,type,subject,{group:g.id,via:'rule'});await groupChanged(ctx,g.id,[personId],reason);}
}
