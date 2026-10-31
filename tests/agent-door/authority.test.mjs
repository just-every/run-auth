import {test} from 'node:test';
import assert from 'node:assert/strict';
import {authorityFixture,heldMembershipPolicy} from './authority-fixture.mjs';

test('native membership authority survives cached success, held execution and restart without widening',{timeout:180000},async t=>{
 const f=await authorityFixture(t),{people:p,groups:g}=f;
 await f.policy();
 const add=(who,group,person,key)=>f.call(who,'auth.groups.add',{group_id:group.id,person_id:person.id,idempotency_key:key});
 const remove=(who,group,person,key)=>f.call(who,'auth.groups.remove',{id:group.id+'/'+person.id,idempotency_key:key});
 const done=result=>{assert.equal(result.status,200);assert.equal(result.isError,false,JSON.stringify(result));};
 const refused=result=>{assert.equal(result.status,200);assert.equal(result.isError,true,JSON.stringify(result));assert.equal(result.structuredContent,undefined);assert.equal(result._meta['com.runeditrun/error'].code,'admin_service_owner_permission_required');};
 const present=async(group,person)=>Boolean((await f.members()).find(x=>x.id===group.id).members.some(x=>x.id===person.id));
 // The native person scope also follows group membership. Keep the outside
 // target in a non-editable group so adding it elsewhere cannot make the
 // subsequent removal an authorized action under the all-groups rule.
 await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:g.outside.id,personId:p.outside.id});
 // The same native membership action is allowed for owner and scoped editor,
 // denied for a reader, another group and a person outside the grant.
 for(const who of [p.owner,p.editor]) {
  assert.equal((await who.call('/api/auth/roles/group',{action:'add',groupId:g.first.id,personId:p.worker.id})).status,200);
  assert.equal(await present(g.first,p.worker),true);
  done(await remove(who,g.first,p.worker,'native-remove-'+who.sub));assert.equal(await present(g.first,p.worker),false);
  done(await add(who,g.first,p.worker,'mcp-add-'+who.sub));assert.equal(await present(g.first,p.worker),true);
  assert.equal((await who.call('/api/auth/roles/group',{action:'remove',groupId:g.first.id,personId:p.worker.id})).status,200);
  assert.equal(await present(g.first,p.worker),false);
 }
 for(const [who,group,person] of [[p.reader,g.first,p.worker],[p.editor,g.outside,p.worker],[p.editor,g.first,p.outside]]) {
  assert.equal((await who.call('/api/auth/roles/group',{action:'add',groupId:group.id,personId:person.id})).status,403);
  const before=await f.members(),answer=await add(who,group,person,'refused-'+who.sub+group.id+person.id);
  assert.equal(answer.isError,true);assert.equal(answer.structuredContent,undefined);assert.deepEqual(await f.members(),before);
  await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:group.id,personId:person.id});
  const seeded=await f.members();assert.equal(await present(group,person),true);
  assert.equal((await who.call('/api/auth/roles/group',{action:'remove',groupId:group.id,personId:person.id})).status,403);
  assert.equal((await remove(who,group,person,'refused-remove-'+who.sub+group.id+person.id)).isError,true);
  assert.deepEqual(await f.members(),seeded);
  await f.post(p.owner,'/api/auth/roles/group',{action:'remove',groupId:group.id,personId:person.id});
 }
 assert.equal((await add(p.editor,g.first,p.editor,'self-widen'))._meta['com.runeditrun/error'].code,'self_escalation');
 assert.equal(await present(g.first,p.editor),false);
 await f.policy(heldMembershipPolicy());
 for(const who of [p.owner,p.editor]) {
  const pendingAdd=await add(who,g.first,p.worker,'held-add-'+who.sub);
  assert.equal(pendingAdd.resultType,'input_required');assert.equal(await present(g.first,p.worker),false);
  assert.equal((await f.approve(who,pendingAdd)).approval.state,'executed');assert.equal(await present(g.first,p.worker),true);
  const pendingRemove=await remove(who,g.first,p.worker,'held-remove-'+who.sub);
  assert.equal(pendingRemove.resultType,'input_required');assert.equal(await present(g.first,p.worker),true);
  assert.equal((await f.approve(who,pendingRemove)).approval.state,'executed');assert.equal(await present(g.first,p.worker),false);
 }
 for(const [who,group,person] of [[p.reader,g.first,p.worker],[p.editor,g.outside,p.worker],[p.editor,g.first,p.outside]]) {
  const before=await f.members(),answer=await add(who,group,person,'held-refused-'+who.sub+group.id+person.id);
  assert.equal(answer.isError,true);assert.equal(answer.structuredContent,undefined);assert.equal(answer._meta['com.runeditrun/approval'],undefined);
  assert.deepEqual(await f.members(),before);
  await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:group.id,personId:person.id});
  const seeded=await f.members(),refusal=await remove(who,group,person,'held-refused-remove-'+who.sub+group.id+person.id);
  assert.equal(refusal.isError,true);assert.equal(refusal._meta['com.runeditrun/approval'],undefined);
  assert.deepEqual(await f.members(),seeded);
  await f.post(p.owner,'/api/auth/roles/group',{action:'remove',groupId:group.id,personId:person.id});
 }
 assert.equal((await add(p.editor,g.first,p.editor,'held-self-widen'))._meta['com.runeditrun/error'].code,'self_escalation');
 assert.equal(await present(g.first,p.editor),false);
 await f.policy();
 done(await add(p.editor,g.first,p.worker,'saved-add'));
 done(await remove(p.editor,g.first,p.worker,'saved-remove'));
 done(await add(p.editor,g.first,p.worker,'saved-add-again'));
 // Keep reads and the independently granted second group while revoking only
 // the first group's edit authority. An old receipt is no longer authority.
 await f.change({kind:'revoke',grantId:f.grants.first.id});
 done(await f.call(p.editor,'auth.groups.inspect',{id:g.first.id}));
 refused(await add(p.editor,g.first,p.worker,'saved-add-again'));
 refused(await remove(p.editor,g.first,p.worker,'saved-remove'));
 assert.equal(await present(g.first,p.worker),true);
 done(await add(p.editor,g.second,p.other,'second-still-authorized'));
 assert.equal(await present(g.second,p.other),true);
 // Held policy cannot turn a read-only sponsor into a preparer or recover lost
 // authority at approval. Existing native permission is checked before holding.
 await f.policy(heldMembershipPolicy());
 refused(await add(p.reader,g.second,p.other,'reader-held'));
 const pending=await remove(p.editor,g.second,p.other,'held-remove');
 assert.equal(pending.resultType,'input_required');assert.equal(await present(g.second,p.other),true);
 await f.change({kind:'revoke',grantId:f.grants.second.id});
 const approval=await f.approve(p.editor,pending);
 assert.equal(approval.approval.state,'refused');assert.equal(await present(g.second,p.other),true);
 await f.app.pause();await f.app.resume();
 refused(await remove(p.editor,g.second,p.other,'held-remove'));
 refused(await add(p.editor,g.first,p.worker,'saved-add-again'));
 assert.equal((await f.get(p.editor,'/agents/api/approvals/'+pending._meta['com.runeditrun/approval'].id)).approval.state,'refused');
 assert.equal(await present(g.first,p.worker),true);assert.equal(await present(g.second,p.other),true);
 await f.post(p.owner,'/api/auth/people/suspend',{personId:p.editor.id});
 assert.equal((await add(p.editor,g.first,p.worker,'after-suspension')).status,401);
 await f.app.pause();await f.app.resume();
 assert.equal((await add(p.editor,g.second,p.other,'after-restart-suspension')).status,401);
});
