import {test} from 'node:test';
import assert from 'node:assert/strict';
import {authorityFixture,heldMembershipPolicy} from './authority-fixture.mjs';

test('native membership authority survives cached success, held execution and restart without widening',{timeout:180000},async t=>{
 const f=await authorityFixture(t),{people:p,groups:g}=f;
 await f.policy();
 const establishedEditor=await f.client(p.editor);
 const add=(who,group,person,key)=>f.call(who,'auth.groups.add',{group_id:group.id,person_id:person.id,idempotency_key:key});
 const remove=(who,group,person,key)=>f.call(who,'auth.groups.remove',{id:group.id+'/'+person.id,idempotency_key:key});
 const done=result=>{assert.equal(result.status,200);assert.equal(result.isError,false,JSON.stringify(result));};
 const refused=result=>{assert.equal(result.status,200);assert.equal(result.isError,true,JSON.stringify(result));assert.equal(result.structuredContent,undefined);assert.equal(result._meta['com.runeditrun/error'].code,'admin_service_owner_permission_required');};
 const present=async(group,person)=>Boolean((await f.members()).find(x=>x.id===group.id).members.some(x=>x.id===person.id));
 // The native person scope also follows group membership. Keep the outside
 // target in a non-editable group so adding it elsewhere cannot make the
 // subsequent removal an authorized action under the all-groups rule.
 await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:g.outside.id,personId:p.outside.id});
 // Native rank fences protect account administration. Ordinary membership
 // edits remain authorized by their published verb and resource scope even
 // when the target holds a higher-ranked role than the group editor.
 const ranked=await f.change({kind:'grant',personId:p.worker.id,roleId:'security-policy-administrator',resources:{view:{people:[p.worker.id],groups:[g.first.id]},edit:{}}});
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
 await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:g.first.id,personId:p.editor.id});
 done(await add(p.editor,g.first,p.editor,'inert-self-add'));
 done(await remove(p.editor,g.first,p.editor,'self-narrow'));
 assert.equal((await add(p.editor,g.first,p.editor,'inert-self-add'))._meta['com.runeditrun/error'].code,'self_escalation');
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
 await f.change({kind:'revoke',grantId:ranked.id});
 // Moving the target into a group outside the edit scope ends authority even
 // though the editor's grants and its read access have not changed.
 await f.policy();
 done(await add(p.editor,g.first,p.worker,'before-person-move-add'));
 done(await remove(p.editor,g.first,p.worker,'before-person-move-remove'));
 done(await add(p.editor,g.first,p.worker,'before-person-move-add-again'));
 await f.policy(heldMembershipPolicy());
 const movedPending=await remove(p.editor,g.first,p.worker,'before-person-move-held');
 assert.equal(movedPending.resultType,'input_required');
 await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:g.outside.id,personId:p.worker.id});
 for(const held of [false,true]) {
  await f.policy(held?heldMembershipPolicy():undefined);
  for(const action of ['add','remove'])assert.equal((await p.editor.call('/api/auth/roles/group',{action,groupId:g.first.id,personId:p.worker.id})).status,403);
  done(await f.call(p.editor,'auth.identity.inspect',{id:p.worker.id}));
  refused(await add(p.editor,g.first,p.worker,'before-person-move-add-again'));
  refused(await remove(p.editor,g.first,p.worker,'before-person-move-remove'));
  const separate=await add(p.editor,g.second,p.other,'unmoved-person-'+held);
  if(held)assert.equal((await f.approve(p.editor,separate)).approval.state,'executed');else done(separate);
  assert.equal(await present(g.second,p.other),true);
  await f.post(p.owner,'/api/auth/roles/group',{action:'remove',groupId:g.second.id,personId:p.other.id});
 }
 assert.equal((await f.approve(p.editor,movedPending)).approval.state,'refused');
 assert.equal(await present(g.first,p.worker),true);
 await f.app.pause();await f.app.resume();
 refused(await add(p.editor,g.first,p.worker,'before-person-move-add-again'));
 assert.equal((await f.get(p.editor,'/agents/api/approvals/'+movedPending._meta['com.runeditrun/approval'].id)).approval.state,'refused');
 await f.post(p.owner,'/api/auth/roles/group',{action:'remove',groupId:g.outside.id,personId:p.worker.id});
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
 refused(await establishedEditor('auth.groups.add',{group_id:g.first.id,person_id:p.worker.id,idempotency_key:'saved-add-again'}));
 assert.equal(await present(g.first,p.worker),true);
 done(await add(p.editor,g.second,p.other,'second-still-authorized'));
 assert.equal(await present(g.second,p.other),true);
 // A role revision may remove the verb without revoking its resource grant.
 // A replacement read-only grant cannot turn a saved receipt into permission.
 const role=await f.change({kind:'role',role:{name:'Synthetic membership editor',rank:20,permissions:['roles.view','people.view','groups.view','groups.edit']}});
 const resources={view:{people:[p.worker.id,p.editor.id],groups:[g.first.id]},edit:{people:[p.worker.id,p.editor.id],groups:[g.first.id]}};
 await f.change({kind:'grant',personId:p.editor.id,roleId:role.role.id,resources});
 await f.policy();
 done(await remove(p.editor,g.first,p.worker,'before-permission-loss-remove'));
 done(await add(p.editor,g.first,p.worker,'before-permission-loss-add'));
 await f.policy(heldMembershipPolicy());
 const permissionPendingRemove=await remove(p.editor,g.first,p.worker,'permission-held-remove');
 assert.equal(permissionPendingRemove.resultType,'input_required');
 await f.post(p.owner,'/api/auth/roles/group',{action:'remove',groupId:g.first.id,personId:p.worker.id});
 const permissionPendingAdd=await add(p.editor,g.first,p.worker,'permission-held-add');
 assert.equal(permissionPendingAdd.resultType,'input_required');
 await f.post(p.owner,'/api/auth/roles/group',{action:'add',groupId:g.first.id,personId:p.worker.id});
 await f.change({kind:'role',role:{...role.role,permissions:['roles.view','people.view','groups.view']}});
 await f.change({kind:'grant',personId:p.editor.id,roleId:role.role.id,resources});
 for(const held of [false,true]) {
  await f.policy(held?heldMembershipPolicy():undefined);
  done(await f.call(p.editor,'auth.groups.inspect',{id:g.first.id}));
  for(const action of ['add','remove'])assert.equal((await p.editor.call('/api/auth/roles/group',{action,groupId:g.first.id,personId:p.worker.id})).status,403);
  refused(await add(p.editor,g.first,p.worker,'before-permission-loss-add'));
  refused(await remove(p.editor,g.first,p.worker,'before-permission-loss-remove'));
 }
 for(const pending of [permissionPendingAdd,permissionPendingRemove])assert.equal((await f.approve(p.editor,pending)).approval.state,'refused');
 assert.equal(await present(g.first,p.worker),true);
 await f.app.pause();await f.app.resume();
 refused(await remove(p.editor,g.first,p.worker,'before-permission-loss-remove'));
 for(const pending of [permissionPendingAdd,permissionPendingRemove])assert.equal((await f.get(p.editor,'/agents/api/approvals/'+pending._meta['com.runeditrun/approval'].id)).approval.state,'refused');
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
 assert.equal((await establishedEditor('auth.groups.inspect',{id:g.first.id})).status,401);
 assert.equal((await establishedEditor('auth.groups.add',{group_id:g.first.id,person_id:p.worker.id,idempotency_key:'saved-add-again'})).status,401);
 assert.equal((await add(p.editor,g.first,p.worker,'after-suspension')).status,401);
 await f.app.pause();await f.app.resume();
 assert.equal((await establishedEditor('auth.groups.remove',{id:g.second.id+'/'+p.other.id,idempotency_key:'held-remove'})).status,401);
 assert.equal((await add(p.editor,g.second,p.other,'after-restart-suspension')).status,401);
});
