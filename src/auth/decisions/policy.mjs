import {one,all,fail,hash} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {requireHardware,assertPermission,roleGuard} from '../roles/policy.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {requestTarget} from '../requests/index.mjs';
import {reviewTarget} from '../reviews/items.mjs';

export async function privilegedGroup(ctx,id) {
 return Boolean(await one(ctx,`SELECT 1 WHERE EXISTS(SELECT 1 FROM auth_privileged_resources p WHERE p.kind='group' AND p.target_id=? AND p.privileged=1)
 OR EXISTS(SELECT 1 FROM auth_app_assignments a LEFT JOIN auth_privileged_resources p ON p.kind='app' AND p.target_id=a.app_id WHERE a.principal_type='group' AND a.principal_id=? AND COALESCE(p.privileged,1)=1)`,id,id));
}
export function employeeGuard(ctx,s,epoch) {
 return {clause:`EXISTS(SELECT 1 FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id WHERE s.id=? AND s.person_id=? AND s.amr=? AND s.person_version=? AND p.version=s.person_version AND p.status='active' AND s.revoked_at IS NULL AND s.expires_at>?) AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,args:[s.id,s.person_id,s.amr,s.person_version,ctx.now(),epoch]};
}
export async function decisionTarget(ctx,s,data) {
 const kind=String(data.kind??''),targetId=String(data.targetId??''),operation=String(data.operation??''),reason=String(data.reason??'').trim();
 if(!reason||reason.length>500)fail('decision_reason_required');
 const state=await roleState(ctx,s);let snapshot,personId=null,privileged=false;
 if(kind==='group') {
  if(!['add','remove'].includes(operation))fail('invalid_group_decision');
  const group=await one(ctx,'SELECT * FROM auth_groups WHERE id=?',targetId)??fail('group_not_found',404);
  const owns=await one(ctx,'SELECT 1 FROM auth_group_owners WHERE group_id=? AND person_id=?',targetId,s.person_id);
  if(!owns)assertPermission(state,'groups.edit',{groupId:targetId,write:true});
  personId=String(data.personId??'');
  const person=await one(ctx,"SELECT id,email,status,version FROM oa_operators WHERE (id=? OR email=?) AND status='active'",personId,personId.toLowerCase())??fail('person_not_found',404);
  personId=person.id;
  if(operation==='add'&&personId===s.person_id)fail('self_approval_refused',403);
  privileged=await privilegedGroup(ctx,targetId);
  if(!owns)assertPermission(state,'groups.edit',{groupId:targetId,personId,write:true});
  const member=await one(ctx,'SELECT * FROM auth_group_members WHERE group_id=? AND person_id=?',targetId,personId);
  const excluded=await one(ctx,'SELECT * FROM auth_group_exclusions WHERE group_id=? AND person_id=?',targetId,personId);
  snapshot={group,person,member,excluded};
 } else if(kind==='request') {
  const target=await requestTarget(ctx,s,{targetId,operation});
  snapshot=target.snapshot;personId=target.personId;privileged=target.privileged;
 } else if(kind==='review') {
  const target=await reviewTarget(ctx,s,{targetId,operation,newRole:data.newRole});
  snapshot=target.snapshot;personId=target.personId;privileged=target.privileged;
 } else fail('decision_kind_not_available',400);
 // Ordinary relationship roles carry rank zero. A real administrator holding
 // the same relationship still uses the administrator gate for every write.
 const admin=state.rank>0||state.entries.some(e=>e.role.rank>0)||privileged;
 let guard=employeeGuard(ctx,s,state.epoch);
 if(admin) {
  requireHardware(s);requireLocalEmail(ctx,s);
  if(privileged&&kind==='group')assertPermission(state,'groups.edit',{groupId:targetId,personId,write:true});
  if(privileged&&kind==='request')assertPermission(state,'apps.assign',{appId:snapshot.request.app_id,personId,write:true});
  guard=roleGuard(ctx,s,state);
 }
 if(!JSON.parse(s.amr).some(m=>['hwk','passkey'].includes(m)))fail('employee_passkey_required',403);
 const canonical={kind,targetId,operation,personId,reason,...(snapshot.reduction?{newRole:snapshot.reduction.newRole}:{})};
 return {...canonical,privileged,guard,epoch:state.epoch,digest:await hash(JSON.stringify(snapshot)),snapshot};
}
export async function decisionsModel(ctx,s) {
 const state=await roleState(ctx,s),canManage=state.legacy,owned=new Set((await all(ctx,'SELECT group_id FROM auth_group_owners WHERE person_id=?',s.person_id)).map(g=>g.group_id));
 const groups=[];
 for(const g of state.dir.groups)if(canManage||owned.has(g.id))groups.push({id:g.id,name:g.name,owner:owned.has(g.id),privileged:await privilegedGroup(ctx,g.id),members:[...state.memberships].filter(([,ids])=>ids.has(g.id)).map(([id])=>({id,email:state.dir.people.get(id)?.email,name:state.dir.people.get(id)?.name}))});
 const visible=new Set(groups.flatMap(g=>g.members.map(p=>p.id)));
 const people=groups.length?[...state.dir.people.values()].filter(p=>p.status==='active'&&(canManage||visible.has(p.id))).map(p=>({id:p.id,email:p.email,name:p.name})):[];
 const apps=canManage?await all(ctx,"SELECT a.id,a.name,COALESCE((SELECT p.privileged FROM auth_privileged_resources p WHERE p.kind='app' AND p.target_id=a.id),1) AS privileged FROM auth_apps a WHERE a.disabled_at IS NULL"):[];
 return {groups,people,apps:apps.map(a=>({...a,privileged:Boolean(a.privileged)})),canManage};
}
