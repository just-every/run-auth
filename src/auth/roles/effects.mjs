import {PERMISSIONS,LEGACY_RANK,BUILTINS,ALL_RESOURCES,permissionKind,writePermission} from './permissions.mjs';
import {permitted} from './policy.mjs';

// Calculate effective action changes, accounting for overlapping grants and
// transitive sponsors. Resource ids are current local resources, not labels.
export function planEffects(state,plan) {
 const removed=new Set();
 if(plan.kind==='role')for(const g of state.activeGrants)if(g.role_id===plan.role.id)removed.add(g.id);
 if(plan.kind==='revoke')removed.add(plan.grantId);
 let changed=true;
 while(changed){changed=false;for(const g of state.activeGrants)if(g.sponsor_grant_id&&removed.has(g.sponsor_grant_id)&&!removed.has(g.id)){removed.add(g.id);changed=true;}}
 const after=state.activeGrants.filter(g=>!removed.has(g.id));
 if(plan.kind==='grant')after.push({id:plan.id,person_id:plan.personId,role:plan.role,resources:plan.resources});
 // Changing a target's rank can also change another administrator's ability
 // to act on that target. Include every current scoped holder in the diff.
 const affected=new Set(state.activeGrants.map(g=>g.person_id));
 if(plan.kind==='grant')affected.add(plan.personId);
 const view=(personId,grants)=>{
  const person=state.dir.people.get(personId),legacy=['owner','admin'].includes(person.role);
  const rankOf=id=>Math.max(LEGACY_RANK[state.dir.people.get(id)?.role]??0,...grants.filter(g=>g.person_id===id).map(g=>g.role.rank));
  return {...state,person,legacy,entries:legacy?[{role:{rank:LEGACY_RANK[person.role],permissions:BUILTINS[0].permissions},resources:ALL_RESOURCES}]:grants.filter(g=>g.person_id===personId),rank:rankOf(personId),rankOf};
 };
 const actions=model=>{
  const found=new Map();
  for(const permission of Object.keys(PERMISSIONS)) {
   const kind=permissionKind(permission),write=permission==='audit.export'?false:writePermission(permission);
   const ids=kind==='people'?[...state.dir.people.keys()]:kind==='groups'?state.dir.groups.map(g=>g.id):kind==='apps'?state.apps.map(a=>a.id):kind==='cases'?state.cases.map(c=>c.id):[null];
   for(const id of ids) {
    const target={write,...(kind==='people'?{personId:id}:kind==='groups'?{groupId:id}:kind==='apps'?{appId:id}:kind==='cases'?{caseId:id}:{})};
    if(permission==='people.factors.reset'&&(model.rankOf(id)>0||state.dir.people.get(id)?.role!=='member'))continue;
    if(permitted(model,permission,target))found.set(permission+':'+(id??''),{permission,...(id===null?{}:{resourceKind:kind,resourceId:id})});
   }
  }
  return found;
 };
 return [...affected].sort().map(personId=>{
  const before=actions(view(personId,state.activeGrants)),now=actions(view(personId,after));
  return {personId,email:state.dir.people.get(personId).email,gained:[...now].filter(([k])=>!before.has(k)).map(([,a])=>a),lost:[...before].filter(([k])=>!now.has(k)).map(([,a])=>a)};
 }).filter(effect=>effect.gained.length||effect.lost.length);
}
