import {one,fail} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {roleState} from './state.mjs';
import {contains,writePermission,permissionKind} from './permissions.mjs';

export function personInScope(state,scope,id,write=false) {
 const groups=state.memberships.get(id);
 if(!groups)return false;
 const held=contains(scope.people,id)||[...groups].some(g=>contains(scope.groups,g));
 return held&&(!write||[...groups].every(g=>contains(scope.groups,g)));
}
export function permitted(state,permission,target={}) {
 const write=target.write??writePermission(permission),kind=permissionKind(permission),mode=write?'edit':'view';
 if(write&&target.personId&&(target.personId===state.person.id||state.rankOf(target.personId)>=state.rank))return false;
 return state.entries.some(entry=>{
  if(!entry.role.permissions.includes(permission))return false;
  const scope=entry.resources[mode];
  if(target.personId&&!personInScope(state,scope,target.personId,write))return false;
  if(target.groupId&&!contains(scope.groups,target.groupId))return false;
  if(target.appId&&!contains(scope.apps,target.appId))return false;
  if(target.caseId&&!contains(scope.cases,target.caseId))return false;
  if(kind&&!target.personId&&!target.groupId&&!target.appId&&!target.caseId)return Object.values(scope).some(ids=>ids.length);
  return true;
 });
}
export function assertPermission(state,permission,target={}) {
 if(!permitted(state,permission,target))fail('role_permission_required',403);
}
export function roleGuard(ctx,s,state) {
 const local=authority(ctx,s,[state.person.role]);
 return {clause:`${local.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,args:[...local.args,state.epoch]};
}
export function requireHardware(s) {
 if(!JSON.parse(s.amr).includes('hwk'))fail('passkey_admin_required',403);
}
export async function requireRolePermission(ctx,s,permission,target={}) {
 requireHardware(s);
 const write=target.write??writePermission(permission);
 if(write)requireLocalEmail(ctx,s);
 const state=await roleState(ctx,s);
 assertPermission(state,permission,{...target,write});
 const guard=roleGuard(ctx,s,state);
 // Public callers append this guard to the committing SQL; merely calling this
 // function is not sufficient to protect a subsequent unguarded mutation.
 return {...guard,state};
}
export async function assertGuard(ctx,guard) {
 if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail('role_authority_changed',409);
}
