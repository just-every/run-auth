import {one,fail} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {roleState} from './state.mjs';
import {accountPermission,lowerAccountRank} from '../ranks.mjs';
import {contains,writePermission,permissionKind} from './permissions.mjs';

export function personInScope(state,scope,id,write=false) {
 const groups=state.memberships.get(id);
 if(!groups)return false;
 const held=contains(scope.people,id)||[...groups].some(g=>contains(scope.groups,g));
 return held&&(!write||[...groups].every(g=>contains(scope.groups,g)));
}
function permissionAllowed(state,permission,target,checkRank) {
 const write=permission==='people.export'||(target.write??writePermission(permission)),kind=permissionKind(permission),mode=write?'edit':'view';
 const personId=target.personId??(accountPermission(permission)&&target.caseId?state.cases.find(c=>c.id===target.caseId)?.person_id:null);
 return state.entries.some(entry=>{
  if(!entry.role.permissions.includes(permission))return false;
  const scope=entry.resources[mode];
  if(target.personId&&!personInScope(state,scope,target.personId,write))return false;
  if(target.groupId&&!contains(scope.groups,target.groupId))return false;
  if(target.appId&&!contains(scope.apps,target.appId))return false;
  if(target.caseId&&!contains(scope.cases,target.caseId))return false;
  if(kind&&!target.personId&&!target.groupId&&!target.appId&&!target.caseId)return Object.values(scope).some(ids=>ids.length);
  // Rank follows permission and scope, and only fences administration of an
  // account. Group membership and app assignments are ordinary decisions.
  if(checkRank&&personId&&accountPermission(permission)&&!lowerAccountRank(state,personId))return false;
  return true;
 });
}
export const permitted=(state,permission,target={})=>permissionAllowed(state,permission,target,true);
// Machine adapters check actual permission/scope before reporting the separate
// account-rank fence. This predicate grants no committing authority by itself.
export const permittedWithinScope=(state,permission,target={})=>permissionAllowed(state,permission,target,false);
export function assertPermission(state,permission,target={}) {
 if(!permitted(state,permission,target))fail('role_permission_required',403);
}
export function roleGuard(ctx,s,state) {
 const local=authority(ctx,s,[state.person.role]);
 return {clause:`${local.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,args:[...local.args,state.epoch]};
}
// Read snapshots retain the same live session and role-epoch fences, without
// the independent local-email freshness required by every committing write.
export function roleReadGuard(ctx,s,state) {
 return {clause:`EXISTS(SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1 WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=? AND a.person_version=p.version AND p.role=? AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?)`,args:[s.id,s.person_id,s.amr,s.person_version,state.person.role,ctx.now(),state.epoch]};
}
export async function assertReadAuthority(ctx,s,state) {
 await assertGuard(ctx,roleReadGuard(ctx,s,state));
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
 const guard=write?roleGuard(ctx,s,state):roleReadGuard(ctx,s,state);
 // Public callers append this guard to the committing SQL; merely calling this
 // function is not sufficient to protect a subsequent unguarded mutation.
 return {...guard,state};
}
export async function assertGuard(ctx,guard) {
 if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail('role_authority_changed',409);
}
