import {one,all,fail} from '../core.mjs';
import {requireOwnerPermission} from './scoped-authority.mjs';
export function requireScope(principal,scope) {if(!principal.scopes.includes(scope))fail('admin_service_scope_required',403);}
export function requireResource(principal,kind,id) {if(!principal.permits(kind,id))fail('admin_service_resource_refused',403);}
export function only(data,keys) {
 if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(k=>!keys.includes(k)))fail('admin_service_action_excluded',403);
}
export async function groupPeople(ctx,principal,id) {
 const rows=await all(ctx,'SELECT person_id FROM auth_group_members WHERE group_id=?',id);
 return [...new Set([...rows.map(r=>r.person_id),...[...principal.ownerState.memberships].filter(([,groups])=>groups.has(id)).map(([person])=>person)])];
}
export async function assignmentEffects(ctx,principal,appId,type,id,permission='apps.assign') {
 requireResource(principal,'apps',appId);requireResource(principal,type==='person'?'people':'groups',id);
 requireOwnerPermission(principal,permission,{appId,[type==='person'?'personId':'groupId']:id,write:true});
 if(type==='group')for(const personId of await groupPeople(ctx,principal,id)) {
  requireResource(principal,'people',personId);
  requireOwnerPermission(principal,permission,{appId,groupId:id,personId,write:true});
 }
}
// Composite effects check the same published permission with every affected
// app/group/person, never an unqualified union of the owner's resource grants.
export async function groupEffects(ctx,principal,id,permission='groups.edit') {
 requireResource(principal,'groups',id);requireOwnerPermission(principal,permission,{groupId:id,write:true});
 for(const personId of await groupPeople(ctx,principal,id)) {
  requireResource(principal,'people',personId);requireOwnerPermission(principal,permission,{groupId:id,personId,write:true});
 }
 for(const row of await all(ctx,"SELECT app_id FROM auth_app_assignments WHERE principal_type='group' AND principal_id=?",id)) {
  requireResource(principal,'apps',row.app_id);requireOwnerPermission(principal,permission,{groupId:id,appId:row.app_id,write:true});
 }
}
export async function personEffects(ctx,principal,id,permissions=['people.profile.edit']) {
 requireResource(principal,'people',id);
 const p=await one(ctx,'SELECT role FROM oa_operators WHERE id=?',id)||fail('person_not_found',404);
 if(p.role!=='member')fail('admin_service_privileged_person_excluded',403);
 for(const permission of permissions)requireOwnerPermission(principal,permission,{personId:id,write:true});
 for(const row of await all(ctx,"SELECT a.app_id FROM auth_app_assignments a WHERE (a.principal_type='person' AND a.principal_id=?) OR (a.principal_type='group' AND a.principal_id IN (SELECT group_id FROM auth_group_members WHERE person_id=?))",id,id)) {
  requireResource(principal,'apps',row.app_id);
  for(const permission of permissions)requireOwnerPermission(principal,permission,{personId:id,appId:row.app_id,write:true});
 }
 for(const groupId of new Set([...(principal.ownerState.memberships.get(id)??[]),...(await all(ctx,'SELECT group_id FROM auth_group_members WHERE person_id=?',id)).map(r=>r.group_id)])) {
  requireResource(principal,'groups',groupId);
  for(const permission of permissions)requireOwnerPermission(principal,permission,{personId:id,groupId,write:true});
 }
}
export function planResources(principal,plan,permission='people.profile.edit') {
 for(const e of plan.entries) {
  requireResource(principal,'people',e.personId);
  for(const g of [...e.groups.added,...e.groups.removed]){requireResource(principal,'groups',g.id);requireOwnerPermission(principal,permission,{personId:e.personId,groupId:g.id,write:true});}
  for(const a of [...e.apps.gained,...e.apps.lost,...e.apps.roleChanged]){requireResource(principal,'apps',a.appId);requireOwnerPermission(principal,permission,{personId:e.personId,appId:a.appId,write:true});}
 }
}
