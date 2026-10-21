import {one,all,fail} from '../core.mjs';
export function requireScope(principal,scope) {if(!principal.scopes.includes(scope))fail('admin_service_scope_required',403);}
export function requireResource(principal,kind,id) {if(!principal.permits(kind,id))fail('admin_service_resource_refused',403);}
export function only(data,keys) {
 if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(k=>!keys.includes(k)))fail('admin_service_action_excluded',403);
}
// A group's edit can change assigned apps and people's access. A narrowed grant
// must cover those resources as well, even when the direct target is a group.
export async function groupEffects(ctx,principal,id) {
 requireResource(principal,'groups',id);
 for(const row of await all(ctx,'SELECT person_id FROM auth_group_members WHERE group_id=?',id))requireResource(principal,'people',row.person_id);
 for(const row of await all(ctx,"SELECT app_id FROM auth_app_assignments WHERE principal_type='group' AND principal_id=?",id))requireResource(principal,'apps',row.app_id);
}
export async function personEffects(ctx,principal,id) {
 requireResource(principal,'people',id);
 const p=await one(ctx,'SELECT role FROM oa_operators WHERE id=?',id)||fail('person_not_found',404);
 if(p.role!=='member')fail('admin_service_privileged_person_excluded',403);
 for(const row of await all(ctx,"SELECT a.app_id FROM auth_app_assignments a WHERE (a.principal_type='person' AND a.principal_id=?) OR (a.principal_type='group' AND a.principal_id IN (SELECT group_id FROM auth_group_members WHERE person_id=?))",id,id))requireResource(principal,'apps',row.app_id);
 for(const row of await all(ctx,'SELECT group_id FROM auth_group_members WHERE person_id=?',id))requireResource(principal,'groups',row.group_id);
}
export function planResources(principal,plan) {
 for(const e of plan.entries) {
  requireResource(principal,'people',e.personId);
  for(const g of [...e.groups.added,...e.groups.removed])requireResource(principal,'groups',g.id);
  for(const a of [...e.apps.gained,...e.apps.lost,...e.apps.roleChanged])requireResource(principal,'apps',a.appId);
 }
}
