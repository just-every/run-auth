import {one,random,fail,json} from '../core.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {roleState} from './state.mjs';
import {assertPermission,personInScope,roleGuard,requireHardware} from './policy.mjs';
import {customRole,resources,RESOURCE_KINDS,subset,contains} from './permissions.mjs';
import {commit} from './commit.mjs';
import {planEffects} from './effects.mjs';

function validateResources(state,scope) {
 const catalogs={people:new Set(state.dir.people.keys()),groups:new Set(state.dir.groups.map(g=>g.id)),apps:new Set(state.apps.map(a=>a.id)),cases:new Set(state.cases.map(c=>c.id))};
 for(const mode of ['view','edit'])for(const kind of RESOURCE_KINDS)for(const id of scope[mode][kind])if(id!=='*'&&!catalogs[kind].has(id))fail('role_resource_not_found',404);
}
function sponsorFor(state,role,scope) {
 return state.entries.find(entry=>entry.role.permissions.includes('roles.grant')&&entry.role.rank>role.rank&&role.permissions.every(p=>entry.role.permissions.includes(p))&&['view','edit'].every(m=>RESOURCE_KINDS.every(k=>subset(scope[m][k],entry.resources[m][k]))));
}
function editableTarget(state,personId) {
 const p=state.dir.people.get(personId);
 if(!p||p.status!=='active')fail('person_unavailable',404);
 if(personId===state.person.id||state.rankOf(personId)>=state.rank)fail('lower_rank_required',403);
 // A grant's cases/apps may be delegated without granting directory access.
 // Its recipient must have no membership outside the issuer's edit groups.
 // Ungrouped recipients can receive app/case-only delegation.
 const entries=state.entries.filter(e=>e.role.permissions.includes('roles.grant'));
 if(!entries.some(e=>personInScope(state,e.resources.edit,personId,true)||[...(state.memberships.get(personId)??[])].every(g=>contains(e.resources.edit.groups,g))))fail('role_recipient_outside_scope',403);
}
export function planChange(state,s,data,{newId=random()}={}) {
 const kind=data.kind;
 if(kind==='role') {
  assertPermission(state,'roles.edit');
  if(!state.canDesignRoles)fail('owner_admin_required',403);
  const id=data.role?.id||newId,held=state.roles.get(id);
  if(held?.builtin)fail('builtin_role_fixed',403);
  for(const grant of state.grants.filter(g=>g.role_id===id&&g.revoked_at===null))if(grant.person_id===state.person.id||state.rankOf(grant.person_id)>=state.rank)fail('lower_rank_required',403);
  const role=customRole(data.role,id);
  if(role.rank>=state.rank)fail('lower_rank_required',403);
  if(!state.entries.some(e=>role.permissions.every(p=>e.role.permissions.includes(p))))fail('role_permissions_wider_than_holder',403);
  return {kind,role:{...role,revision:(held?.revision??0)+1},before:held??null};
 }
 assertPermission(state,'roles.grant');
 if(kind==='grant') {
  const personId=String(data.personId??''),role=state.roles.get(data.roleId)??fail('role_not_found',404),scope=resources(data.resources);
  editableTarget(state,personId);validateResources(state,scope);
  const sponsor=sponsorFor(state,role,scope);
  if(!sponsor)fail('role_grant_wider_than_holder',403);
  return {kind,id:newId,personId,roleId:role.id,roleRevision:role.revision,resources:scope,sponsorGrantId:sponsor.id,role};
 }
 if(kind==='revoke') {
  const grant=state.grants.find(g=>g.id===data.grantId)??fail('role_grant_not_found',404);
  if(grant.revoked_at!==null)fail('role_grant_revoked',409);
  editableTarget(state,grant.person_id);
  const role=state.roles.get(grant.role_id)??fail('role_not_found',404),scope=JSON.parse(grant.resources);
  if(!sponsorFor(state,role,scope))fail('role_grant_wider_than_holder',403);
  return {kind,grantId:grant.id,before:grant};
 }
 fail('invalid_role_change');
}
export async function preview(ctx,s,data) {
 requireHardware(s);requireLocalEmail(ctx,s);
 const state=await roleState(ctx,s),plan=planChange(state,s,data),id=random(),guard=roleGuard(ctx,s,state),expiresAt=ctx.now()+600000;
 plan.effects=planEffects(state,plan);
 await commit(ctx,s,guard,'roles.preview',plan.personId??plan.role?.id??plan.grantId,{previewId:id,epoch:state.epoch,plan},(g,p)=>[
  p(`INSERT INTO auth_role_previews(id,actor_id,session_id,epoch,plan,created_at,expires_at) SELECT ?,?,?,?,?,?,? WHERE ${g.clause}`,id,s.person_id,s.id,state.epoch,JSON.stringify(plan),ctx.now(),expiresAt,...g.args),
 ]);
 return json({previewId:id,expiresAt,epoch:state.epoch,plan});
}
export async function apply(ctx,s,data) {
 requireHardware(s);requireLocalEmail(ctx,s);
 const saved=await one(ctx,'SELECT * FROM auth_role_previews WHERE id=? AND actor_id=? AND session_id=? AND consumed_at IS NULL AND expires_at>?',String(data.previewId??''),s.person_id,s.id,ctx.now());
 if(!saved)fail('role_preview_required',409);
 const state=await roleState(ctx,s);
 if(state.epoch!==saved.epoch)fail('role_preview_changed',409);
 const plan=JSON.parse(saved.plan),raw=plan.kind==='role'?{kind:'role',role:plan.role}:plan.kind==='grant'?{kind:'grant',personId:plan.personId,roleId:plan.roleId,resources:plan.resources}:{kind:'revoke',grantId:plan.grantId};
 const current=planChange(state,s,raw,{newId:plan.id??plan.role?.id});
 current.effects=planEffects(state,current);
 if(JSON.stringify(current)!==JSON.stringify(plan))fail('role_preview_changed',409);
 const live=roleGuard(ctx,s,state),guard={clause:`${live.clause} AND EXISTS(SELECT 1 FROM auth_role_previews WHERE id=? AND consumed_at IS NULL AND expires_at>?)`,args:[...live.args,saved.id,ctx.now()]};
 const result=await commit(ctx,s,guard,'roles.'+plan.kind,plan.personId??plan.role?.id??plan.grantId,{previewId:saved.id,epoch:saved.epoch,plan},(g,p)=>{
  const statements=[p(`UPDATE auth_role_previews SET consumed_at=? WHERE id=? AND ${g.clause}`,ctx.now(),saved.id,...g.args)];
  if(plan.kind==='role')statements.push(p(`INSERT INTO auth_roles(id,name,rank,permissions,revision,created_by,created_at,updated_at) SELECT ?,?,?,?,?,?,?,? WHERE ${g.clause} ON CONFLICT(id) DO UPDATE SET name=excluded.name,rank=excluded.rank,permissions=excluded.permissions,revision=excluded.revision,updated_at=excluded.updated_at`,plan.role.id,plan.role.name,plan.role.rank,JSON.stringify(plan.role.permissions),plan.role.revision,s.person_id,ctx.now(),ctx.now(),...g.args));
  if(plan.kind==='grant')statements.push(p(`INSERT INTO auth_role_grants(id,person_id,role_id,role_revision,resources,granted_by,sponsor_grant_id,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${g.clause}`,plan.id,plan.personId,plan.roleId,plan.roleRevision,JSON.stringify(plan.resources),s.person_id,plan.sponsorGrantId,ctx.now(),...g.args));
  if(plan.kind==='revoke')statements.push(p(`UPDATE auth_role_grants SET revoked_at=?,revoked_by=? WHERE id=? AND ${g.clause}`,ctx.now(),s.person_id,plan.grantId,...g.args));
  return statements;
 });
 return json({ok:true,...result,results:undefined,plan});
}
