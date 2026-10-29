import {AuthError,one,fail,hash,auditDetail} from '../auth/core.mjs';
import {ownerState,ownerPermits,ownerSnapshotGuard} from '../auth/admin-api/scoped-authority.mjs';
import {readAdmin} from '../auth/admin-api/reads.mjs';
import {writeAdmin} from '../auth/admin-api/commands.mjs';
import {epoch,transactionPrincipal} from '../auth/admin-api/concurrency.mjs';
import {ToolRefusal} from '../modules/agent-door/index.ts';

// This is a native machine principal, never an invented person or session. The
// same command, rank, field ownership and role/resource fences serve REST/UI.
export async function principal(native,ctx,scopes) {
 const state=await ownerState(native,ctx.person.id),guard=ownerSnapshotGuard(state);
 const assertAuthority=async()=>{if(!await one(native,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail('role_authority_changed',409);};
 return {kind:'service',id:ctx.agent.id,actorId:ctx.actor?.label??`${ctx.agent.name} for ${ctx.person.name}`,ownerId:ctx.person.id,
  ownerState:state,guard,scopes,resources:{people:['*'],groups:['*'],apps:['*']},revision:state.epoch,
  permits:()=>true,ownerAllows:(permission,target)=>ownerPermits(state,permission,target),
  assertAuthority,prepareAuthority:assertAuthority};
}
export async function read(native,ctx,path,scope,query={}) {
 try {
  const actor=await principal(native,ctx,[scope]);
  const url=new URL(native.origin+'/api/auth/admin/v1'+path);
  for(const [key,value] of Object.entries(query))if(value!==undefined)url.searchParams.set(key,String(value));
  const response=await readAdmin(native,actor,path,url);
  if(!response||!response.ok)throw new ToolRefusal('resource_unavailable');
  const value=await response.json();
  if(path==='/people'||path.startsWith('/people/')) {
   const project=({id,email,name,state})=>({id,email,name,state});
   return Array.isArray(value.items)?{...value,items:value.items.map(project)}:project(value);
  }
  return value;
 }catch(error){if(error instanceof AuthError)throw new ToolRefusal('resource_unavailable');throw error;}
}
export async function write(native,ctx,path,method,data,scope) {
 try {
  const actor=await principal(native,ctx,[scope]);
  const tx=transactionPrincipal(native,actor,await epoch(native));
  const response=await writeAdmin(native,tx,path,method,data);
  if(!response.ok)throw new ToolRefusal('native_refused');
  const result=await response.json();
  await auditDetail(native,actor.actorId,'agent_door_effect',result.id??data.id??path,{agent:ctx.agent.id,sponsor:ctx.person.id,operationId:ctx.operationId,approvers:ctx.approvers.map(p=>({id:p.id,name:p.name})),path});
  return result;
 }catch(error){if(error instanceof AuthError)throw new ToolRefusal(error.message);throw error;}
}
export async function snapshot(native,ctx) {
 const out={};
 async function collection(path,scope) {
  const items=[];let offset=0;
  do {
   const value=await read(native,ctx,path,scope,{limit:100,offset});
   items.push(...value.items);offset=value.nextOffset;
  }while(offset!==null);
  return items;
 }
 for(const [family,scope] of [['people','people.read'],['groups','groups.read'],['apps','apps.read'],['assignments','assignments.read']]) {
  const items=await collection('/'+family,scope);
  if(family==='groups')for(const group of items)group.members=await collection('/groups/'+encodeURIComponent(group.id)+'/members','groups.read');
  out[family]=await hash(JSON.stringify(items));
 }
 return out;
}
export async function group(native,ctx,id) {return read(native,ctx,'/groups/'+encodeURIComponent(id),'groups.read');}
export async function membership(native,ctx,id) {
 const [groupId,personId,...extra]=String(id).split('/');
 if(!groupId||!personId||extra.length)throw new ToolRefusal('resource_unavailable');
 await group(native,ctx,groupId);
 await read(native,ctx,'/people/'+encodeURIComponent(personId),'people.read');
 return {groupId,personId,present:Boolean(await one(native,'SELECT 1 FROM auth_group_members WHERE group_id=? AND person_id=?',groupId,personId))};
}
// Group edits touching an external connector belong to a later provider-edge
// family. Refuse before classification/preparation rather than enqueueing work.
export async function internalGroup(native,ctx,id) {
 await group(native,ctx,id);
 if(await one(native,"SELECT 1 FROM auth_app_assignments a JOIN auth_scim_connectors c ON c.app_id=a.app_id WHERE a.principal_type='group' AND a.principal_id=?",id))throw new ToolRefusal('connector_door_required');
}

export async function nativeAdmission(native,p) {
 const {domainPermitted}=await import('../auth/domains/ownership.mjs');
 const {invitationAdmitted}=await import('../auth/tenancy/routes.mjs');
 return Boolean(await invitationAdmitted(native,p)&&await domainPermitted(native,p));
}
export async function nativeLauncher(native,id) {
 const {launcher}=await import('../auth/launcher/index.mjs');return launcher(native,id);
}
