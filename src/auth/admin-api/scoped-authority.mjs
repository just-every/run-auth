import {fail} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {permitted,personInScope} from '../roles/policy.mjs';

// A machine scope is a transport vocabulary, never a replacement for the
// accountable human's published permissions or resource/rank decisions.
export const SCOPE_PERMISSIONS=Object.freeze({
 'people.read':['people.view'],
 'people.manage':['people.view','people.profile.edit','people.suspend','people.restore'],
 'groups.read':['groups.view','people.view'],
 'groups.manage':['groups.view','people.view','groups.edit','groups.rules.edit'],
 'apps.read':['apps.view'], 'apps.manage':['apps.view','apps.edit'],
 'assignments.read':['apps.view'], 'assignments.manage':['apps.view','apps.assign'],
 'policies.read':['policy.manage'], 'policies.manage':['policy.manage'],
 'idps.read':['identity-providers.manage'], 'idps.manage':['identity-providers.manage'],
 'domains.read':['policy.manage'], 'logs.read':['audit.view'],
});
const GLOBAL=new Set(['policies.read','policies.manage','idps.read','idps.manage','domains.read']);
const kinds=['people','groups','apps'];
const contains=(ids,id)=>ids.includes('*')||ids.includes(id);
export const readPermission=family=>({people:'people.view',groups:'groups.view',apps:'apps.view',assignments:'apps.view',policies:'policy.manage',idps:'identity-providers.manage',domains:'policy.manage',logs:'audit.view'})[family];
export const ownerState=(ctx,ownerId)=>roleState(ctx,{person_id:ownerId});
export function ownerPermits(state,permission,target={}) {
 if(target.personId==='*'){const mode=target.write===false?'view':'edit';return state.entries.some(e=>e.role.permissions.includes(permission)&&kinds.every(k=>e.resources[mode][k].includes('*')));}
 return permitted(state,permission,target);
}
export function requireOwnerPermission(principal,permission,target={}) {
 if(!principal.ownerAllows?.(permission,target))fail('admin_service_owner_permission_required',403);
}
function covers(state,scope,requested,write) {
 return kinds.every(kind=>requested[kind].every(id=>kind==='people'&&id!=='*'?personInScope(state,scope,id,write):contains(scope[kind],id)));
}
export function assertEnvelope(state,config,{custody=true}={}) {
 if(state.legacy)return;
 if(config.scopes.some(s=>!SCOPE_PERMISSIONS[s]||GLOBAL.has(s))||kinds.some(k=>config.resources[k].includes('*')))fail('admin_service_wider_than_owner',403);
 const permissions=[...new Set([...(custody?['admin-api.manage']:[]),...config.scopes.flatMap(s=>SCOPE_PERMISSIONS[s])])],writes=config.scopes.some(s=>s.endsWith('.manage'));
 // One grant must cover the whole credential: unrelated permissions and
 // resource sets from different grants cannot be unioned into wider automation.
 if(!state.entries.some(e=>permissions.every(p=>e.role.permissions.includes(p))&&covers(state,e.resources.view,config.resources,false)&&(!writes||covers(state,e.resources.edit,config.resources,true))))fail('admin_service_wider_than_owner',403);
}
export const envelopeOf=app=>({scopes:JSON.parse(app.scopes),resources:JSON.parse(app.resources)});
export function scopedRead(principal,family) {
 const permission=readPermission(family);
 requireOwnerPermission(principal,permission,{write:false});
 return {...principal,globalRead:principal.ownerState.legacy||principal.ownerState.entries.some(e=>e.role.permissions.includes(permission)&&kinds.every(k=>e.resources.view[k].includes('*'))),permits:(kind,id)=>principal.permits(kind,id)&&principal.ownerAllows(family==='groups'&&kind==='people'?'people.view':permission,{[kind==='people'?'personId':kind==='groups'?'groupId':'appId']:id,write:false})};
}
export function ownerSnapshotGuard(state) {
 return {clause:"EXISTS(SELECT 1 FROM oa_operators credential_owner JOIN auth_role_epoch authority_epoch ON authority_epoch.id=1 WHERE credential_owner.id=? AND credential_owner.status='active' AND credential_owner.version=? AND credential_owner.role=? AND authority_epoch.epoch=?)",args:[state.person.id,state.person.version,state.person.role,state.epoch]};
}
