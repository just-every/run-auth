import {fail} from '../core.mjs';
import {BUILTIN_RANKS} from '../ranks.mjs';
export {LEGACY_RANK} from '../ranks.mjs';

export const PERMISSIONS=Object.freeze({
 'reviews.view':'View access certification within assigned resources',
 'reviews.manage':'Schedule and delegate access certification within assigned resources',
 'reviews.export':'Export access certification within assigned resources',
 'followup.manage':'Manage follow-up',
 'roles.view':'View role definitions and own grants',
 'roles.edit':'Create or revise custom roles (also requires legacy owner/admin)',
 'roles.grant':'Grant or revoke strictly lower roles within held authority',
 'people.view':'View people within view resources',
 'people.export':'Export lower-ranked people within edit resources',
 'people.profile.edit':'Edit directory profile fields within edit resources',
 'people.sessions.end':'End all native sessions and refresh grants for a lower-ranked person within edit resources',
 'people.factors.reset':'Reset non-administrator passkeys and revoke all sessions',
 'people.suspend':'Suspend a lower non-owner person within edit resources',
 'people.restore':'Restore a lower non-owner person within edit resources',
 'recovery.approve':'Approve a scoped non-administrator recovery case',
 'groups.rules.edit':'Manage group rules and every affected person',
 'apps.assign':'Assign an app to an editable person or group',
 'policy.manage':'Manage organization-wide exact-domain provider requirements',
 'identity-providers.manage':'Enable or disable configured identity providers',
 'audit.view':'View scoped administrator audit events',
 'audit.export':'Export scoped administrator audit events with fresh email',
 'admin-api.manage':'Manage scoped admin API credentials within current human authority',
 'groups.view':'View groups within view resources',
 'groups.edit':'Add or remove group members within edit resources',
 'apps.view':'View app identity and enabled state within view resources',
 'apps.edit':'Configure an assigned app, credentials and provisioning; create only with wildcard apps',
 'cases.view':'View assigned recovery review cases',
 'cases.verify':'Record verification or close an assigned recovery review case',
 'cases.open':'Open a recovery review case for an editable non-administrator',
});
const role=(id,name,permissions)=>Object.freeze({id,name,rank:BUILTIN_RANKS[id],permissions:Object.freeze(permissions),builtin:true,revision:1});
export const BUILTINS=Object.freeze([
 role('owner','Owner',Object.keys(PERMISSIONS)),
 role('identity-administrator','Identity administrator',Object.keys(PERMISSIONS).filter(p=>!['roles.edit','admin-api.manage'].includes(p))),
 role('security-policy-administrator','Security/policy administrator',['roles.view','roles.grant','people.view','people.export','policy.manage','identity-providers.manage','audit.view','audit.export','cases.view','reviews.view','reviews.manage','reviews.export']),
 role('app-administrator','App administrator',['roles.view','roles.grant','apps.view','apps.edit','apps.assign']),
 role('group-owner','Group owner',['roles.view','people.view','groups.view','groups.edit','groups.rules.edit']),
 role('manager','Manager',['roles.view','people.view','groups.view']),
 role('app-owner','App owner',['roles.view','apps.view','apps.assign']),
 role('help-desk','Help desk',['roles.view','people.view','people.sessions.end','people.factors.reset','groups.view','cases.view','cases.open','cases.verify','recovery.approve','people.suspend','people.restore']),
 role('auditor','Auditor',['roles.view','people.view','people.export','groups.view','apps.view','cases.view','audit.view','audit.export','reviews.view','reviews.export']),
 role('employee','Employee',[]),
]);
export const RESOURCE_KINDS=['people','groups','apps','cases'];
export const ALL_RESOURCES=Object.freeze(Object.fromEntries(['view','edit'].map(mode=>[mode,Object.fromEntries(RESOURCE_KINDS.map(k=>[k,['*']]))])));
export const writePermission=p=>['reviews.manage','reviews.export','followup.manage','roles.edit','roles.grant','people.profile.edit','people.sessions.end','people.factors.reset','groups.edit','apps.edit','cases.open','cases.verify','people.suspend','people.restore','recovery.approve','groups.rules.edit','apps.assign','policy.manage','identity-providers.manage','admin-api.manage','audit.export'].includes(p);
export const permissionKind=p=>p==='recovery.approve'?'cases':p.startsWith('people.')?'people':p.startsWith('groups.')?'groups':p.startsWith('apps.')?'apps':p.startsWith('cases.')?'cases':null;
export const contains=(ids,id)=>ids.includes('*')||ids.includes(id);
export const subset=(small,large)=>large.includes('*')||small.every(id=>large.includes(id));
export function resources(raw) {
 if(!raw||typeof raw!=='object'||Object.keys(raw).some(k=>!['view','edit'].includes(k)))fail('invalid_role_resources');
 const out={};
 for(const mode of ['view','edit']) {
  const source=raw[mode]??{};
  if(!source||typeof source!=='object'||Array.isArray(source)||Object.keys(source).some(k=>!RESOURCE_KINDS.includes(k)))fail('invalid_role_resources');
  out[mode]={};
  for(const kind of RESOURCE_KINDS) {
   const ids=source[kind]??[];
   if(!Array.isArray(ids)||ids.length>200||ids.some(v=>typeof v!=='string'||!v||v.length>200))fail('invalid_role_resources');
   out[mode][kind]=[...new Set(ids)].sort();
   if(ids.includes('*')&&ids.length!==1)fail('invalid_role_resources');
  }
 }
 for(const k of RESOURCE_KINDS)if(!subset(out.edit[k],out.view[k]))fail('edit_requires_view_scope');
 return out;
}
export function customRole(raw,id) {
 const name=String(raw?.name??'').trim();
 const rank=raw?.rank;
 if(!name||name.length>80||!Number.isInteger(rank)||rank<1||rank>=90||!Array.isArray(raw.permissions)||!raw.permissions.length||raw.permissions.some(p=>!Object.hasOwn(PERMISSIONS,p)))fail('invalid_role');
 return {id,name,rank,permissions:[...new Set(raw.permissions)].sort(),builtin:false};
}
