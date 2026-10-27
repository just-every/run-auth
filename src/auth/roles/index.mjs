import {endPersonSessions} from '../session-control/index.mjs';
import {json,fail,requireSession,one} from '../core.mjs';
import {roleState} from './state.mjs';
import {PERMISSIONS,BUILTINS} from './permissions.mjs';
import {requireHardware,permitted,assertPermission} from './policy.mjs';
import {preview,apply} from './plans.mjs';
import {resetFactors} from './factors.mjs';
import {editProfile} from './profile.mjs';
import {editApp,editGroup,recoveryCase} from './resources.mjs';
import {roleCommand,ROLE_COMMANDS} from './native.mjs';
import {auditRead} from './audit.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {roleGuard} from './policy.mjs';
import {commit} from './commit.mjs';
import {adminServiceAction,isAdminServiceAction} from '../admin-api/credentials/index.mjs';
import {requireRolePermission} from './policy.mjs';
export {requireRolePermission} from './policy.mjs';

export const ROLE_READS=['/api/auth/roles','/api/auth/roles/people','/api/auth/roles/export','/api/auth/roles/audit','/api/auth/roles/audit/export'];
const ACTIONS=['/roles/end-sessions','/roles/preview','/roles/apply','/roles/reset-factors','/roles/profile','/roles/recovery-case','/roles/app','/roles/group','/roles/command','/roles/admin-service'];
export const isRoleAction=path=>ACTIONS.includes(path);

export async function roleModel(ctx,s) {
 requireHardware(s);
 const state=await roleState(ctx,s);
 assertPermission(state,'roles.view');
 const model={commands:ROLE_COMMANDS,epoch:state.epoch,rank:state.rank,canDesignRoles:state.canDesignRoles,permissions:PERMISSIONS,builtinRoles:BUILTINS,
  roles:[...state.roles.values()],
  grants:state.grants.filter(g=>state.legacy||g.person_id===s.person_id||g.granted_by===s.person_id).map(g=>({...g,resources:JSON.parse(g.resources),active:state.activeGrants.some(a=>a.id===g.id)})),
  ownGrants:state.entries.map(e=>({id:e.id,roleId:e.role.id,rank:e.role.rank,permissions:e.role.permissions,resources:e.resources})),
  groups:state.dir.groups.filter(g=>permitted(state,'groups.view',{groupId:g.id})).map(g=>({id:g.id,name:g.name,rule:g.rule})),
  apps:state.apps.filter(a=>permitted(state,'apps.view',{appId:a.id})),
  cases:state.cases.filter(c=>permitted(state,'cases.view',{caseId:c.id})).map(c=>({...c,verification:c.verification?JSON.parse(c.verification):null})),
 };
 // A concurrent authority change must not leak a directory snapshot after its
 // grant has been revoked. Reads do not require fresh email proof.
 await assertReadAuthority(ctx,s,state);
 return model;
}
async function assertReadAuthority(ctx,s,state) {
 // Local-email authority is deliberately for writes. A read checks the current
 // version/methods, session lifetime and exact authority epoch without email age.
 const held=await one(ctx,`SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1 WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?`,s.id,s.person_id,s.amr,ctx.now(),state.epoch);
 if(!held)fail('role_authority_changed',409);
}
function visiblePerson(state,p,permission) {
 if(!permitted(state,permission,{personId:p.id,write:false}))return null;
 const fields=state.dir.values(p);
 return {id:p.id,email:p.email,name:p.name,status:p.status,role:p.role,rank:state.rankOf(p.id),fields,
  groups:[...(state.memberships.get(p.id)??[])].filter(groupId=>permitted(state,'groups.view',{groupId})),
  canEndSessions:permitted(state,'people.sessions.end',{personId:p.id,write:true}),
  canResetFactors:p.role==='member'&&state.rankOf(p.id)===0&&permitted(state,'people.factors.reset',{personId:p.id,write:true}),
  canEditProfile:permitted(state,'people.profile.edit',{personId:p.id,write:true})};
}
export async function roleRead(ctx,request,path) {
 const s=await requireSession(ctx,request);requireHardware(s);
 if(path==='/api/auth/roles')return json(await roleModel(ctx,s));
 if(!ROLE_READS.includes(path))fail('not_found',404);
 if(path.startsWith('/api/auth/roles/audit'))return auditRead(ctx,s,path,request);
 const state=await roleState(ctx,s),exporting=path==='/api/auth/roles/export',permission=exporting?'people.export':'people.view';
 assertPermission(state,permission,{write:false});
 const query=new URL(request.url).searchParams,personId=query.get('personId'),groupId=query.get('groupId'),q=(query.get('q')??'').trim().toLowerCase();
 if(personId)assertPermission(state,permission,{personId,write:false});
 if(groupId)assertPermission(state,'groups.view',{groupId,write:false});
 const people=[...state.dir.people.values()].filter(p=>(!personId||p.id===personId)&&(!groupId||state.memberships.get(p.id)?.has(groupId))&&(!q||`${p.name} ${p.email}`.toLowerCase().includes(q))).map(p=>visiblePerson(state,p,permission)).filter(Boolean);
 await assertReadAuthority(ctx,s,state);
 if(exporting) {
  // Export is a separate permission; it never falls through to the legacy
  // unscoped directory/export doors and returns only independently authorized rows.
  requireLocalEmail(ctx,s);
  await commit(ctx,s,roleGuard(ctx,s,state),'roles.people.export',null,{people:people.map(p=>p.id),epoch:state.epoch});
  return json({people,exportedAt:ctx.now()},200,{'content-disposition':'attachment; filename="auth-scoped-people.json"'});
 }
 return json({people,total:people.length,epoch:state.epoch});
}
export async function roleAction(ctx,request,path,data) {
 if(!isRoleAction(path))fail('not_found',404);
 if(request.method!=='POST')fail('method_not_allowed',405);
 if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
 const s=await requireSession(ctx,request);
 if(path==='/roles/admin-service') {
  await requireRolePermission(ctx,s,'admin-api.manage',{write:true});
  if(!isAdminServiceAction(data.action))fail('role_command_excluded',403);
  return adminServiceAction(ctx,request,data.action,data.params??{});
 }
 if(path==='/roles/end-sessions')return endPersonSessions(ctx,s,data);
 if(path==='/roles/command')return roleCommand(ctx,s,data);
 if(path==='/roles/preview')return preview(ctx,s,data);
 if(path==='/roles/apply')return apply(ctx,s,data);
 if(path==='/roles/reset-factors')return resetFactors(ctx,s,data);
 if(path==='/roles/profile')return editProfile(ctx,s,data);
 if(path==='/roles/app')return editApp(ctx,s,data);
 if(path==='/roles/group')return editGroup(ctx,s,data);
 return recoveryCase(ctx,s,data);
}
