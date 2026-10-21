import {all,one,json,fail} from '../core.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {roleState} from './state.mjs';
import {assertPermission,permitted,roleGuard} from './policy.mjs';
import {commit} from './commit.mjs';

export async function auditRead(ctx,s,path) {
 const state=await roleState(ctx,s),exporting=path.endsWith('/export'),permission=exporting?'audit.export':'audit.view';
 assertPermission(state,permission,{write:false});
 // Scoped readers get the event summary only. Exact plans can include grants
 // and other resources outside their directory scope and remain legacy custody.
 const rows=await all(ctx,'SELECT id,actor_id,event,subject_id,created_at FROM auth_role_events ORDER BY id DESC LIMIT 1000');
 const events=rows.filter(row=>{
  if(state.legacy||row.actor_id===s.person_id)return true;
  const id=row.subject_id;
  if(state.dir.people.has(id))return permitted(state,permission,{personId:id,write:false});
  if(state.dir.groups.some(g=>g.id===id))return permitted(state,permission,{groupId:id,write:false});
  if(state.apps.some(a=>a.id===id))return permitted(state,permission,{appId:id,write:false});
  if(state.cases.some(c=>c.id===id))return permitted(state,permission,{caseId:id,write:false});
  return false;
 });
 if(!await one(ctx,`SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1 WHERE a.id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?`,s.id,s.amr,ctx.now(),state.epoch))fail('role_authority_changed',409);
 if(exporting) {
  requireLocalEmail(ctx,s);
  await commit(ctx,s,roleGuard(ctx,s,state),'roles.audit.export',null,{events:events.map(e=>e.id),epoch:state.epoch});
 }
 return json({events,epoch:state.epoch},200,exporting?{'content-disposition':'attachment; filename="auth-scoped-audit.json"'}:{});
}
