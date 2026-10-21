import {AuthError,random,one,all,requireSession,json,fail} from '../../core.mjs';
import {requireAuthority} from '../../local-email.mjs';
import {CLIENT_PREFIX,serviceSettings} from './config.mjs';
import {requireRolePermission} from '../../roles/policy.mjs';
import {ownerState,assertEnvelope,ownerSnapshotGuard} from '../scoped-authority.mjs';
import {authorityState} from './authority.mjs';

const PATHS=['/admin-service-apps/create','/admin-service-apps/revoke','/admin-service-apps/reassign'];
export const isAdminServiceAction=path=>PATHS.includes(path);
const intersect=(a,b)=>({clause:`(${a.clause}) AND (${b.clause})`,args:[...a.args,...b.args]});
async function accountable(ctx,id,config,creator) {
 if(!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active'",id))fail('invalid_admin_service_owner');
 const state=await ownerState(ctx,id);
 if(state.person.id!==creator.person.id&&state.rank>=creator.rank)fail('lower_rank_required',403);
 assertEnvelope(state,config);return state;
}
async function commit(ctx,s,guard,statement,event,id,detail) {
 // Record the action atomically, only if its guarded mutation won.
 const result=await ctx.db.batch([
  statement,
  ctx.db.prepare('INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,?,?,? WHERE changes()>0').bind(s.person_id,event,id,ctx.now()),
  ctx.db.prepare('INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE changes()>0').bind(JSON.stringify(detail)),
 ]);
 if(!result[0].meta.changes){await requireAuthority(ctx,s,guard);fail('admin_service_conflict',409);}
}
export async function adminServiceAction(ctx,request,path,data) {
 if(!isAdminServiceAction(path))return null;
 if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
 const s=await requireSession(ctx,request);
 const custody=await requireRolePermission(ctx,s,'admin-api.manage',{write:true});
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_admin_service');
 if(path==='/admin-service-apps/create') {
  const config=await serviceSettings(ctx,data),id=random(),clientId=CLIENT_PREFIX+id,now=ctx.now();
  if(!custody.state.legacy&&config.ownerId!==s.person_id)fail('admin_service_self_owner_required',403);
  assertEnvelope(custody.state,config);
  const owner=await accountable(ctx,config.ownerId,config,custody.state),guard=intersect(custody,ownerSnapshotGuard(owner));
  const statement=ctx.db.prepare(`INSERT INTO auth_admin_service_apps(id,client_id,name,purpose,owner_id,jwks,scopes,resources,allowed_ips,created_by,created_at,expires_at)
   SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`).bind(id,clientId,config.name,config.purpose,config.ownerId,JSON.stringify(config.jwks),JSON.stringify(config.scopes),JSON.stringify(config.resources),JSON.stringify(config.allowedIps),s.person_id,now,config.expiresAt,...guard.args);
  await commit(ctx,s,guard,statement,'admin_service_created',id,{serviceApp:id,owner:config.ownerId,scope:config.scopes.join(' '),result:'created',name:config.name,purpose:config.purpose});
  return json({id,clientId},201);
 }
 const id=data.id??data.serviceAppId;
 if(typeof id!=='string'||!id||id.length>256)fail('invalid_admin_service');
 const app=await one(ctx,'SELECT * FROM auth_admin_service_apps WHERE id=?',id);if(!app)fail('admin_service_not_found',404);
 if(!custody.state.legacy&&app.owner_id!==s.person_id)fail('admin_service_self_owner_required',403);
 if(path==='/admin-service-apps/revoke') {
  const guard=custody;
  const statement=ctx.db.prepare(`UPDATE auth_admin_service_apps SET revoked_at=?,revoked_by=?,revision=revision+1 WHERE id=? AND revision=? AND revoked_at IS NULL AND ${guard.clause}`).bind(ctx.now(),s.person_id,id,app.revision,...guard.args);
  await commit(ctx,s,guard,statement,'admin_service_revoked',id,{serviceApp:id,owner:app.owner_id,scope:JSON.parse(app.scopes).join(' '),result:'revoked'});
 } else {
  if(!custody.state.legacy)fail('legacy_admin_reassignment_required',403);
  if(typeof data.ownerId!=='string'||!data.ownerId||data.ownerId.length>256)fail('invalid_admin_service_owner');
  const config={scopes:JSON.parse(app.scopes),resources:JSON.parse(app.resources)};
  assertEnvelope(custody.state,config);
  const owner=await accountable(ctx,data.ownerId,config,custody.state),guard=intersect(custody,ownerSnapshotGuard(owner));
  const statement=ctx.db.prepare(`UPDATE auth_admin_service_apps SET owner_id=?,suspended_at=NULL,suspension_reason=NULL,revision=revision+1 WHERE id=? AND revision=? AND revoked_at IS NULL AND ${guard.clause}`).bind(data.ownerId,id,app.revision,...guard.args);
  await commit(ctx,s,guard,statement,'admin_service_reassigned',id,{serviceApp:id,previousOwner:app.owner_id,owner:data.ownerId,scope:JSON.parse(app.scopes).join(' '),result:'reassigned'});
 }
 return json({ok:true,id,clientId:app.client_id});
}
export async function adminServicesModel(ctx) {
 const rows=await all(ctx,'SELECT a.*,p.email AS owner_email,p.display_name AS owner_name,p.status AS owner_status,p.role AS owner_role FROM auth_admin_service_apps a LEFT JOIN oa_operators p ON p.id=a.owner_id ORDER BY a.created_at DESC,a.id');
 return Promise.all(rows.map(async a=>{
  let held=true;try{await authorityState(ctx,a);}catch(error){if(!(error instanceof AuthError))throw error;held=false;}
  return ({
  id:a.id,clientId:a.client_id,name:a.name,purpose:a.purpose,ownerId:a.owner_id,ownerEmail:a.owner_email,ownerName:a.owner_name,
  jwks:JSON.parse(a.jwks),scopes:JSON.parse(a.scopes),resources:JSON.parse(a.resources),allowedIps:JSON.parse(a.allowed_ips),
  revision:a.revision,createdAt:a.created_at,expiresAt:a.expires_at,revokedAt:a.revoked_at,suspendedAt:a.suspended_at,lastUsedAt:a.last_used_at,
  suspensionReason:a.suspension_reason,
  status:a.revoked_at!==null?'revoked':a.suspended_at!==null||a.owner_status!=='active'||!held?'suspended':a.expires_at<=ctx.now()?'expired':'active',
 });}));
}
