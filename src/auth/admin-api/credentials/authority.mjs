import {one,fail} from '../../core.mjs';
import {permitsIp} from './ip.mjs';
import {permitsResource} from './config.mjs';

export const serviceRow=(ctx,clientId)=>one(ctx,'SELECT * FROM auth_admin_service_apps WHERE client_id=?',clientId);
export function liveGuard(ctx,app,tokenExpiresAt) {
 const now=ctx.now();
 return {
  clause:"EXISTS(SELECT 1 FROM auth_admin_service_apps service_authority JOIN oa_operators service_owner ON service_owner.id=service_authority.owner_id WHERE service_authority.id=? AND service_authority.owner_id=? AND service_authority.revision=? AND service_authority.revoked_at IS NULL AND service_authority.suspended_at IS NULL AND service_authority.expires_at>? AND service_owner.status='active' AND service_owner.role IN ('owner','admin')) AND ?>?",
  args:[app.id,app.owner_id,app.revision,now,tokenExpiresAt,now],
 };
}
export async function assertLive(ctx,app,tokenExpiresAt) {
 const guard=liveGuard(ctx,app,tokenExpiresAt);
 if(!(await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args)))fail('admin_service_authority_changed',403);
}
export async function requireLive(ctx,app,request,tokenExpiresAt=app.expires_at) {
 if(!permitsIp(JSON.parse(app.allowed_ips),request))fail('admin_service_ip_refused',403);
 await assertLive(ctx,app,tokenExpiresAt);
}
export function principalFor(ctx,app,granted,expiresAt) {
 const resources=JSON.parse(app.resources);
 for(const ids of Object.values(resources))Object.freeze(ids);
 Object.freeze(resources);
 const principal={kind:'service',id:app.id,actorId:'admin-service:'+app.id,ownerId:app.owner_id,scopes:Object.freeze(granted),resources,revision:app.revision,expiresAt,
  get guard(){return liveGuard(ctx,app,expiresAt);},
  assertAuthority:()=>assertLive(ctx,app,expiresAt),
  permits:(kind,id)=>permitsResource(principal,kind,id),
 };
 return Object.freeze(principal);
}
