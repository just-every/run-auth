import {one,fail} from '../../core.mjs';
import {permitsIp} from './ip.mjs';
import {permitsResource} from './config.mjs';
import {ownerState,assertEnvelope,envelopeOf,ownerPermits} from '../scoped-authority.mjs';

export const serviceRow=(ctx,clientId)=>one(ctx,'SELECT * FROM auth_admin_service_apps WHERE client_id=?',clientId);
// A supplied role snapshot is required for scoped member authority. The old
// synchronous signature remains conservative for legacy-only callers.
export function liveGuard(ctx,app,tokenExpiresAt,state=null) {
 const now=ctx.now();
 return {
  clause:`EXISTS(SELECT 1 FROM auth_admin_service_apps service_authority JOIN oa_operators service_owner ON service_owner.id=service_authority.owner_id WHERE service_authority.id=? AND service_authority.owner_id=? AND service_authority.revision=? AND service_authority.revoked_at IS NULL AND service_authority.suspended_at IS NULL AND service_authority.expires_at>? AND service_owner.status='active'${state?" AND service_owner.version=? AND service_owner.role=? AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)":" AND service_owner.role IN ('owner','admin')"}) AND ?>?`,
  args:[app.id,app.owner_id,app.revision,now,...(state?[state.person.version,state.person.role,state.epoch]:[]),tokenExpiresAt,now],
 };
}
export async function authorityState(ctx,app) {
 const state=await ownerState(ctx,app.owner_id);
 assertEnvelope(state,envelopeOf(app));return state;
}
export async function assertLive(ctx,app,tokenExpiresAt,state=null) {
 state??=await authorityState(ctx,app);
 const guard=liveGuard(ctx,app,tokenExpiresAt,state);
 if(!(await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args)))fail('admin_service_authority_changed',403);
 return state;
}
export async function requireLive(ctx,app,request,tokenExpiresAt=app.expires_at) {
 if(!permitsIp(JSON.parse(app.allowed_ips),request))fail('admin_service_ip_refused',403);
 return assertLive(ctx,app,tokenExpiresAt);
}
export async function principalFor(ctx,app,granted,expiresAt,state=null) {
 state??=await authorityState(ctx,app);
 const resources=JSON.parse(app.resources);
 for(const ids of Object.values(resources))Object.freeze(ids);
 Object.freeze(resources);
 const principal={kind:'service',id:app.id,actorId:'admin-service:'+app.id,ownerId:app.owner_id,scopes:Object.freeze(granted),resources,revision:app.revision,expiresAt,
  get ownerState(){return state;},
  get guard(){return liveGuard(ctx,app,expiresAt,state);},
  // Reads retain their original snapshot epoch. Refreshing after a read could
  // hide a concurrent narrowing that happened while its projection was built.
  assertAuthority:()=>assertLive(ctx,app,expiresAt,state),
  prepareAuthority:async()=>{state=await authorityState(ctx,app);await assertLive(ctx,app,expiresAt,state);},
  ownerAllows:(permission,target)=>ownerPermits(state,permission,target),
  permits:(kind,id)=>permitsResource(principal,kind,id),
 };
 return Object.freeze(principal);
}
