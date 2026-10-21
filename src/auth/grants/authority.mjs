import {one} from '../core.mjs';

export const issuer=ctx=>ctx.issuer??ctx.origin;
export const organization=ctx=>ctx.organizationId??'root';
export const apiRow=(ctx,id)=>one(ctx,'SELECT * FROM auth_resource_apis WHERE id=?',id);
export const serviceRow=(ctx,id)=>one(ctx,'SELECT * FROM auth_resource_services WHERE client_id=?',id);
export function serviceGuard(ctx,service,expiresAt=service.expires_at,apiRevision=null) {
 const now=ctx.now();
 return {
  clause:`EXISTS(SELECT 1 FROM auth_resource_services rs JOIN oa_operators rp ON rp.id=rs.owner_id JOIN auth_resource_apis ra ON ra.id=rs.api_id JOIN auth_apps app ON app.id=ra.app_id WHERE rs.id=? AND rs.client_id=? AND rs.api_id=? AND rs.owner_id=? AND rs.owner_version=? AND rs.revision=? AND rs.revoked_at IS NULL AND rs.expires_at>? AND rp.status='active' AND rp.version=rs.owner_version AND app.disabled_at IS NULL${apiRevision===null?'':' AND ra.revision=?'}) AND ?>?`,
  args:[service.id,service.client_id,service.api_id,service.owner_id,service.owner_version,service.revision,now,...(apiRevision===null?[]:[apiRevision]),expiresAt,now],
 };
}
export const guardHolds=async(ctx,g)=>Boolean(await one(ctx,`SELECT 1 WHERE ${g.clause}`,...g.args));
