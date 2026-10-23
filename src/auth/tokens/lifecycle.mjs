import {all,auditDetail,one,run} from '../core.mjs';
import {deliverGenericLogouts} from '../oidc-apps/session.mjs';
import {liveFamily} from './authority.mjs';

export async function endFamily(ctx,id,reason,actor=null) {
 const changed=await one(ctx,'UPDATE auth_refresh_families SET revoked_at=?,reason=? WHERE id=? AND revoked_at IS NULL RETURNING *',ctx.now(),reason,id);
 if(changed)await auditDetail(ctx,actor??changed.person_id,'refresh_family_ended',id,{clientId:changed.client_id,reason});
 const family=changed??await one(ctx,'SELECT * FROM auth_refresh_families WHERE id=?',id);
 if(!family||family.logout_queued_at!==null)return;
 // The queue and marker commit together, so a crash cannot lose a supported
 // logout or create duplicate queues. The existing delivery worker retries it.
 const client=await one(ctx,'SELECT backchannel_logout_uri FROM auth_oidc_clients WHERE client_id=?',family.client_id);
 const queue=client?.backchannel_logout_uri;
 await ctx.db.batch([
  ...(queue?[ctx.db.prepare(`INSERT INTO auth_oidc_logouts(id,client_id,person_id,sid,jti,next_attempt_at,created_at)
   SELECT 'refresh:'||id,client_id,person_id,id,'refresh:'||id,?,? FROM auth_refresh_families WHERE id=? AND logout_queued_at IS NULL
   ON CONFLICT(id) DO NOTHING`).bind(ctx.now(),ctx.now(),id)]:[]),
  ctx.db.prepare('UPDATE auth_refresh_families SET logout_queued_at=? WHERE id=? AND logout_queued_at IS NULL').bind(ctx.now(),id),
 ]);
 if(queue){const work=deliverGenericLogouts(ctx,['refresh:'+id]);if(ctx.waitUntil)ctx.waitUntil(work);else await work;}
}
export async function maintainFamilies(ctx,{personId=null,appId=null,reason='authority_ended'}={}) {
 const rows=await all(ctx,`SELECT f.* FROM auth_refresh_families f JOIN auth_oidc_clients c ON c.client_id=f.client_id WHERE f.revoked_at IS NULL${personId?' AND f.person_id=?':''}${appId?' AND c.app_id=?':''}`,...(personId?[personId]:[]),...(appId?[appId]:[]));
 for(const f of rows)if(personId||appId||!await liveFamily(ctx,f))await endFamily(ctx,f.id,reason);
}
