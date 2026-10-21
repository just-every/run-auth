import {all,hash} from '../core.mjs';

// Consent binds exactly the downstream objects shown to the employer owner.
// Its own audit append does not alter this authority digest; adding or changing
// any remote object does. Local reset authority remains installation-owned.
export const remoteDigest=plan=>hash(JSON.stringify(plan.remote.map(task=>[
 task.kind,task.partner,task.work?.connector?.app_id??null,
 task.work?.connector?.base_url??null,task.work?.resource??null,task.work?.remoteId??null,
]).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)))));
export async function resetConsent(ctx,plan) {
 const digest=await remoteDigest(plan);
 const rows=await all(ctx,"SELECT c.* FROM auth_erasure_reset_consents c JOIN oa_operators p ON p.id=c.actor_id WHERE c.remote_digest=? AND c.expires_at>? AND p.role='owner' AND p.status='active' AND p.version=c.actor_version ORDER BY c.created_at DESC,c.id DESC",digest,ctx.now());
 const row=rows[0];
 if(!row)return null;
 return {id:row.id,digest,destinations:JSON.parse(row.destinations),actorId:row.actor_id,actorVersion:row.actor_version,expiresAt:row.expires_at};
}
export function consentGuard(consent,now) {
 if(!consent)return {clause:'1',args:[]};
 return {clause:"EXISTS(SELECT 1 FROM auth_erasure_reset_consents c JOIN oa_operators p ON p.id=c.actor_id WHERE c.id=? AND c.remote_digest=? AND c.destinations=? AND c.expires_at>? AND p.id=? AND p.version=? AND p.role='owner' AND p.status='active')",args:[consent.id,consent.digest,JSON.stringify(consent.destinations),now,consent.actorId,consent.actorVersion]};
}
