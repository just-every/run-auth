import {one,random,fail,json} from '../core.mjs';
import {ownerWrite} from './authorization.mjs';
import {planErasure,publicPlan} from './plan.mjs';
import {remoteDigest} from './reset-policy.mjs';
import {deletionConsent} from './consent.mjs';

// Employer consent authorizes only downstream deletion. It never authorizes
// the local reset, which remains a separate installation-owner action.
export async function resetConsentAction(ctx,s,path,data) {
 if(ctx.organizationId==='root'||ctx.installationAuthority)fail('organization_owner_required',403);
 const selected={...ctx,organizationOwnerConsent:true};
 if(path==='/erasure/reset-preview') {
  const plan=await planErasure(selected,'organization',ctx.organizationId),id=random(),now=ctx.now();
  await ownerWrite(ctx,s,g=>[ctx.db.prepare(`INSERT INTO auth_erasure_previews(id,actor_id,kind,target,digest,created_at,expires_at) SELECT ?,?,'organization-consent',?,?,?,? WHERE ${g.clause}`).bind(id,s.person_id,ctx.organizationId,plan.fingerprint,now,now+600000,...g.args)]);
  return json({id,expiresAt:now+600000,...publicPlan(plan),confirmation:'AUTHORIZE DELETION'});
 }
 const preview=await one(ctx,"SELECT * FROM auth_erasure_previews WHERE id=? AND kind='organization-consent'",String(data.previewId||''));
 if(!preview||preview.actor_id!==s.person_id||preview.expires_at<=ctx.now())fail('erasure_preview_expired',409);
 const plan=await planErasure(selected,'organization',ctx.organizationId);
 if(plan.fingerprint!==preview.digest)fail('erasure_preview_changed',409);
 if(data.confirmation!=='AUTHORIZE DELETION')fail('erasure_confirmation_required');
 const destinations=deletionConsent(plan,data),digest=await remoteDigest(plan),id=random(),now=ctx.now();
 await ownerWrite(ctx,s,g=>[
  ctx.db.prepare(`INSERT INTO auth_erasure_reset_consents(id,actor_id,actor_version,remote_digest,destinations,created_at,expires_at) SELECT ?,?,?,?,?,?,? WHERE ${g.clause}`).bind(id,s.person_id,s.person_version,digest,JSON.stringify(destinations),now,now+600000,...g.args),
  ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'erasure_reset_deletion_consent',?,? WHERE ${g.clause}`).bind(s.person_id,id,now,...g.args),
  ctx.db.prepare(`DELETE FROM auth_erasure_previews WHERE id=? AND ${g.clause}`).bind(preview.id,...g.args),
 ]);
 return json({id,destinations,expiresAt:now+600000});
}
