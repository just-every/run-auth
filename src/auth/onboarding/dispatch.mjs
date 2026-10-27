import {one,fail} from '../core.mjs';

// This is standing employer authorization recorded by a proved administrator.
// A later role removal, suspension or account-version change ends it.
export const dispatchRule=`h.rescinded_at IS NULL AND h.personal_verified_at IS NULL
 AND h.contact_authority IS NOT NULL AND h.start_at>? AND h.start_at-h.lead_days*86400000<=?
 AND p.status='invited' AND sender.status='active' AND sender.role IN ('owner','admin')
 AND sender.version=h.sending_person_version`;
export const dispatchFrom=`auth_onboarding h JOIN oa_operators p ON p.id=h.person_id
 JOIN oa_operators sender ON sender.id=h.sending_person_id`;

// Called by the delivery journal immediately before handing bytes to transport.
// Never trust the schedule or authority captured while queueing the message.
export async function requireActivationDispatch(ctx,activation) {
 const now=ctx.now();
 const current=await one(ctx,`SELECT h.person_id FROM ${dispatchFrom} WHERE h.person_id=?
 AND h.generation=? AND h.operation_id=? AND ${dispatchRule}`,
 activation.personId,activation.generation,activation.operationId,now,now);
 if(!current)fail('activation_dispatch_no_longer_authorized',403);
}

export async function personalRecoveryContact(ctx,personId) {
 return one(ctx,`SELECT h.personal_email FROM ${dispatchFrom} WHERE h.person_id=?
 AND h.rescinded_at IS NULL AND h.personal_verified_at IS NOT NULL AND h.contact_authority IS NOT NULL
 AND h.recovery_notices_enabled=1 AND p.status='active' AND sender.status='active'
 AND sender.role IN ('owner','admin') AND sender.version=h.sending_person_version`,personId);
}
export async function requirePersonalRecoveryDispatch(ctx,notice,address) {
 const current=await personalRecoveryContact(ctx,notice.personId);
 if(!current||current.personal_email!==address)fail('personal_recovery_no_longer_authorized',403);
}
