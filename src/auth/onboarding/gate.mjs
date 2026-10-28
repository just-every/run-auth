import {one,fail} from '../core.mjs';
export async function onboardingGate(ctx,personId) {
 const hire=await one(ctx,'SELECT start_at,rescinded_at FROM auth_onboarding WHERE person_id=?',personId);
 if(!hire)return null;
 if(hire.rescinded_at!==null||hire.start_at>ctx.now())return hire;
 return null;
}
export async function appAccess(ctx,s) {
 if(!s||JSON.parse(s.amr).some(m=>['onboarding','recovery_code'].includes(m))||await onboardingGate(ctx,s.person_id))return false;
 return true;
}
export async function requireAppAccess(ctx,s) {if(!await appAccess(ctx,s))fail('start_time_or_work_proof_required',403);}

export function appAccessGuard(ctx,s) {
 return {clause:`EXISTS(SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id WHERE a.id=? AND a.person_id=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND a.amr NOT LIKE '%"onboarding"%' AND a.amr NOT LIKE '%"recovery_code"%') AND NOT EXISTS(SELECT 1 FROM auth_onboarding h WHERE h.person_id=? AND (h.start_at>? OR h.rescinded_at IS NOT NULL))`,args:[s.id,s.person_id,ctx.now(),s.person_id,ctx.now()]};
}
