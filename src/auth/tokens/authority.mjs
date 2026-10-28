import {factorAssurance} from '../factors/policy.mjs';
import {appAccess} from '../onboarding/gate.mjs';
import {one,fail} from '../core.mjs';
import {permitsSession} from '../domain-policy.mjs';
import {assignment} from '../workforce/directory.mjs';

// Offline grants outlive browser expiry, but never browser revocation, proof
// withdrawal, employer policy, account versions or the exact approved profile.
export function familyGuard(ctx,f) {
 return {clause:`EXISTS(SELECT 1 FROM auth_refresh_families rf
 JOIN auth_refresh_profiles rp ON rp.client_id=rf.client_id
 JOIN auth_oidc_clients rc ON rc.client_id=rf.client_id
 JOIN auth_apps ra ON ra.id=rc.app_id
 JOIN auth_resource_apis api ON api.id=rf.api_id
 JOIN oa_operators person ON person.id=rf.person_id
 JOIN auth_sessions source ON source.id=rf.session_id
 WHERE rf.id=? AND rf.revoked_at IS NULL AND rf.idle_expires_at>? AND rf.absolute_expires_at>?
 AND rp.enabled=1 AND rp.revision=rf.profile_revision AND rp.api_id=rf.api_id
 AND api.revision=rf.api_revision AND api.app_id=ra.id AND ra.version=rf.app_version AND ra.disabled_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM auth_onboarding h WHERE h.person_id=person.id AND (h.start_at>? OR h.rescinded_at IS NOT NULL))
 AND source.amr NOT LIKE '%"onboarding"%' AND source.amr NOT LIKE '%"recovery_code"%'
 AND NOT EXISTS(SELECT 1 FROM auth_factor_policies fp WHERE fp.app_id=ra.id AND NOT ((source.amr LIKE '%"hwk"%' AND EXISTS(SELECT 1 FROM auth_passkey_session_proofs pk WHERE pk.session_id=source.id AND pk.person_id=source.person_id AND pk.verified_at>? - fp.max_age_seconds*1000 AND pk.verified_at<=?)) OR (fp.method='passkey_or_totp' AND EXISTS(SELECT 1 FROM auth_factor_proofs proof JOIN auth_totp_factors tf ON tf.id=proof.factor_id WHERE proof.session_id=source.id AND tf.person_id=source.person_id AND tf.confirmed_at IS NOT NULL AND proof.verified_at>? - fp.max_age_seconds*1000 AND proof.verified_at<=?))))
 AND person.status='active' AND person.version=rf.person_version AND source.person_id=person.id
 AND source.person_version=person.version AND source.revoked_at IS NULL
 AND NOT EXISTS(SELECT 1 FROM auth_app_denials d WHERE d.app_id=ra.id AND d.person_id=person.id)
 AND EXISTS(SELECT 1 FROM auth_app_assignments a LEFT JOIN auth_group_members m ON a.principal_type='group' AND m.group_id=a.principal_id WHERE a.app_id=ra.id AND ((a.principal_type='person' AND a.principal_id=person.id) OR m.person_id=person.id)))`,args:[f.id,ctx.now(),ctx.now(),ctx.now(),ctx.now(),ctx.now(),ctx.now(),ctx.now()]};
}
export async function liveFamily(ctx,f) {
 const g=familyGuard(ctx,f);
 if(!(await one(ctx,`SELECT ${g.clause} AS held`,...g.args)).held)return false;
 const s=await one(ctx,'SELECT s.*,p.email,p.role FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id WHERE s.id=?',f.session_id);
 if(!s||!await appAccess(ctx,s)||!ctx.local&&JSON.parse(s.amr).includes('dev')||!await permitsSession(ctx,s))return false;
 const client=await one(ctx,'SELECT app_id FROM auth_oidc_clients WHERE client_id=?',f.client_id);
 return Boolean(client&&await factorAssurance(ctx,s,client.app_id)&&await assignment(ctx,client.app_id,f.person_id));
}
export async function requireFamily(ctx,f) {if(!f||!await liveFamily(ctx,f))fail('invalid_grant');}
