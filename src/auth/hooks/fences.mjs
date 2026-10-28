import {requireFactorAssurance} from '../factors/policy.mjs';
import {requireAppAccess} from '../onboarding/gate.mjs';
// A remote extension never carries stale sign-in authority across its latency.
import {one,fail,EMAIL_MAX_AGE} from '../core.mjs';
import {permitsSession} from '../domain-policy.mjs';
import {assignment} from '../workforce/directory.mjs';
export async function recheckIssuance(ctx,s,{appId,clientId,appVersion,mappingVersion,assignmentRole}={}) {
 await requireAppAccess(ctx,s);
 await requireFactorAssurance(ctx,s,appId??clientId);
 const fresh=await one(ctx,"SELECT a.*,p.email,p.role FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id WHERE a.id=? AND a.person_id=? AND a.person_version=? AND a.amr=? AND p.version=a.person_version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>?",s.id,s.person_id,s.person_version,s.amr,ctx.now());
 const proof=fresh&&await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',s.person_id);
 if(!fresh||!proof||ctx.now()-proof.verified_at>=EMAIL_MAX_AGE||!await permitsSession(ctx,fresh))fail('sign_in_authority_changed',403);
 if(appId){
  const app=await one(ctx,'SELECT version,mapping_version FROM auth_apps WHERE id=? AND disabled_at IS NULL',appId),assigned=await assignment(ctx,appId,s.person_id);
  if(!app||!assigned||appVersion!==undefined&&app.version!==appVersion||mappingVersion!==undefined&&app.mapping_version!==mappingVersion||assignmentRole!==undefined&&assigned.role!==assignmentRole)fail('sign_in_authority_changed',403);
 }
 if(clientId&&!await one(ctx,'SELECT id FROM auth_clients WHERE id=? AND disabled_at IS NULL',clientId))fail('sign_in_authority_changed',403);
}
