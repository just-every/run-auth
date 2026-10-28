import {one,fail,json,all,random,requireSession} from '../core.mjs';
import {requireLocalEmail,authority} from '../local-email.mjs';
import {factorCommit} from './writes.mjs';
// These assurance choices apply only to native web app doors. Neither an email
// session nor a recovery capability ever becomes administrator authority.
export async function factorAssurance(ctx,s,appId) {
 const policy=await one(ctx,'SELECT * FROM auth_factor_policies WHERE app_id=?',appId);
 if(!policy)return true;
 if(!s||JSON.parse(s.amr).some(m=>['tap','onboarding','recovery_code'].includes(m)))return false;
 const now=ctx.now(),floor=now-policy.max_age_seconds*1000;
 if(JSON.parse(s.amr).includes('hwk')&&s.created_at>floor&&s.created_at<=now)return true;
 if(policy.method!=='passkey_or_totp')return false;
 return Boolean(await one(ctx,`SELECT 1 FROM auth_factor_proofs p JOIN auth_totp_factors f ON f.id=p.factor_id WHERE p.session_id=? AND p.person_id=? AND f.person_id=p.person_id AND f.confirmed_at IS NOT NULL AND p.verified_at>? AND p.verified_at<=?`,s.id,s.person_id,floor,now));
}
export async function requireFactorAssurance(ctx,s,appId){if(!await factorAssurance(ctx,s,appId))fail('factor_step_up_required',403);}
export function factorPolicyGuard(ctx,s,appId) {
 return {clause:`NOT EXISTS(SELECT 1 FROM auth_factor_policies fp WHERE fp.app_id=? AND NOT (
 (? LIKE '%"hwk"%' AND ?>? - fp.max_age_seconds*1000 AND ?<=?) OR
 (fp.method='passkey_or_totp' AND EXISTS(SELECT 1 FROM auth_factor_proofs proof JOIN auth_totp_factors f ON f.id=proof.factor_id WHERE proof.session_id=? AND proof.person_id=? AND f.person_id=proof.person_id AND f.confirmed_at IS NOT NULL AND proof.verified_at>? - fp.max_age_seconds*1000 AND proof.verified_at<=?))
 ))`,args:[appId,s.amr,s.created_at,ctx.now(),s.created_at,ctx.now(),s.id,s.person_id,ctx.now(),ctx.now()]};
}
export async function configurePolicy(ctx,request,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 if(s.role!=='owner')fail('owner_required',403);
 const appId=String(data.appId??''),maxAge=Number(data.maxAgeSeconds);
 if(!['passkey','passkey_or_totp'].includes(data.method)||!Number.isSafeInteger(maxAge)||maxAge<60||maxAge>3600)fail('invalid_factor_policy');
 if(!await one(ctx,'SELECT id FROM auth_apps WHERE id=? AND disabled_at IS NULL UNION SELECT id FROM auth_clients WHERE id=? AND disabled_at IS NULL',appId,appId))fail('app_not_found',404);
 const g=authority(ctx,s,['owner']),revision=random();
 await factorCommit(ctx,s,g,'factor_policy_changed',(q,held)=>[
  q(`INSERT INTO auth_factor_policies(app_id,method,max_age_seconds,revision) SELECT ?,?,?,? WHERE ${held} ON CONFLICT(app_id) DO UPDATE SET method=excluded.method,max_age_seconds=excluded.max_age_seconds,revision=excluded.revision`,appId,data.method,maxAge,revision),
 ]);
 return json({ok:true});
}
export async function policyModel(ctx) {
 return {policies:await all(ctx,'SELECT * FROM auth_factor_policies'),apps:await all(ctx,'SELECT id,name FROM auth_apps WHERE disabled_at IS NULL UNION SELECT id,name FROM auth_clients WHERE disabled_at IS NULL')};
}
