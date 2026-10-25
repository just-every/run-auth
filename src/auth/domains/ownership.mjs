import {one,all,fail} from '../core.mjs';

export const employerId=ctx=>ctx.organizationId??'root';
export function domainName(value) {
 const domain=String(value??'').trim().toLowerCase();
 if(domain.length>253||!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain))fail('invalid_domain');
 return domain;
}
export async function verifiedDomain(ctx,domain) {
 return Boolean(await one(ctx,'SELECT 1 FROM auth_domain_claims o JOIN auth_domain_challenges c ON c.id=o.challenge_id WHERE o.domain=? AND o.organization_id=? AND o.revoked_at IS NULL AND c.verified_at IS NOT NULL',domain,employerId(ctx)));
}
export async function requireVerifiedDomain(ctx,domain) {
 if(!await verifiedDomain(ctx,domain))fail('domain_not_verified',409);
}
export async function domainPermitted(ctx,person) {
 if(person.role==='owner') {
  if(person.person_id) {
   const domain=person.email.split('@')[1];
   await ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'domain_emergency_access',?,? WHERE EXISTS(SELECT 1 FROM auth_domain_claims WHERE domain=? AND organization_id=? AND revoked_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM auth_activity WHERE actor_id=? AND event='domain_emergency_access' AND subject_id=? AND created_at>=(SELECT revoked_at FROM auth_domain_claims WHERE domain=?))`).bind(person.person_id,domain,ctx.now(),domain,employerId(ctx),person.person_id,domain,domain).run();
  }
  return true;
 }
 const domain=person.email.split('@')[1],claim=await one(ctx,'SELECT organization_id,revoked_at FROM auth_domain_claims WHERE domain=?',domain);
 if(claim&&claim.organization_id===employerId(ctx))return claim.revoked_at===null&&await verifiedDomain(ctx,domain);
 return !await one(ctx,'SELECT domain FROM auth_domains WHERE domain=? UNION SELECT domain FROM oa_domain_rules WHERE domain=?',domain,domain);
}
export async function ownershipModel(ctx) {
 const challenges=await all(ctx,'SELECT c.*,o.organization_id,o.revoked_at,o.challenge_id FROM auth_domain_challenges c LEFT JOIN auth_domain_claims o ON o.domain=c.domain WHERE c.id=(SELECT id FROM auth_domain_challenges newest WHERE newest.domain=c.domain ORDER BY created_at DESC,rowid DESC LIMIT 1) ORDER BY c.domain');
 return Promise.all(challenges.map(async c=>({id:c.id,domain:c.domain,label:`${c.id}._auth-test.${c.domain}`,value:c.value,expiresAt:c.expires_at,status:await verifiedDomain(ctx,c.domain)?'verified':c.revoked_at!==null&&c.organization_id===employerId(ctx)?'revoked':c.expires_at<=ctx.now()?'expired':'pending',people:await all(ctx,"SELECT id,email,role FROM oa_operators WHERE substr(email,instr(email,'@')+1)=? ORDER BY email",c.domain)})));
}
