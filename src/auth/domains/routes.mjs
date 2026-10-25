import {all,one,run,json,fail,auditDetail,requireSession} from '../core.mjs';
import {authority,requireAuthority,requireLocalEmail} from '../local-email.mjs';
import {domainName,employerId,ownershipModel} from './ownership.mjs';
import {emit} from '../events/store.mjs';

export const DOMAIN_PATH='/api/auth/domains';
export const isDomainAction=path=>['/domains/challenge','/domains/verify','/domains/revoke'].includes(path);
export async function domainRead(ctx,request) {
 await requireSession(ctx,request,true);return json({domains:await ownershipModel(ctx)});
}
async function dnsMatches(ctx,challenge) {
 const name=`${challenge.id}._auth-test.${challenge.domain}`;
 let response;
 try {response=await (ctx.dnsFetch??fetch)('https://cloudflare-dns.com/dns-query?'+new URLSearchParams({name,type:'TXT'}),{headers:{accept:'application/dns-json'},redirect:'manual',signal:AbortSignal.timeout(10000)});}
 catch {fail('domain_dns_unavailable',502);}
 if(!response.ok)fail('domain_dns_unavailable',502);
 const data=await response.json();
 return data.Status===0&&(data.Answer??[]).some(answer=>answer.type===16&&String(answer.name).replace(/\.$/,'').toLowerCase()===name&&String(answer.data).replace(/^"|"$/g,'').replace(/"\s+"/g,'')===challenge.value);
}
export async function domainAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const guard=authority(ctx,s,['owner','admin']),domain=domainName(data.domain),organization=employerId(ctx);
 const claim=await one(ctx,'SELECT * FROM auth_domain_claims WHERE domain=?',domain);
 if(claim&&claim.organization_id!==organization)fail('domain_already_claimed',409);
 if(path==='/domains/challenge') {
  const id=crypto.randomUUID().replaceAll('-',''),value='auth-domain='+crypto.randomUUID(),now=ctx.now();
  const result=await run(ctx,`INSERT INTO auth_domain_challenges(id,domain,value,expires_at,created_by,created_at) SELECT ?,?,?,?,?,? WHERE ${guard.clause}`,id,domain,value,now+30*60000,s.person_id,now,...guard.args);
  if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('domain_claim_changed',409);}
  await auditDetail(ctx,s.person_id,'domain_challenge_started',domain,{challengeId:id,expiresAt:now+30*60000});
  return json({id,domain,label:`${id}._auth-test.${domain}`,value,expiresAt:now+30*60000},201);
 }
 if(path==='/domains/revoke') {
  if(data.confirm!==true&&data.confirm!=='true')fail('confirmation_required');
  const result=await run(ctx,`UPDATE auth_domain_claims SET revoked_at=? WHERE domain=? AND organization_id=? AND revoked_at IS NULL AND ${guard.clause}`,ctx.now(),domain,organization,...guard.args);
  if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('domain_claim_unavailable',409);}
  const affected=await all(ctx,"SELECT id,role FROM oa_operators WHERE substr(email,instr(email,'@')+1)=?",domain);
  await auditDetail(ctx,s.person_id,'domain_ownership_revoked',domain,{affected:affected.map(p=>p.id),emergencyOwners:affected.filter(p=>p.role==='owner').map(p=>p.id),policy:'deny-non-owners-until-reverified'});
  await emit(ctx,'policy.domain_ownership_revoked',{type:'domain',id:domain},{people:affected.length});
  return json({ok:true,affected:affected.length,emergencyOwnerAccess:true});
 }
 const c=await one(ctx,'SELECT * FROM auth_domain_challenges WHERE id=? AND domain=? AND verified_at IS NULL AND expires_at>?',String(data.id??''),domain,ctx.now());
 if(!c)fail('domain_challenge_expired_or_used',409);
 if(!await dnsMatches(ctx,c))fail('domain_challenge_incorrect',409);
 // Both statements share a transaction and the live administrator guard. The
 // unique global domain key prevents simultaneous employers from both winning.
 const results=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_domain_claims(domain,organization_id,challenge_id,verified_at,revoked_at) SELECT ?,?,?,?,NULL WHERE ${guard.clause} AND EXISTS(SELECT 1 FROM auth_domain_challenges WHERE id=? AND verified_at IS NULL AND expires_at>?) ON CONFLICT(domain) DO UPDATE SET challenge_id=excluded.challenge_id,verified_at=excluded.verified_at,revoked_at=NULL WHERE auth_domain_claims.organization_id=excluded.organization_id`).bind(domain,organization,c.id,ctx.now(),...guard.args,c.id,ctx.now()),
  ctx.db.prepare(`UPDATE auth_domain_challenges SET verified_at=? WHERE id=? AND verified_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_domain_claims WHERE domain=? AND organization_id=? AND challenge_id=?) AND ${guard.clause}`).bind(ctx.now(),c.id,ctx.now(),domain,organization,c.id,...guard.args),
 ]);
 if(!results[1].meta.changes){await requireAuthority(ctx,s,guard);fail('domain_claim_changed',409);}
 await auditDetail(ctx,s.person_id,'domain_ownership_verified',domain,{challengeId:c.id,aliasPolicy:'each-exact-domain-needs-its-own-proof'});
 return json({ok:true,domain});
}
