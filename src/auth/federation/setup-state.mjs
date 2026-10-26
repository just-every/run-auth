import {all,one,fail,requireSession,hash} from '../core.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {unseal} from '../keys.mjs';
import {requireVerifiedDomain,verifiedDomain,employerId} from '../domains/ownership.mjs';

export const SETUP_LIFETIME=10*60000;
export const setupLabel=(ctx,id)=>'federation-setup:'+(ctx.organizationId??'root')+':'+id;
export async function setupOwner(ctx,request,{write=true}={}) {
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('federation_owner_required',403);
 if(write)requireLocalEmail(ctx,s);return s;
}
export const setupById=async(ctx,id)=>await one(ctx,'SELECT * FROM auth_federation_setups WHERE id=?',String(id??''))??fail('federation_setup_not_found',404);
export const setupConfiguration=(ctx,row)=>unseal(ctx,setupLabel(ctx,row.id),row.sealed_config);
export function requireSetupCreator(row,owner) {
 if(row.created_by!==owner.person_id||row.owner_version!==owner.person_version)fail('federation_setup_owner_changed',403);
}
export async function mappingPreview(ctx,domain,provider) {
 await requireVerifiedDomain(ctx,domain);
 const entries=Object.entries(provider.subjectEmails??{});if(!entries.length||entries.length>200)fail('reviewed_federation_subjects_required');
 const rows=[];
 for(const [subject,address] of entries.sort(([a],[b])=>a.localeCompare(b))) {
  if(address.split('@')[1]!==domain)fail('federation_mapping_domain_mismatch',403);
  const person=await one(ctx,"SELECT id,email,status,version FROM oa_operators WHERE email=? AND role='member' AND status IN ('active','invited') AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=oa_operators.id AND g.revoked_at IS NULL)",address);
  if(!person)fail('federation_mapping_person_unreviewed',409);
  const bound=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',provider.issuer,subject);
  if(bound&&bound.operator_id!==person.id)fail('federation_subject_bound_elsewhere',409);
  if(rows.some(row=>row.personId===person.id))fail('federation_person_mapped_twice',409);
  rows.push({subject,personId:person.id,email:person.email,state:person.status,version:person.version});
 }
 return rows;
}
// Recheck every reviewed association and domain ownership inside the write.
export function mappingGuard(ctx,domain,provider,people) {
 const clauses=[`EXISTS(SELECT 1 FROM auth_domain_claims o JOIN auth_domain_challenges c ON c.id=o.challenge_id WHERE o.domain=? AND o.organization_id=? AND o.revoked_at IS NULL AND c.verified_at IS NOT NULL)`];
 const args=[domain,employerId(ctx)];
 clauses.push(`(SELECT COUNT(*) FROM json_each(?) j JOIN oa_operators p ON p.id=json_extract(j.value,'$.personId') WHERE p.email=json_extract(j.value,'$.email') AND p.version=json_extract(j.value,'$.version') AND p.status=json_extract(j.value,'$.state') AND p.role='member' AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM oa_external_identities i WHERE i.issuer=? AND i.subject=json_extract(j.value,'$.subject') AND i.operator_id<>p.id))=?`);
 args.push(JSON.stringify(people),provider.issuer,people.length);
 return {clause:clauses.join(' AND '),args};
}
export async function setupPreview(ctx,row) {
 const provider=await setupConfiguration(ctx,row),people=await mappingPreview(ctx,row.domain,provider);
 const digest=await hash(JSON.stringify([row.id,row.provider_id,row.domain,row.config_hash,row.revision,row.tested_subject,row.tested_at,people]));
 return {id:row.id,providerId:row.provider_id,domain:row.domain,state:row.state,preset:provider.preset,label:provider.label??provider.id,issuer:provider.issuer,callback:provider.redirectUri??provider.callback,configurationHash:row.config_hash,revision:row.revision,digest,testedSubject:row.tested_subject,testedAt:row.tested_at,people,
  trust:{entityId:provider.entityId??null,ssoUrl:provider.ssoUrl??null,endpointPins:provider.endpointPins??null,certificates:provider.certificates??[],nameIdFormat:provider.nameIdFormat??null,signAuthnRequests:provider.signAuthnRequests===true},provider};
}
export async function federationProviders(ctx) {
 const rows=await all(ctx,"SELECT s.* FROM auth_federation_setups s JOIN oa_operators owner ON owner.id=s.created_by WHERE s.state='active' AND owner.status='active' AND owner.role='owner' AND owner.version=s.owner_version ORDER BY s.provider_id");
 const result=[];
 for(const row of rows) {
  if(!await verifiedDomain(ctx,row.domain))continue;
  const provider=await setupConfiguration(ctx,row);
  result.push({...provider,federationSetupId:row.id,federationConfigHash:row.config_hash,federationRevision:row.revision});
 }
 return result;
}
