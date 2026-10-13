import {PRESETS} from '../modules/operator-auth/identity/oidc/index.mjs';
import {one,hash,fail} from './core.mjs';

// Enrollment permission (auth_domains) and required sign-in routes are independent.
export async function requiredProvider(ctx,person) {
 if(person.role==='owner')return null;
 return one(ctx,'SELECT provider_id FROM oa_domain_rules WHERE domain=?',person.email.split('@')[1]);
}
export function configuredProvider(ctx,id) {
 return (ctx.upstreamProviders||[]).find(p=>p.id===id&&['google','microsoft','okta'].includes(p.preset));
}
export async function matchesConfiguredPin(ctx,provider,issuer) {
 const preset=PRESETS[provider.preset],expected=preset.issuer||(preset.tenantIssuer?preset.tenantIssuer(provider.tenant):provider.issuer);
 const pin=await one(ctx,'SELECT issuer,client_id,preset,status FROM oa_identity_providers WHERE provider_id=?',provider.id);
 return Boolean(pin&&pin.status==='linked'&&pin.issuer===expected&&(!issuer||issuer===expected)&&pin.client_id===provider.clientId&&pin.preset===provider.preset);
}
export async function configurationHash(provider) {
 // Rotation of a client secret does not change an identity; changing its issuer,
 // client or subject association does require a new verified upstream sign-in.
 return hash(JSON.stringify([provider.id,provider.preset,provider.issuer||null,provider.tenant||null,provider.clientId,Object.entries(provider.subjectEmails||{}).sort(([a],[b])=>a.localeCompare(b))]));
}
export async function upstreamProof(ctx,personId,id) {
 if(!id)return null;
 const proof=await one(ctx,'SELECT * FROM auth_upstream_proofs WHERE id=? AND person_id=? AND expires_at>? AND verified_at<=?',id,personId,ctx.now(),ctx.now());
 if(!proof)return null;
 const provider=configuredProvider(ctx,proof.provider_id);
 if(!provider||!await matchesConfiguredPin(ctx,provider,proof.issuer)||proof.configuration_hash!==await configurationHash(provider))return null;
 const binding=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',proof.issuer,proof.subject);
 return binding?.operator_id===personId?proof:null;
}
export async function permitsProvider(ctx,person,providerId) {
 const rule=await requiredProvider(ctx,person);
 return !rule||(rule.provider_id===providerId&&Boolean(configuredProvider(ctx,providerId)));
}
export async function permitsSession(ctx,person,proofId=person.upstream_proof_id) {
 const rule=await requiredProvider(ctx,person);
 if(!rule)return true;
 const proof=await upstreamProof(ctx,person.person_id||person.id,proofId);
 return Boolean(proof&&proof.provider_id===rule.provider_id);
}
export async function requirePolicy(ctx,person,proofId) {
 if(!await permitsSession(ctx,person,proofId))fail('required_provider',403);
}
