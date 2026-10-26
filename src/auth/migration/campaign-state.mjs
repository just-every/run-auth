import {all,one,run,fail} from '../core.mjs';
import {configuredProvider,configurationHash,matchesConfiguredPin} from '../domain-policy.mjs';

export const CAMPAIGNS='/api/auth/move-in/campaigns';
export async function campaignCurrent(ctx,campaign) {
 const provider=configuredProvider(ctx,campaign.provider_id);
 const custodian=await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status='active' AND role IN ('owner','admin')",campaign.created_by,campaign.owner_version);
 return !!(!campaign.cancelled_at&&custodian&&provider&&await matchesConfiguredPin(ctx,provider)&&campaign.configuration_hash===await configurationHash(provider));
}
export async function campaignPeople(ctx,campaign) {
 const people=await all(ctx,`SELECT c.*,p.display_name,p.status,p.role,m.email AS manager_email,
  EXISTS(SELECT 1 FROM auth_passkeys k WHERE k.person_id=c.person_id) AS passkey,
  EXISTS(SELECT 1 FROM auth_import_rows r JOIN auth_import_batches b ON b.id=r.batch_id WHERE b.id=? AND b.undone_at IS NULL AND r.person_id=c.person_id AND r.source_id=c.source_subject AND r.status='admitted' AND COALESCE(r.disabled,0)=0) AS staged,
  EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=c.person_id AND g.revoked_at IS NULL) AS privileged
  FROM auth_campaign_people c JOIN oa_operators p ON p.id=c.person_id LEFT JOIN oa_operators m ON m.id=c.manager_id WHERE c.campaign_id=? ORDER BY c.email`,campaign.batch_id,campaign.id);
 return people.map(person=>({...person,factors:person.passkey?['passkey']:[],state:person.exempt_at?'exempt':person.role!=='member'||person.privileged||!person.staged||!['active','invited'].includes(person.status)?'unavailable':person.proven_at&&person.passkey?'passkey_ready':ctx.now()>=campaign.deadline_at?'overdue':'pending'}));
}

// A provider dedicated to a campaign never falls back to matching an email.
// This gate applies even if the browser omits the campaign return address.
export async function campaignAdmission(ctx,principal) {
 const campaign=await one(ctx,'SELECT * FROM auth_campaigns WHERE provider_id=?',principal.provider);
 if(!campaign)return null;
 if(!await campaignCurrent(ctx,campaign)||ctx.now()<campaign.starts_at||ctx.now()>=campaign.cutover_at)fail('campaign_window_closed',403);
 const methods=principal.amr??[];
 if(!methods.includes('mfa')&&!(methods.includes('pwd')&&methods.some(method=>['otp','hwk','swk','push'].includes(method))))fail('campaign_incumbent_mfa_required',403);
 const row=(await campaignPeople(ctx,campaign)).find(person=>person.source_subject===principal.subject);
 if(!row||!['pending','overdue','passkey_ready'].includes(row.state))fail('campaign_staged_member_required',403);
 if(principal.associatedEmail&&principal.associatedEmail!==row.email)fail('campaign_subject_mismatch',403);
 const binding=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',principal.issuer,principal.subject);
 if(binding&&binding.operator_id!==row.person_id)fail('campaign_subject_mismatch',403);
 return {campaign,row};
}

export async function recordCampaignProof(ctx,{campaign,row}) {
 const updated=await run(ctx,`UPDATE auth_campaign_people SET proven_at=? WHERE campaign_id=? AND person_id=? AND source_subject=? AND exempt_at IS NULL
  AND EXISTS(SELECT 1 FROM auth_campaigns c JOIN oa_operators owner ON owner.id=c.created_by WHERE c.id=? AND c.cancelled_at IS NULL AND c.starts_at<=? AND c.cutover_at>? AND owner.version=c.owner_version AND owner.status='active' AND owner.role IN ('owner','admin'))
  AND EXISTS(SELECT 1 FROM oa_operators p JOIN auth_import_rows r ON r.person_id=p.id JOIN auth_import_batches b ON b.id=r.batch_id WHERE p.id=? AND p.email=? AND p.status IN ('active','invited') AND p.role='member' AND b.id=? AND b.undone_at IS NULL AND r.source_id=? AND r.status='admitted' AND COALESCE(r.disabled,0)=0 AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL))`,ctx.now(),campaign.id,row.person_id,row.source_subject,campaign.id,ctx.now(),ctx.now(),row.person_id,row.email,campaign.batch_id,row.source_subject);
 if(!updated.meta.changes)fail('campaign_authority_changed',403);
}
