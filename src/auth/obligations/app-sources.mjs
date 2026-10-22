import {one,all} from '../core.mjs';
const administrator=async(ctx,id)=>Boolean(await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",id));
export async function appCandidates(ctx) {
 return all(ctx,`SELECT 'app_setup' AS kind,id AS source_id,requested_by AS owner_id,NULL AS person_id,NULL AS app_id,created_at FROM auth_link_requests
  UNION ALL SELECT 'app_link_proposal',p.id,k.owner_id,NULL,NULL,p.created_at FROM auth_agent_proposals p JOIN auth_agent_keys k ON k.id=p.key_id WHERE p.kind IN ('approve_app_link','remove_app_link')
  UNION ALL SELECT 'app_link_token',f.id,t.created_by,NULL,NULL,t.issued_at FROM auth_followup_link_tokens f JOIN auth_link_tokens t ON t.token_hash=f.token_hash`);
}
export async function appSourceState(ctx,ob) {
 if(ob.kind==='app_link_token') {
  const row=await one(ctx,'SELECT t.*,f.client_id FROM auth_followup_link_tokens f JOIN auth_link_tokens t ON t.token_hash=f.token_hash WHERE f.id=?',ob.source_id);
  if(!row)return {state:'expired'};
  if(row.client_id)return {state:'completed'}; // Written only after callback and redemption both acknowledge.
  if(row.consumed_at)return {state:'expired',action:'review_link_state_and_issue_new_link_authority',error:'link_authority_consumed_effect_unconfirmed'};
  if(row.expires_at<=ctx.now()||!await administrator(ctx,row.created_by))return {state:'expired'};
  return {state:'open',action:'finish_app_setup_with_one_use_link_authority',expiresAt:row.expires_at};
 }
 if(ob.kind==='app_setup') {
  const row=await one(ctx,'SELECT * FROM auth_link_requests WHERE id=?',ob.source_id);
  if(!row)return {state:'cancelled'};
  if(row.outcome==='linked')return {state:'completed'};
  if(row.expires_at<=ctx.now())return {state:'expired'};
  if(row.decided_at) {
   // The one-winner approval already committed, but the callback may have failed
   // or lost its answer. Keep the uncertain effect visible; no automatic retry.
   if(!await administrator(ctx,row.decided_by))return {state:'expired',error:'app_setup_approver_authority_ended'};
   return {state:'open',action:'inspect_app_link_and_request_fresh_setup_if_needed',error:'app_setup_callback_not_confirmed',expiresAt:row.expires_at};
  }
  if(!await administrator(ctx,row.requested_by))return {state:'expired',error:'app_setup_requester_authority_ended'};
  return {state:'open',action:'review_and_approve_app_link',expiresAt:row.expires_at};
 }
 const row=await one(ctx,'SELECT * FROM auth_agent_proposals WHERE id=?',ob.source_id);
 if(!row||row.status==='rejected')return {state:'cancelled'};
 if(row.status==='expired'||row.status==='pending'&&row.expires_at<=ctx.now())return {state:'expired'};
 // Key revocation does not revoke a filed proposal: human approval remains a
 // current public door by policy. No preparer authority is inferred here.
 if(row.status==='pending')return {state:'open',action:row.kind==='remove_app_link'?'review_proposed_app_link_removal':'review_proposed_app_link',expiresAt:row.expires_at};
 if(row.status==='failed')return {state:'cancelled',error:'app_proposal_refused_requires_new_proposal'};
 if(row.kind==='remove_app_link') {
  const client=await one(ctx,'SELECT disabled_at FROM auth_clients WHERE id=?',row.target);
  return !client||client.disabled_at?{state:'completed'}:{state:'open',action:'inspect_unconfirmed_app_link_removal',error:'app_link_removal_unconfirmed'};
 }
 // A redeemed client can exist even when its callback refused the link.
 // Only the successful callback's durable confirmation closes this source.
 if(JSON.parse(row.outcome??'{}').linkConfirmed===true)return {state:'completed'};
 if(row.expires_at<=ctx.now())return {state:'expired'};
 if(!await administrator(ctx,row.decided_by))return {state:'expired',error:'app_setup_approver_authority_ended'};
 return {state:'open',action:'inspect_app_link_and_request_fresh_setup_if_needed',error:'approved_app_link_effect_unconfirmed'};
}
