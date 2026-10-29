import {one,fail} from '../core.mjs';

// Door decision evidence is retained, not silently erased with native people.
// Until the native client-to-artifact/redaction contract is agreed, close the
// custody exception for the root organization. Isolated employers use separate
// native namespaces and have no shared agent door in this declared subset.
export async function assertAgentCustody(ctx) {
 if(ctx.organizationId&&ctx.organizationId!=='root')return;
 const installed=await one(ctx,"SELECT 1 FROM sqlite_master WHERE type='table' AND name='agent_door_audit'");
 if(!installed)return;
 const retained=await one(ctx,`SELECT 1 FROM agent_door_audit UNION ALL SELECT 1 FROM agent_door_calls UNION ALL SELECT 1 FROM agent_door_approvals UNION ALL SELECT 1 FROM agent_door_reviews UNION ALL SELECT 1 FROM bs_team UNION ALL SELECT 1 FROM bs_settings WHERE owner_id IS NOT NULL LIMIT 1`);
 if(retained)fail('agent_custody_review_required',409);
}
