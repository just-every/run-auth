import {one,fail,auditDetail,limit} from '../core.mjs';
import {endpoint} from '../saml/apps.mjs';
import {administrator} from './keys.mjs';
import {requireAuthority} from '../local-email.mjs';
import {diagnoseFacts} from './diagnostic-model.mjs';
import {diagnosticState,diagnosticSources,justifiedRepair} from './diagnostic-state.mjs';
import {storeProposal} from './preparer.mjs';

export async function diagnoseSignIn(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request);
 if(s.role!=='owner')fail('owner_required',403);
 // No trace text, caller-supplied facts, instructions, tokens or extra fields
 // enter the model. A person's consent covers this precise snapshot only.
 const allowed=['keyId','appId','personId','issue','callback','kid','recoveryId','consent','csrf'];
 if(Object.keys(data).some(k=>!allowed.includes(k)))fail('untrusted_diagnostic_fields');
 if(![true,'on','true'].includes(data.consent))fail('diagnostic_consent_required',403);
 if(!['callback','certificate','mail'].includes(data.issue))fail('invalid_diagnostic_issue');
 const key=await one(ctx,"SELECT k.* FROM auth_agent_keys k JOIN oa_operators p ON p.id=k.owner_id WHERE k.id=? AND k.owner_id=? AND k.owner_version=p.version AND k.revoked_at IS NULL AND k.expires_at>?",String(data.keyId||''),s.person_id,ctx.now())||fail('preparer_key_refused',403);
 const params={personId:String(data.personId||''),issue:data.issue,...(data.issue==='callback'?{callback:endpoint(ctx,data.callback,'callback')}:{}),...(data.issue==='certificate'?{kid:String(data.kid||'')}:{}),...(data.issue==='mail'?{recoveryId:String(data.recoveryId||'')}:{} )};
 if(params.callback&&new URL(params.callback).search)fail('callback_query_not_supported');
 const target=String(data.appId||''),state=await diagnosticState(ctx,target,params),sources=diagnosticSources(ctx,state,params);
 await requireAuthority(ctx,s,guard);
 await auditDetail(ctx,s.person_id,'diagnostic_snapshot_approved',target,{testIdentity:params.personId,sources:sources.map(s=>s.id),model:'claude-haiku-4-5-20251001'});
 if(!await limit(ctx,'diagnostic-model:'+key.id,10,3600000))fail('rate_limited',429);
 const result=await diagnoseFacts({key:ctx.agentModelKey,workspaceId:ctx.agentModelWorkspace,fetcher:ctx.agentModelFetch},sources);
 const repair=justifiedRepair(ctx,state,params,result);
 if(!repair&&result.diagnosis!=='uncertain') {
  result.diagnosis='uncertain';
  result.nextAction={callback:'Reproduce the refused callback with this assigned test employee, confirm the exact expected URI and prepare a new snapshot.',certificate:'Stage and publish a currently valid replacement certificate, confirm the app trusts it and prepare a new snapshot.',mail:'Inspect this employee’s pending recovery and its mail outcome. Prepare a new snapshot only after observing a failed delivery.'}[params.issue];
 }
 // Keep the approved pre-call snapshot. A target that moved during the paid
 // call cannot silently acquire a new scope; its eventual approval is stale.
 return storeProposal(ctx,key,'repair_signin',target,{...params,sources,result,repair},'Diagnose and repair '+data.issue,guard,state);
}
