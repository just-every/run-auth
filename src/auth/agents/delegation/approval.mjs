import {generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {all,one,run,random,hash,cookie,scopedCookieName,cookies,challenge,consumeChallenge,unb64,json,fail,auditDetail} from '../../core.mjs';
import {browserData,exact,id,approvalSession,approvalGuard,both} from './common.mjs';
import {taskTable,taskRow,agentForTask,taskGuard,held} from './state.mjs';

const bindingCookie=ctx=>scopedCookieName(ctx,ctx.local?'auth_delegation_approval':'__Host-auth_delegation_approval');
function independent(s,task,agent) {
 if(s.person_id===task.accountable_id||s.person_id===agent.registered_by)fail('independent_administrator_required',403);
}
async function pending(ctx,request,grantId,effectDigest) {
 const s=await approvalSession(ctx,request),task=await taskRow(ctx,id(grantId))||fail('delegation_not_found',404),agent=await agentForTask(ctx,task)||fail('agent_not_found',404);
 independent(s,task,agent);
 if(effectDigest!==task.effect_digest)fail('delegation_effect_changed',403);
 return {s,task,agent,guard:both(approvalGuard(ctx,s),await taskGuard(ctx,agent,task,['consented'],{approval:false}))};
}
export async function delegationApprovalOptions(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['grantId','effectDigest']);
 const {s,task,guard}=await pending(ctx,request,data.grantId,data.effectDigest);
 const keys=await all(ctx,'SELECT id,transports FROM auth_passkeys WHERE person_id=?',s.person_id);
 if(!keys.length)fail('passkey_required',403);
 const options=await generateAuthenticationOptions({rpID:new URL(ctx.origin).hostname,userVerification:'required',allowCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
 const browser=random(),transaction=await challenge(ctx,'delegation-approval',s.person_id,await hash(browser),{challenge:options.challenge,grantId:task.id,digest:task.effect_digest,revision:task.revision,sessionId:s.id},300000,guard);
 if(!transaction){await held(ctx,guard);fail('delegation_approval_refused',409);}
 return json({transaction,options,grantId:task.id,effectDigest:task.effect_digest},200,{'set-cookie':cookie(ctx,bindingCookie(ctx),browser,300)});
}
export async function approveDelegation(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['grantId','effectDigest','transaction','response']);
 const {s,task,agent}=await pending(ctx,request,data.grantId,data.effectDigest);
 const browser=cookies(request)[bindingCookie(ctx)],tx=await consumeChallenge(ctx,data.transaction,'delegation-approval',browser?await hash(browser):null);
 if(tx.person_id!==s.person_id||tx.payload.sessionId!==s.id||tx.payload.grantId!==task.id||tx.payload.digest!==task.effect_digest||tx.payload.revision!==task.revision)fail('delegation_approval_changed',403);
 const key=await one(ctx,'SELECT * FROM auth_passkeys WHERE id=? AND person_id=?',String(data.response?.id??''),s.person_id)||fail('invalid_passkey');
 let checked;
 try {checked=await verifyAuthenticationResponse({response:data.response,expectedChallenge:tx.payload.challenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,credential:{id:key.id,publicKey:unb64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});}catch{fail('invalid_passkey');}
 if(!checked.verified)fail('invalid_passkey');
 const guard=both(approvalGuard(ctx,s),await taskGuard(ctx,agent,task,['consented'],{approval:false}));
 // The passkey counter and exact approval commit together. A counter conflict
 // aborts the approval through the inserted transaction-local marker.
 const operation=random(),latch={clause:'EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)',args:[operation]};
 const results=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause} AND EXISTS(SELECT 1 FROM auth_passkeys WHERE id=? AND person_id=? AND counter=?)`).bind(operation,...guard.args,key.id,s.person_id,key.counter),
  ctx.db.prepare(`UPDATE auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND ${latch.clause}`).bind(checked.authenticationInfo.newCounter,ctx.now(),key.id,...latch.args),
  ctx.db.prepare(`UPDATE ${taskTable(task)} SET state='approved',approved_by=?,approver_version=?,approved_at=?,approval_session_id=?,revision=revision+1 WHERE id=? AND ${latch.clause}`).bind(s.person_id,s.person_version,ctx.now(),s.id,task.id,...latch.args),
  ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(operation),
 ]);
 if(!results[0].meta.changes){await held(ctx,guard);fail('passkey_changed',409);}
 await auditDetail(ctx,s.person_id,'delegation_approved',task.id,{agentId:agent.id,agentCustodian:agent.registered_by,accountablePersonId:task.accountable_id,effectDigest:task.effect_digest});
 return json({grantId:task.id,state:'approved',effectDigest:task.effect_digest},200,{'set-cookie':cookie(ctx,bindingCookie(ctx),'',0)});
}
