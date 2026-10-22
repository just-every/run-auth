import {generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {all,one,random,hash,cookie,scopedCookieName,cookies,challenge,consumeChallenge,unb64,json,fail,auditDetail} from '../../core.mjs';
import {browserData,exact,id,consentingSession,personSessionGuard,both} from './common.mjs';
import {taskRow,agentForTask,taskGuard,held} from './state.mjs';

const bindingCookie=ctx=>scopedCookieName(ctx,ctx.local?'auth_delegation_consent':'__Host-auth_delegation_consent');
async function pending(ctx,request,grantId,effectDigest) {
 const s=await consentingSession(ctx,request),task=await taskRow(ctx,id(grantId))||fail('delegation_not_found',404);
 if(task.accountable_id!==s.person_id||task.accountable_version!==s.person_version)fail('delegation_person_refused',403);
 if(effectDigest!==task.effect_digest)fail('delegation_effect_changed',403);
 const agent=await agentForTask(ctx,task)||fail('agent_not_found',404);
 const guard=both(personSessionGuard(ctx,s),await taskGuard(ctx,agent,task,['requested'],{consent:false,approval:false}));
 return {s,task,agent,guard};
}
export async function consentOptions(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['grantId','effectDigest']);
 const {s,task,guard}=await pending(ctx,request,data.grantId,data.effectDigest);
 const keys=await all(ctx,'SELECT id,transports FROM auth_passkeys WHERE person_id=?',s.person_id);
 if(!keys.length)fail('passkey_required',403);
 const options=await generateAuthenticationOptions({rpID:new URL(ctx.origin).hostname,userVerification:'required',allowCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
 // This employee ceremony has its own purpose and browser cookie. Its signed
 // challenge names the exact grant revision/digest and the current session.
 const browser=random(),transaction=await challenge(ctx,'delegation-consent',s.person_id,await hash(browser),{challenge:options.challenge,grantId:task.id,digest:task.effect_digest,revision:task.revision,sessionId:s.id},300000,guard);
 if(!transaction){await held(ctx,guard);fail('delegation_consent_refused',409);}
 return json({transaction,options,grantId:task.id,effectDigest:task.effect_digest},200,{'set-cookie':cookie(ctx,bindingCookie(ctx),browser,300)});
}
export async function consentDelegation(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['grantId','effectDigest','decision','transaction','response']);
 if(data.decision!=='consent')fail('explicit_consent_required',403);
 const {s,task,agent}=await pending(ctx,request,data.grantId,data.effectDigest);
 const browser=cookies(request)[bindingCookie(ctx)],tx=await consumeChallenge(ctx,data.transaction,'delegation-consent',browser?await hash(browser):null);
 if(tx.person_id!==s.person_id||tx.payload.sessionId!==s.id||tx.payload.grantId!==task.id||tx.payload.digest!==task.effect_digest||tx.payload.revision!==task.revision)fail('delegation_consent_changed',403);
 const key=await one(ctx,'SELECT * FROM auth_passkeys WHERE id=? AND person_id=?',String(data.response?.id??''),s.person_id)||fail('invalid_passkey');
 let checked;
 try {checked=await verifyAuthenticationResponse({response:data.response,expectedChallenge:tx.payload.challenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,credential:{id:key.id,publicKey:unb64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});}catch{fail('invalid_passkey');}
 if(!checked.verified)fail('invalid_passkey');
 const guard=both(personSessionGuard(ctx,s),await taskGuard(ctx,agent,task,['requested'],{consent:false,approval:false}));
 // Claim live person/task authority and the verified counter together. Every
 // write uses the transaction-local native latch, so consent cannot outlive a
 // concurrent revocation or commit without its passkey counter update.
 const operation=random(),latch={clause:'EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)',args:[operation]};
 const results=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause} AND EXISTS(SELECT 1 FROM auth_passkeys WHERE id=? AND person_id=? AND counter=?)`).bind(operation,...guard.args,key.id,s.person_id,key.counter),
  ctx.db.prepare(`UPDATE auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND ${latch.clause}`).bind(checked.authenticationInfo.newCounter,ctx.now(),key.id,...latch.args),
  ctx.db.prepare(`UPDATE auth_delegated_tasks SET state='consented',consented_by=?,consented_at=?,consent_session_id=?,revision=revision+1 WHERE id=? AND ${latch.clause}`).bind(s.person_id,ctx.now(),s.id,task.id,...latch.args),
  ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(operation),
 ]);
 if(!results[0].meta.changes){await held(ctx,guard);fail('passkey_changed',409);}
 await auditDetail(ctx,s.person_id,'delegation_consented',task.id,{agentId:agent.id,effectDigest:task.effect_digest,independentAdministratorApprovalRequired:true});
 return json({grantId:task.id,state:'consented',effectDigest:task.effect_digest},200,{'set-cookie':cookie(ctx,bindingCookie(ctx),'',0)});
}
