import {fail,AuthError,session,auditDetail,json} from '../../core.mjs';
import {TARGET_PATH} from './common.mjs';
import {registerAgent,suspendAgent} from './registry.mjs';
import {requestDelegation} from './request.mjs';
import {delegationInventory,delegationConsentView} from './views.mjs';
import {consentDelegation,consentOptions} from './consent.mjs';
import {delegationApprovalOptions,approveDelegation} from './approval.mjs';
import {revokeDelegation} from './revoke.mjs';
import {executeDelegation} from './execute.mjs';
import {requestReversal} from './reversal.mjs';

const PREFIX='/api/auth/delegations';
const writes=new Map([
 [PREFIX+'/agents/register',registerAgent],
 [PREFIX+'/agents/suspend',suspendAgent],
 [PREFIX+'/request',requestDelegation],
 [PREFIX+'/consent',consentDelegation],
 [PREFIX+'/consent/options',consentOptions],
 [PREFIX+'/approval/options',delegationApprovalOptions],
 [PREFIX+'/approve',approveDelegation],
 [PREFIX+'/revoke',revokeDelegation],
 [PREFIX+'/reverse',requestReversal],
 [TARGET_PATH,executeDelegation],
]);
export const isDelegationPath=path=>path===TARGET_PATH||path===PREFIX||path.startsWith(PREFIX+'/');
export async function delegationRoute(ctx,request,path) {
 delete ctx.delegationActor;
 try {
 if(path!==TARGET_PATH&&path!==PREFIX+'/request') {
  const s=await session(ctx,request);
  if(s)ctx.delegationActor={actorId:s.person_id};
 }
 if(request.method==='GET') {
  if(path===PREFIX)return await delegationInventory(ctx,request);
  if(path===PREFIX+'/consent')return await delegationConsentView(ctx,request,new URL(request.url).searchParams.get('id'));
 }
 const handler=writes.get(path);
 if(!handler)fail('not_found',404);
 if(request.method!=='POST')fail('method_not_allowed',405);
 // Browser handlers parse and Origin-check their own input. Machine request
 // and execution handlers accept only their bound private-key authority.
 return await handler(ctx,request);
 }catch(error) {
  if(error instanceof AuthError) {
   const actor=ctx.delegationActor;
   await auditDetail(ctx,actor?.actorId??null,'delegation_refused',actor?.grantId??null,{
    method:request.method,path:writes.has(path)||path===PREFIX||path===PREFIX+'/consent'?path:PREFIX+'/*',reason:error.message,
    ...(actor?.agentId?{agentId:actor.agentId,accountablePersonId:actor.accountablePersonId,approvedBy:actor.approvedBy}:{}),
   });
   if(error.headers)return json({error:error.message},error.status,error.headers);
  }
  throw error;
 }
}
