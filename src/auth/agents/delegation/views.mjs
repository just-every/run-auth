import {one,all,json,fail,requireSession} from '../../core.mjs';
import {id,organization,target} from './common.mjs';
import {taskRow,agentRow,agentForTask,taskCurrent} from './state.mjs';
import {reversalRow,reversalView,canRequestReversal} from './reversal.mjs';

export function taskView(task,{agentName,personName,personEmail,appName,valid=false}={}) {
 return {id:task.id,grantId:task.id,agentId:task.agent_id,agentName,accountablePersonId:task.accountable_id,personName,personEmail,appName,organizationId:task.organization_id,task:JSON.parse(task.effect),effectDigest:task.effect_digest,before:{role:task.before_role},after:{role:JSON.parse(task.effect).role??JSON.parse(task.effect).operation},state:task.state,authorityCurrent:valid,revision:task.revision,createdAt:task.created_at,expiresAt:task.expires_at,consentedAt:task.consented_at,approvedAt:task.approved_at,approvedBy:task.approved_by,completedAt:task.completed_at,revokedAt:task.revoked_at,endedReason:task.ended_reason,executionId:task.execution_id,requiredApprovals:['Accountable person explicit consent','Independent employer owner or administrator passkey approval; approver differs from person and agent custodian'],revocationReach:{local:'Revocation prevents the next token and target execution immediately.',completedEffect:task.resource_id?'Revocation does not undo an operation already released to its resource. A release receipt is not remote completion proof.':'Revocation does not undo an assignment already changed.',downstream:'Ordinary app provisioning and existing external sessions retain their own lifecycle; no blanket remote-revocation claim is made.'}};
}
export async function delegationInventory(ctx,request) {
 const s=await requireSession(ctx,request),owner=['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk');
 const cursor=new URL(request.url).searchParams.get('before');
 const anchor=cursor?await taskRow(ctx,id(cursor)):null;
 if(anchor&&!owner&&anchor.accountable_id!==s.person_id)fail('invalid_inventory_cursor');
 if(cursor&&!anchor)fail('invalid_inventory_cursor');
 const tasks='(SELECT t.*,NULL AS resource_id,NULL AS resource_version FROM auth_delegated_tasks t UNION ALL SELECT '+
  'id,agent_id,agent_revision,service_revision,organization_id,accountable_id,accountable_version,app_id,app_version,native_epoch,role_epoch,effect,effect_digest,before_role,before_created_by,before_created_at,created_at,expires_at,state,revision,consented_by,consented_at,consent_session_id,approved_by,approver_version,approved_at,approval_session_id,revoked_by,revoked_at,ended_reason,execution_id,completed_at,last_issued_at,resource_id,resource_version FROM auth_external_tasks)';
 const fetched=await all(ctx,`SELECT d.*,a.name AS agent_name,a.client_id,p.display_name AS person_name,p.email AS person_email,COALESCE(app.name,res.name) AS app_name FROM ${tasks} d JOIN auth_delegated_agents a ON a.id=d.agent_id JOIN oa_operators p ON p.id=d.accountable_id LEFT JOIN auth_apps app ON app.id=d.app_id LEFT JOIN auth_delegation_resources res ON res.id=d.resource_id WHERE ${owner?'1':'d.accountable_id=?'} ${anchor?'AND (d.created_at<? OR (d.created_at=? AND d.id<?))':''} ORDER BY d.created_at DESC,d.id DESC LIMIT 101`,...(owner?[]:[s.person_id]),...(anchor?[anchor.created_at,anchor.created_at,anchor.id]:[]));
 const rows=fetched.slice(0,100);
 const grants=[];
 for(const row of rows) {
  const agent=await agentRow(ctx,row.client_id),valid=await taskCurrent(ctx,agent,row);
  const reversal=await reversalRow(ctx,row.id);
  grants.push({...taskView(row,{agentName:row.agent_name,personName:row.person_name,personEmail:row.person_email,appName:row.app_name,valid}),reversalRequest:reversalView(reversal),canRequestReversal:canRequestReversal(row,s,reversal)});
 }
 const agents=owner?await all(ctx,'SELECT id,client_id AS clientId,name,registered_by AS registeredBy,state,revision,created_at AS createdAt,expires_at AS expiresAt FROM auth_delegated_agents ORDER BY created_at DESC'):[];
 return json({organizationId:organization(ctx),targetApi:target(ctx),grants,agents,hasMore:fetched.length>100,nextCursor:fetched.length>100?rows.at(-1).id:null});
}
export async function delegationConsentView(ctx,request,grantId) {
 const s=await requireSession(ctx,request),task=await taskRow(ctx,id(grantId))||fail('delegation_not_found',404);
 if(task.accountable_id!==s.person_id&&!(['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk')))fail('delegation_person_refused',403);
 const info=await one(ctx,'SELECT a.name AS agent_name,p.display_name AS person_name,p.email AS person_email,COALESCE(app.name,res.name) AS app_name FROM auth_delegated_agents a JOIN oa_operators p ON p.id=? LEFT JOIN auth_apps app ON app.id=? LEFT JOIN auth_delegation_resources res ON res.id=? WHERE a.id=?',task.accountable_id,task.app_id,task.resource_id??null,task.agent_id)||fail('delegation_target_unavailable',409);
 const agent=await agentForTask(ctx,task);
 const valid=await taskCurrent(ctx,agent,task);
 const reversal=await reversalRow(ctx,task.id);
 return json({...taskView(task,{agentName:info.agent_name,personName:info.person_name,personEmail:info.person_email,appName:info.app_name,valid}),reversalRequest:reversalView(reversal),canRequestReversal:canRequestReversal(task,s,reversal),canConsent:valid&&s.person_id===task.accountable_id&&JSON.parse(s.amr).includes('hwk')&&task.state==='requested',canApprove:valid&&task.state==='consented'&&['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk')&&s.person_id!==task.accountable_id&&s.person_id!==agent.registered_by,agentCustodianId:agent?.registered_by??null});
}
