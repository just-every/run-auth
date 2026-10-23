import {fail,DAY} from '../../core.mjs';
import {exact,id,text,organization} from './common.mjs';

export function externalEffect(ctx,data,{creating=false}={}) {
 exact(data,['organizationId','accountablePersonId','personId','purpose','apiId','resourceId','detailType','audience','resource','operation','scopes','expiresAt','arguments']);
 const personId=id(data.personId),resourceId=id(data.resourceId);
 if(data.organizationId!==organization(ctx)||data.accountablePersonId!==personId||data.apiId!==resourceId)fail('delegation_target_refused',403);
 if(!Array.isArray(data.scopes)||data.scopes.length!==1||typeof data.scopes[0]!=='string')fail('invalid_scope');
 if(!Number.isSafeInteger(data.expiresAt)||creating&&(data.expiresAt<=ctx.now()||data.expiresAt>ctx.now()+DAY))fail('invalid_delegation_expiry');
 if(!data.arguments||typeof data.arguments!=='object'||Array.isArray(data.arguments)||JSON.stringify(data.arguments).length>8000)fail('invalid_task_arguments');
 return {organizationId:organization(ctx),accountablePersonId:personId,personId,purpose:text(data.purpose,500,'invalid_delegation_purpose'),apiId:resourceId,resourceId,detailType:text(data.detailType,80,'invalid_detail_type'),audience:text(data.audience,2000,'invalid_audience'),resource:text(data.resource,500,'invalid_task_resource'),operation:text(data.operation,100,'invalid_operation'),scopes:[text(data.scopes[0],100,'invalid_scope')],expiresAt:data.expiresAt,arguments:data.arguments};
}
