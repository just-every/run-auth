import {hash,fail,DAY,AuthError} from '../../core.mjs';
import {externalEffect} from './external-effect.mjs';
import {API_ID,SCOPE,id,text,exact,organization,target} from './common.mjs';
export const resourceId=(appId,personId)=>'assignment:'+appId+':person:'+personId;
export function canonicalEffect(ctx,data,{creating=false}={}) {
 if(data?.resourceId)return externalEffect(ctx,data,{creating});
 exact(data,['organizationId','accountablePersonId','personId','purpose','apiId','audience','resource','operation','appId','role','scopes','expiresAt']);
 const appId=id(data.appId,'invalid_app_id'),personId=id(data.personId,'invalid_person_id');
 if(data.organizationId!==organization(ctx)||data.accountablePersonId!==personId||data.apiId!==API_ID||data.audience!==target(ctx)||data.resource!==resourceId(appId,personId)||data.operation!=='assignment.update'||!Array.isArray(data.scopes)||data.scopes.length!==1||data.scopes[0]!==SCOPE)fail('delegation_target_refused',403);
 if(!Number.isSafeInteger(data.expiresAt)||creating&&(data.expiresAt<=ctx.now()||data.expiresAt>ctx.now()+DAY))fail('invalid_delegation_expiry');
 return {organizationId:organization(ctx),accountablePersonId:personId,personId,purpose:text(data.purpose,500,'invalid_delegation_purpose'),apiId:API_ID,audience:target(ctx),resource:resourceId(appId,personId),operation:'assignment.update',appId,role:text(data.role,80,'invalid_assignment_role'),scopes:[SCOPE],expiresAt:data.expiresAt};
}
export const effectDigest=effect=>hash(JSON.stringify(effect));
export async function sameEffect(ctx,task,data) {
 let effect;
 try {effect=canonicalEffect(ctx,data);}catch(error){if(error instanceof AuthError)fail('delegation_effect_changed',403);throw error;}
 if(await effectDigest(effect)!==await effectDigest(JSON.parse(task.effect)))fail('delegation_effect_changed',403);
 return effect;
}
export const authorizationDetails=task=>{
 const effect=JSON.parse(task.effect);
 return [{type:effect.detailType??'auth_assignment_task',locations:[effect.audience],actions:[effect.operation],identifier:effect.resource,grant_id:task.id,effect_digest:task.effect_digest,task:effect}];
};
const stable=value=>Array.isArray(value)?'['+value.map(stable).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+stable(value[key])).join(',')+'}':JSON.stringify(value);
export const sameDetails=(actual,expected)=>stable(actual)===stable(expected);
