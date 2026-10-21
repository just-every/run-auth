import {one,requireSession,fail} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {requireRolePermission,assertPermission,requireHardware,roleGuard} from '../roles/policy.mjs';
import {roleState} from '../roles/state.mjs';
import {apiRow,serviceRow} from './authority.mjs';

export async function configuration(ctx,request,path,data) {
 const s=await requireSession(ctx,request);requireHardware(s);requireLocalEmail(ctx,s);
 if(['owner','admin'].includes(s.role))return {s,guard:authority(ctx,s,['owner','admin'])};
 let appId=data.appId,ownerId=data.ownerId;
 if(path.endsWith('/service-revoke')) {
  const service=await serviceRow(ctx,String(data.clientId??''));if(!service)fail('service_not_found',404);
  appId=(await apiRow(ctx,service.api_id))?.app_id;ownerId=service.owner_id;
 }else if(!path.endsWith('/register'))appId=(await apiRow(ctx,String(data.apiId??'')))?.app_id;
 if(!appId)fail('api_not_found',404);
 const permission=path.endsWith('/assign')?'apps.assign':'apps.edit';
 const guard=await requireRolePermission(ctx,s,permission,{appId,write:true});
 if(ownerId)assertPermission(guard.state,permission,{appId,personId:ownerId,write:true});
 if(path.endsWith('/assign')) {
  if(data.principalType==='person')assertPermission(guard.state,permission,{appId,personId:data.principalId,write:true});
  else if(data.principalType==='group') {
   assertPermission(guard.state,permission,{appId,groupId:data.principalId,write:true});
   for(const [personId,groups] of guard.state.memberships)if(groups.has(data.principalId))assertPermission(guard.state,permission,{appId,personId,write:true});
  }else fail('invalid_principal_type');
 }
 return {s,guard};
}
export async function configurationView(ctx,request,model) {
 const s=await requireSession(ctx,request);requireHardware(s);
 if(['owner','admin'].includes(s.role))return model;
 const state=await roleState(ctx,s),{permitted}=await import('../roles/policy.mjs');
 assertPermission(state,'apps.view');
 const apis=model.apis.filter(api=>permitted(state,'apps.view',{appId:api.appId})),ids=new Set(apis.map(api=>api.id));
 if(!await one(ctx,`SELECT 1 WHERE ${roleGuard(ctx,s,state).clause}`,...roleGuard(ctx,s,state).args))fail('role_authority_changed',409);
 return {...model,apis,services:model.services.filter(service=>ids.has(service.apiId))};
}
