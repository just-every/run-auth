import {all,run,random,json,fail,auditDetail} from '../../core.mjs';
import {publicKeys} from '../../grants/public-keys.mjs';
import {text,exact,browserData,ownerSession,ownerGuard,both} from './common.mjs';
import {employerGuard,held} from './state.mjs';

const published=(value,code)=>{
 if(!Array.isArray(value)||!value.length||value.length>100)fail(code);
 const items=value.map(item=>text(item,100,code));
 if(items.some(item=>!/^[A-Za-z][A-Za-z0-9_.:-]*$/.test(item))||new Set(items).size!==items.length)fail(code);
 return items;
};
export async function registerResource(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['name','kind','audience','scopes','detailType','operations','jwks']);
 const s=await ownerSession(ctx,request),keys=await publicKeys(data.jwks);
 if(!['mcp','api'].includes(data.kind))fail('invalid_resource_kind');
 const name=text(data.name,80,'invalid_resource_name'),audience=text(data.audience,2000,'invalid_resource_audience');
 let url;try{url=new URL(audience);}catch{fail('invalid_resource_audience');}
 if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.href!==audience||url.origin===ctx.origin)fail('invalid_resource_audience');
 const scopes=published(data.scopes,'invalid_resource_scopes'),operations=published(data.operations,'invalid_resource_operations'),detailType=published([data.detailType],'invalid_detail_type')[0];
 if(['auth_assignment_task'].includes(detailType))fail('invalid_detail_type');
 const id=random(),clientId='delegated-resource:'+id,guard=both(ownerGuard(ctx,s),employerGuard(ctx));
 const result=await run(ctx,`INSERT INTO auth_delegation_resources(id,client_id,name,kind,audience,scopes,detail_type,operations,jwks,registered_by,owner_version,created_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`,id,clientId,name,data.kind,audience,JSON.stringify(scopes),detailType,JSON.stringify(operations),JSON.stringify(keys),s.person_id,s.person_version,ctx.now(),...guard.args);
 if(!result.meta.changes){await held(ctx,guard);fail('resource_registration_refused',409);}
 await auditDetail(ctx,s.person_id,'delegation_resource_registered',id,{kind:data.kind,audience,scopes,detailType,operations});
 return json({id,clientId,name,kind:data.kind,audience,scopes,detailType,operations},201);
}
export async function resourceInventory(ctx,request) {
 await ownerSession(ctx,request);
 const resources=await all(ctx,'SELECT id,client_id AS clientId,name,kind,audience,scopes,detail_type AS detailType,operations,disabled_at AS disabledAt FROM auth_delegation_resources ORDER BY created_at DESC');
 return json({resources:resources.map(row=>({...row,scopes:JSON.parse(row.scopes),operations:JSON.parse(row.operations)}))});
}
export async function disableResource(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['resourceId']);
 const s=await ownerSession(ctx,request),guard=both(ownerGuard(ctx,s),employerGuard(ctx));
 const result=await run(ctx,`UPDATE auth_delegation_resources SET disabled_at=?,revision=revision+1 WHERE id=? AND disabled_at IS NULL AND ${guard.clause}`,ctx.now(),data.resourceId,...guard.args);
 if(!result.meta.changes){await held(ctx,guard);fail('resource_unavailable',404);}
 await auditDetail(ctx,s.person_id,'delegation_resource_disabled',data.resourceId,{});
 return json({ok:true});
}
