import {one,all,hash,random,fail,json,limit} from '../core.mjs';
import {readBounded,withinTimeout} from '../hooks/network.mjs';
import {object,identifier,LIMITS} from './network.mjs';
import {user,group} from './normalize.mjs';
import {DIRECTORY_SOURCES,sourceOf,requireLiveSource,stageSnapshot} from './store.mjs';

const USER='urn:ietf:params:scim:schemas:core:2.0:User',GROUP='urn:ietf:params:scim:schemas:core:2.0:Group';
const ENTERPRISE='urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const PATCH='urn:ietf:params:scim:api:messages:2.0:PatchOp';
function scimDocument(type,row) {
 if(type==='Users')return {schemas:[USER,ENTERPRISE],id:row.sourceId,externalId:row.sourceId,userName:row.email,displayName:row.name,active:row.active,emails:[{value:row.email,primary:true,type:'work'}],title:row.fields.title??undefined,[ENTERPRISE]:{department:row.fields.department??undefined}};
 return {schemas:[GROUP],id:row.sourceId,externalId:row.sourceId,displayName:row.name,members:row.memberIds.map(value=>({value,type:'User'}))};
}
function normalize(type,data,id){
 if(!object(data)||!Array.isArray(data.schemas)||!data.schemas.includes(type==='Users'?USER:GROUP)||data.id!==undefined&&data.id!==id||data.externalId!==undefined&&data.externalId!==id)fail('directory_scim_invalid_resource');
 if(type==='Users'){
  if(data.emails!==undefined&&(!Array.isArray(data.emails)||data.emails.some(row=>!object(row))))fail('directory_scim_invalid_resource');
  const address=data.emails?.find(row=>row.primary===true)?.value??data.userName;
  return user({id},{email:address,name:data.displayName??data.name?.formatted,active:data.active??true,profile:{title:data.title,department:data[ENTERPRISE]?.department}});
 }
 if(data.members!==undefined&&(!Array.isArray(data.members)||data.members.some(row=>!object(row)||row.type!==undefined&&row.type!=='User')))fail('directory_source_membership_unsupported',409);
 return group({id},data.displayName,(data.members??[]).map(row=>row.value),{countMembers(n){if(n>LIMITS.members)fail('directory_source_limit',413);}});
}
function patch(type,stored,data){
 if(!object(data)||!Array.isArray(data.schemas)||!data.schemas.includes(PATCH)||!Array.isArray(data.Operations)||!data.Operations.length||data.Operations.length>100)fail('directory_scim_invalid_patch');
 const document=scimDocument(type,stored),allowed=new Set(type==='Users'?['userName','displayName','active','emails','name','title',ENTERPRISE]:['displayName','members']);
 for(const operation of data.Operations){
  if(!object(operation)||!['add','replace','remove'].includes(String(operation.op).toLowerCase()))fail('directory_scim_invalid_patch');
  const op=operation.op.toLowerCase(),path=operation.path;
  if(path===undefined){
   if(op==='remove'||!object(operation.value)||Object.keys(operation.value).some(key=>!allowed.has(key)))fail('directory_scim_invalid_patch');
   for(const [key,value] of Object.entries(operation.value))document[key]=key==='members'&&op==='add'?[...(document.members??[]),...value]:value;
  }else if(typeof path==='string'&&allowed.has(path)){
   if(op==='remove'){if(path==='active'||path==='userName'||path==='displayName')fail('directory_scim_invalid_patch');delete document[path];}
   else if(path==='members'&&op==='add'){
    if(!Array.isArray(operation.value))fail('directory_scim_invalid_patch');document.members.push(...operation.value);
   }else document[path]=operation.value;
  }else if(type==='Groups'&&op==='remove'&&typeof path==='string'&&/^members\[value eq "[^"\\]+"\]$/.test(path)){
   const id=path.slice(18,-2);document.members=document.members.filter(member=>member.value!==id);
  }else if(type==='Users'&&path===ENTERPRISE+':department'){
   document[ENTERPRISE]={...document[ENTERPRISE],department:op==='remove'?undefined:operation.value};
  }else fail('directory_scim_unsupported_patch',409);
 }
 return normalize(type,document,stored.sourceId);
}
export async function directorySourceScim(ctx,request,path=new URL(request.url).pathname) {
 const match=new RegExp('^'+DIRECTORY_SOURCES+'/scim/([^/]+)/(Users|Groups)(?:/([^/]+))?/?$').exec(path);
 if(!match)fail('directory_scim_not_found',404);
 const source=await sourceOf(ctx,match[1]),token=request.headers.get('authorization');
 if(source.kind!=='scim'||source.mode!=='push'||!token?.startsWith('Bearer ')||token.length>1024||!source.ingress_hash||await hash(token.slice(7))!==source.ingress_hash)fail('directory_scim_token_required',401);
 const guard=await requireLiveSource(ctx,source);
 if(source.organization_binding!==(ctx.issuer??ctx.origin))fail('directory_source_binding_refused',403);
 if(!await limit(ctx,'directory-ingress:'+source.id,120,60000))fail('rate_limited',429);
 const type=match[2];let id;try{id=match[3]?decodeURIComponent(match[3]):null;}catch{fail('directory_scim_invalid_id');}if(id)identifier(id);
 const stored=id?await one(ctx,'SELECT document,deleted FROM auth_directory_resources WHERE source_id=? AND resource_type=? AND external_id=?',source.id,type,id):null;
 if(request.method==='GET'){
  if(id){if(!stored||stored.deleted)fail('directory_scim_not_found',404);return json(scimDocument(type,JSON.parse(stored.document)));}
  const query=new URL(request.url).searchParams;
  if(query.has('filter')||query.has('sortBy'))fail('directory_scim_filter_unsupported',400);
  const start=Number(query.get('startIndex')??1),count=Number(query.get('count')??100);
  if(!Number.isSafeInteger(start)||start<1||!Number.isSafeInteger(count)||count<0||count>200)fail('directory_scim_invalid_page');
  const rows=await all(ctx,'SELECT document FROM auth_directory_resources WHERE source_id=? AND resource_type=? AND deleted=0 ORDER BY external_id LIMIT ? OFFSET ?',source.id,type,count,start-1);
  const total=(await one(ctx,'SELECT COUNT(*) AS n FROM auth_directory_resources WHERE source_id=? AND resource_type=? AND deleted=0',source.id,type)).n;
  return json({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:total,startIndex:start,itemsPerPage:rows.length,Resources:rows.map(row=>scimDocument(type,JSON.parse(row.document)))});
 }
 if(!['POST','PATCH','DELETE'].includes(request.method)||request.method==='POST'&&id||request.method!=='POST'&&!id)fail('directory_scim_method_refused',405);
 let data;
 if(request.method!=='DELETE'){
  if(!/^application\/(?:scim\+)?json(?:\s*;|$)/i.test(request.headers.get('content-type')??''))fail('unsupported_content_type',415);
  try{data=JSON.parse(await withinTimeout(10000,signal=>readBounded(request,signal,65536)));}catch{fail('directory_scim_invalid_json');}
 }
 if(request.method==='POST'){
  id=identifier(data?.externalId??data?.id??random());
  if(await one(ctx,'SELECT 1 FROM auth_directory_resources WHERE source_id=? AND resource_type=? AND external_id=?',source.id,type,id))fail('directory_scim_resource_exists',409);
 }else if(!stored||stored.deleted)fail('directory_scim_not_found',404);
 let row=request.method==='DELETE'?{...JSON.parse(stored.document),deleted:true,...(type==='Users'?{active:false}:{memberIds:[]})}:request.method==='PATCH'?patch(type,JSON.parse(stored.document),data):normalize(type,data,id);
 if(type==='Groups')for(const member of row.memberIds)if(!await one(ctx,"SELECT 1 FROM auth_directory_resources WHERE source_id=? AND resource_type='Users' AND external_id=? AND deleted=0",source.id,member))fail('directory_source_unknown_member',409);
 const observed=await stageSnapshot(ctx,source,{complete:false,users:type==='Users'?[row]:[],groups:type==='Groups'?[row]:[]},guard,{resource:{type,id,document:row}});
 if(request.method==='DELETE')return new Response(null,{status:204,headers:{'cache-control':'no-store','x-auth-directory-snapshot':observed.snapshotId}});
 return json(scimDocument(type,row),request.method==='POST'?201:200,{location:(ctx.issuer??ctx.origin)+DIRECTORY_SOURCES+'/scim/'+source.id+'/'+type+'/'+encodeURIComponent(id),'x-auth-directory-snapshot':observed.snapshotId});
}
