import {fail} from '../core.mjs';
import {sourceUrl,collectPages,uniqueRows,LIMITS,invalid,object} from './network.mjs';
import {user,group} from './normalize.mjs';

const LIST='urn:ietf:params:scim:api:messages:2.0:ListResponse';
const ENTERPRISE='urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
// https://www.rfc-editor.org/rfc/rfc7644.html#section-3.4.2.4
// https://www.rfc-editor.org/rfc/rfc7643.html#section-4
function listPage(){
 let total=null;
 return ({body},current)=>{
  if(!object(body)||!Array.isArray(body.schemas)||!body.schemas.includes(LIST)||!Number.isSafeInteger(body.totalResults)||body.totalResults<0)invalid();
  if(total!==null&&total!==body.totalResults)fail('directory_source_snapshot_changed',409);total=body.totalResults;
  const rows=body.Resources??[],start=Number(new URL(current).searchParams.get('startIndex'));
  if(!Array.isArray(rows)||rows.length>200||rows.length>total||start-1+rows.length>total)invalid();
  if(body.startIndex!==undefined&&body.startIndex!==start||body.itemsPerPage!==undefined&&body.itemsPerPage!==rows.length)invalid();
  let next=null;
  if(start-1+rows.length<total){
   if(!rows.length||body.startIndex!==start||body.itemsPerPage!==rows.length)invalid();
   const url=new URL(current);url.searchParams.set('startIndex',String(start+rows.length));next=url.href;
  }
  return {rows,next};
 };
}
export async function scimSnapshot(net,source) {
 const base=sourceUrl(source.baseUrl);
 if(base.origin!==source.organizationBinding)fail('directory_source_binding_refused',403);
 const path=base.href.replace(/\/+$/,'');
 const raw=uniqueRows(await collectPages(net,path+'/Users?startIndex=1&count=200',listPage(),LIMITS.users));
 const users=raw.map(row=>{
  if(!Array.isArray(row.schemas)||!row.schemas.includes('urn:ietf:params:scim:schemas:core:2.0:User'))invalid();
  if(row.emails!==undefined&&!Array.isArray(row.emails))invalid();
  const address=row.emails?.find(entry=>entry.primary===true)?.value??row.emails?.find(entry=>entry.type==='work')?.value??row.userName;
  return user(row,{email:address,name:row.displayName||row.name?.formatted,active:row.active,profile:{department:row[ENTERPRISE]?.department,title:row.title}});
 });
 const rawGroups=uniqueRows(await collectPages(net,path+'/Groups?startIndex=1&count=200',listPage(),LIMITS.groups));
 const groups=rawGroups.map(row=>{
  if(!Array.isArray(row.schemas)||!row.schemas.includes('urn:ietf:params:scim:schemas:core:2.0:Group'))invalid();
  if(row.members!==undefined&&!Array.isArray(row.members))invalid();
  if(row.members?.some(member=>!object(member)||member.type!==undefined&&member.type!=='User'))fail('directory_source_membership_unsupported',409);
  return group(row,row.displayName,(row.members??[]).map(member=>member.value),net);
 });
 return {users,groups,organizationId:base.origin};
}
