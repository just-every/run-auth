import {fail} from '../core.mjs';
import {collectPages,uniqueRows,LIMITS,invalid,object} from './network.mjs';
import {user,group} from './normalize.mjs';

const BASE='https://admin.googleapis.com/admin/directory/v1';
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/customers/get
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/list
function page(key) {
 return ({body},current)=>{
  if(!object(body)||body.kind!=='directory#'+key||body[key]!==undefined&&!Array.isArray(body[key]))invalid();
  let next=null;
  if(body.nextPageToken!==undefined){if(typeof body.nextPageToken!=='string'||!body.nextPageToken||body.nextPageToken.length>4096)invalid();const url=new URL(current);url.searchParams.set('pageToken',body.nextPageToken);next=url.href;}
  return {rows:body[key]??[],next};
 };
}
export async function googleSnapshot(net,source) {
 if(source.baseUrl!==undefined&&source.baseUrl!==BASE)fail('directory_source_binding_refused',403);
 const customer=source.organizationBinding;
 if(typeof customer!=='string'||!/^C[a-zA-Z0-9_-]{2,63}$/.test(customer))fail('directory_source_binding_refused',403);
 const {body:identity}=await net.get(BASE+'/customers/my_customer');
 if(!object(identity)||identity.kind!=='admin#directory#customer'||identity.id!==customer)fail('directory_source_binding_refused',403);
 const query=new URLSearchParams({customer,maxResults:'200'});
 const raw=uniqueRows(await collectPages(net,BASE+'/users?'+query,page('users'),LIMITS.users));
 const users=raw.map(row=>{
  if(row.customerId!==customer||typeof row.suspended!=='boolean'||row.archived!==undefined&&typeof row.archived!=='boolean')fail('directory_source_binding_refused',403);
  if(row.organizations!==undefined&&!Array.isArray(row.organizations))invalid();
  const primary=row.organizations?.find(organization=>object(organization)&&organization.primary===true);
  return user(row,{email:row.primaryEmail,name:row.name?.fullName,active:!row.suspended&&!row.archived,profile:{department:primary?.department,title:primary?.title}});
 });
 const rawGroups=uniqueRows(await collectPages(net,BASE+'/groups?'+query,page('groups'),LIMITS.groups)),groups=[];
 for(const row of rawGroups){
  const members=uniqueRows(await collectPages(net,BASE+`/groups/${encodeURIComponent(row.id)}/members?maxResults=200&includeDerivedMembership=false`,page('members'),LIMITS.users));
  if(members.some(member=>member.type!=='USER'))fail('directory_source_membership_unsupported',409);
  groups.push(group(row,row.name,members.map(member=>member.id),net));
 }
 return {users,groups,organizationId:customer};
}
