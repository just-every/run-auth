import {fail} from '../core.mjs';
import {collectPages,uniqueRows,LIMITS,invalid,object} from './network.mjs';
import {user,group} from './normalize.mjs';

const BASE='https://graph.microsoft.com/v1.0';
// https://learn.microsoft.com/en-us/graph/api/organization-list?view=graph-rest-1.0
// https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0
// https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0
// https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
function page({body}) {
 if(!object(body)||!Array.isArray(body.value))invalid();
 if(body['@odata.nextLink']!==undefined&&typeof body['@odata.nextLink']!=='string')invalid();
 return {rows:body.value,next:body['@odata.nextLink']};
}
export async function entraSnapshot(net,source) {
 if(source.baseUrl!==undefined&&source.baseUrl!==BASE)fail('directory_source_binding_refused',403);
 const tenant=source.organizationBinding;
 if(typeof tenant!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(tenant))fail('directory_source_binding_refused',403);
 // Graph authenticates the access token; bind its actual organization, rather
 // than trusting an unverified decoded JWT claim or an email domain.
 const org=await collectPages(net,BASE+'/organization?$select=id',page,2);
 if(org.length!==1||typeof org[0].id!=='string'||org[0].id.toLowerCase()!==tenant.toLowerCase())fail('directory_source_binding_refused',403);
 const raw=uniqueRows(await collectPages(net,BASE+'/users?$select=id,mail,userPrincipalName,displayName,accountEnabled,department,jobTitle,officeLocation&$top=100',page,LIMITS.users));
 const users=raw.map(row=>user(row,{email:row.mail??row.userPrincipalName,name:row.displayName,active:row.accountEnabled,profile:{department:row.department,title:row.jobTitle,location:row.officeLocation}}));
 const rawGroups=uniqueRows(await collectPages(net,BASE+'/groups?$select=id,displayName&$top=100',page,LIMITS.groups)),groups=[];
 for(const row of rawGroups){
  const members=uniqueRows(await collectPages(net,BASE+`/groups/${encodeURIComponent(row.id)}/members?$select=id&$top=100`,page,LIMITS.users));
  if(members.some(member=>member['@odata.type']!=='#microsoft.graph.user'))fail('directory_source_membership_unsupported',409);
  groups.push(group(row,row.displayName,members.map(member=>member.id),net));
 }
 return {users,groups,organizationId:tenant.toLowerCase()};
}
