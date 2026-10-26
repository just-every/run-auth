import {fail} from '../core.mjs';
import {sourceUrl,collectPages,uniqueRows,LIMITS,invalid} from './network.mjs';
import {user,group} from './normalize.mjs';

// https://developer.okta.com/docs/api/#pagination
// https://developer.okta.com/okta-sdk-java/25.0.0/apidocs/apidocs/com/okta/sdk/resource/api/UserApi.html
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Group/
function page({body,link}) {
 if(!Array.isArray(body))invalid();
 let next=null;
 if(link){
  if(link.length>16384)invalid();
  for(const part of link.split(/,(?=\s*<)/)){
   const match=/^\s*<([^>]+)>\s*;\s*rel="([^"]+)"(?:\s*;[^,]*)?\s*$/.exec(part);
   if(!match)invalid();
   if(match[2].split(' ').includes('next')){if(next)invalid();next=match[1];}
  }
 }
 return {rows:body,next};
}
export async function oktaSnapshot(net,source) {
 const base=sourceUrl(source.baseUrl);
 if(base.pathname!=='/'||base.origin!==source.organizationBinding)fail('directory_source_binding_refused',403);
 const usersUrl=new URL('/api/v1/users',base);usersUrl.searchParams.set('limit','200');
 // Unfiltered Okta listings omit deprovisioned users. A supported timestamp
 // filter includes those users without eventually consistent search results.
 usersUrl.searchParams.set('filter','lastUpdated gt "1970-01-01T00:00:00.000Z"');
 const raw=uniqueRows(await collectPages(net,usersUrl.href,page,LIMITS.users));
 const statuses=new Set(['STAGED','PROVISIONED','ACTIVE','RECOVERY','LOCKED_OUT','PASSWORD_EXPIRED','SUSPENDED','DEPROVISIONED']);
 const users=raw.map(row=>{
  if(!statuses.has(row.status)||!row.profile)invalid();
  return user(row,{email:row.profile.email,name:row.profile.displayName||[row.profile.firstName,row.profile.lastName].filter(Boolean).join(' '),active:['ACTIVE','PASSWORD_EXPIRED'].includes(row.status),profile:{department:row.profile.department,title:row.profile.title,location:row.profile.city}});
 });
 const rawGroups=uniqueRows(await collectPages(net,new URL('/api/v1/groups?limit=200',base).href,page,LIMITS.groups)),groups=[];
 for(const row of rawGroups){
  const members=uniqueRows(await collectPages(net,new URL(`/api/v1/groups/${encodeURIComponent(row.id)}/users?limit=200`,base).href,page,LIMITS.users));
  groups.push(group(row,row.profile?.name,members.map(member=>member.id),net));
 }
 return {users,groups,organizationId:base.origin};
}
