// A SCIM 2.0 service provider as Auth reaches it: one connector per app, its
// bearer credential sealed under AUTH_ENCRYPTION_KEY and used only here.
import {one,fail,isLoopback} from '../core.mjs';
import {unseal} from '../keys.mjs';

export const USER='urn:ietf:params:scim:schemas:core:2.0:User',GROUP='urn:ietf:params:scim:schemas:core:2.0:Group',PATCH='urn:ietf:params:scim:api:messages:2.0:PatchOp';
const TIMEOUT=15000,MAX_BODY=1048576;

export function scimBase(ctx,value) {
 let url;try{url=new URL(String(value||''));}catch{fail('invalid_scim_url');}
 if(url.username||url.password||url.hash||url.search||!(url.protocol==='https:'||(ctx.local&&url.protocol==='http:'&&isLoopback(url.hostname))))fail('invalid_scim_url');
 if(!ctx.local&&(isLoopback(url.hostname)||/^(10|127|169\.254|192\.168|172\.(1[6-9]|2\d|3[01]))\.|^\[?(fc|fd|fe80|::1)/i.test(url.hostname)||/^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)))fail('invalid_scim_url');
 return url.href.replace(/\/+$/,'');
}
export const connectorOf=(ctx,appId)=>one(ctx,'SELECT * FROM auth_scim_connectors WHERE app_id=?',appId);

// {status, body, retryAfter}; status 0 is a network failure or timeout.
export async function scim(ctx,connector,method,path,body) {
 const token=await unseal(ctx,'scim:'+connector.app_id,connector.sealed_token);
 let response;
 try {
  response=await (ctx.connectorFetch||fetch)(connector.base_url+path,{method,redirect:'manual',signal:AbortSignal.timeout(TIMEOUT),headers:{authorization:`Bearer ${token}`,accept:'application/scim+json, application/json',...(body?{'content-type':'application/scim+json'}:{})},body:body?JSON.stringify(body):undefined});
 } catch {return {status:0,body:null,retryAfter:null};}
 const text=await response.text().catch(()=>'');
 let parsed=null;if(text&&text.length<=MAX_BODY){try{parsed=JSON.parse(text);}catch{parsed=null;}}
 return {status:response.status,body:parsed,retryAfter:response.headers.get('retry-after')};
}
export const ok=r=>r.status>=200&&r.status<300;
export const retryable=r=>r.status===0||r.status===429||r.status>=500;
const quote=v=>`"${String(v).replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`;
export async function findOne(ctx,connector,resource,attribute,value) {
 const r=await scim(ctx,connector,'GET',`/${resource}?filter=${encodeURIComponent(`${attribute} eq ${quote(value)}`)}&startIndex=1&count=2`);
 if(!ok(r))return {response:r,found:null};
 const match=(r.body?.Resources??[]).filter(x=>x?.[attribute]===value||String(x?.[attribute]).toLowerCase()===String(value).toLowerCase());
 return {response:r,found:match[0]??null};
}

// Connection check: the service's own configuration, then a read of one user.
export async function testConnection(ctx,connector) {
 const config=await scim(ctx,connector,'GET','/ServiceProviderConfig');
 const users=await scim(ctx,connector,'GET','/Users?startIndex=1&count=1');
 return {ok:ok(users),configStatus:config.status,usersStatus:users.status,patch:config.body?.patch?.supported??null,filter:config.body?.filter?.supported??null,totalUsers:users.body?.totalResults??null};
}
