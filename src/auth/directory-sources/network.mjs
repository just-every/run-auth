import {AuthError,fail} from '../core.mjs';
import {outboundUrl} from '../outbound.mjs';
import {checkedDestination,withinTimeout,readBounded} from '../hooks/network.mjs';

export const LIMITS=Object.freeze({pages:500,users:10000,groups:1000,members:100000,pageBytes:1048576,snapshotBytes:16777216});
export const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
export const invalid=()=>fail('directory_source_invalid_response',502);
export function identifier(value) {
 if(typeof value!=='string'||!value||value.length>128||value.trim()!==value||/[\x00-\x20\x7f]/.test(value))invalid();
 return value;
}
export function sourceUrl(value) {
 try{return outboundUrl({local:false},value,'directory_source_invalid_url');}
 catch{fail('directory_source_invalid_url');}
}
export function nextUrl(value,current) {
 if(typeof value!=='string'||value.length>8192)invalid();
 let url;try{url=new URL(value,current);}catch{invalid();}
 const first=new URL(current);
 if(url.origin!==first.origin||url.pathname!==first.pathname||url.username||url.password||url.hash)fail('directory_source_pagination_refused',502);
 return url.href;
}
// A snapshot has one total deadline and a bounded request count. No response
// body, credential or provider-controlled error reaches the caller on failure.
export function snapshotNetwork(ctx,authorization,signal) {
 let pages=0,members=0,bytes=0;
 return {get pages(){return pages;}, countMembers(count){members+=count;if(members>LIMITS.members)fail('directory_source_limit',413);},
  async get(value) {
   if(++pages>LIMITS.pages)fail('directory_source_limit',413);
   try{return await withinTimeout(10000,async requestSignal=>{
    const combined=AbortSignal.any([signal,requestSignal]),target=new URL(value);
    const query=target.search;target.search='';
    const checked=new URL(await checkedDestination(ctx,target.href,combined));checked.search=query;
    const response=await (ctx.connectorFetch||fetch)(checked.href,{method:'GET',redirect:'manual',signal:combined,headers:{authorization,accept:'application/json, application/scim+json'}});
    if(response.status!==200){await response.body?.cancel();fail(response.status===429?'directory_source_rate_limited':'directory_source_request_refused',response.status===429?429:502);}
    if(!/^application\/(?:scim\+)?json(?:\s*;|$)/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();invalid();}
    let body;
    const content=await readBounded(response,combined,LIMITS.pageBytes);bytes+=new TextEncoder().encode(content).length;
    if(bytes>LIMITS.snapshotBytes)fail('directory_source_limit',413);
    try{body=JSON.parse(content);}catch{invalid();}
    return {body,link:response.headers.get('link')};
   });}catch(error){if(error instanceof AuthError&&error.message.startsWith('directory_source_'))throw error;fail('directory_source_unavailable',503);}
  }
 };
}

export async function collectPages(net,initial,decode,maximum) {
 const rows=[],seen=new Set();let current=initial;
 while(current){
  if(seen.has(current))fail('directory_source_pagination_refused',502);seen.add(current);
  const response=await net.get(current),page=decode(response,current);
  if(!Array.isArray(page.rows)||page.rows.some(row=>!object(row)))invalid();
  rows.push(...page.rows);if(rows.length>maximum)fail('directory_source_limit',413);
  current=page.next?nextUrl(page.next,current):null;
 }
 return rows;
}
export function uniqueRows(rows) {
 const ids=new Set();
 for(const row of rows){const id=identifier(row.id);if(ids.has(id))fail('directory_source_duplicate_id',502);ids.add(id);}
 return rows;
}
