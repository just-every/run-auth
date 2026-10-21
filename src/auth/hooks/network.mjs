import {fail,AuthError} from '../core.mjs';
import {outboundUrl} from '../outbound.mjs';

export function publicAddress(value) {
 if(typeof value!=='string')return false;
 if(/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
  const parts=value.split('.');if(parts.some(x=>! /^(0|[1-9]\d{0,2})$/.test(x)||Number(x)>255))return false;
  const [a,b,c]=parts.map(Number);
  return !(a===0||a===10||a===127||a>=224||a===100&&b>=64&&b<=127||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&(b===168||b===0&&(c===0||c===2)||b===88&&c===99)||a===198&&(b===18||b===19||b===51&&c===100)||a===203&&b===0&&c===113);
 }
 // Accept global-unicast IPv6 only, excluding special-purpose/documentation
 // allocations. URL parsing validates and canonicalizes compressed addresses.
 let host;try{host=new URL(`https://[${value}]/`).hostname.slice(1,-1);}catch{return false;}
 const [a,b]=host.split(':').map(x=>parseInt(x||'0',16));
 return a>=0x2000&&a<=0x3fff&&a!==0x2002&&!(a===0x2001&&(b<=0x1ff||b===0xdb8))&&!(a===0x3fff&&b<=0xfff);
}

export async function readBounded(response,signal,maximum=32768) {
 const reader=response.body?.getReader();if(!reader)return '';
 const chunks=[];let size=0;
 const cancel=()=>{void reader.cancel().catch(()=>{});};
 signal.addEventListener('abort',cancel,{once:true});
 try {
  for(;;) {
   if(signal.aborted)throw signal.reason;
   const {done,value}=await reader.read();if(done)break;
   size+=value.length;if(size>maximum)fail('hook_invalid_response',403);chunks.push(value);
  }
  if(signal.aborted)throw signal.reason;
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
  return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 } finally {signal.removeEventListener('abort',cancel);cancel();}
}

async function resolvePublic(ctx,hostname,signal) {
 const addresses=[];
 for(const type of ['A','AAAA']) {
  const url=new URL('https://cloudflare-dns.com/dns-query');url.searchParams.set('name',hostname);url.searchParams.set('type',type);
  let response;
  try {response=await (ctx.connectorFetch||fetch)(url.href,{headers:{accept:'application/dns-json'},redirect:'manual',signal});}
  catch {fail('hook_dns_unavailable',503);}
  if(response.status!==200){await response.body?.cancel();fail('hook_dns_unavailable',503);}
  let result;try{result=JSON.parse(await readBounded(response,signal));}catch{fail('hook_dns_unavailable',503);}
  if(result.Status!==0||result.TC||!Array.isArray(result.Answer??[]))fail('hook_dns_unavailable',503);
  for(const record of result.Answer??[]) {
   if(record.type===1||record.type===28)addresses.push(record.data);
   else if(record.type===5) {
    // A CNAME's resulting address records are checked below; an unresolved
    // chain yields no addresses and is refused, never treated as public.
    outboundUrl({...ctx,local:false},`https://${String(record.data).replace(/\.$/,'')}`,'invalid_hook_url');
   }
  }
 }
 return addresses;
}

export async function checkedDestination(ctx,value,signal) {
 const url=outboundUrl({...ctx,local:false},value,'invalid_hook_url');
 let addresses;
 try {addresses=ctx.hookResolve?await ctx.hookResolve(url.hostname,{signal}):await resolvePublic(ctx,url.hostname,signal);}
 catch(error){if(error instanceof AuthError)throw error;fail('hook_dns_unavailable',503);}
 if(!Array.isArray(addresses)||!addresses.length||!addresses.every(publicAddress))fail('invalid_hook_url');
 return url.href;
}

export async function withinTimeout(milliseconds,work) {
 const controller=new AbortController();let timer;
 const expiry=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Object.assign(new Error('hook_timeout'),{hookTimeout:true}));},milliseconds);});
 try{return await Promise.race([work(controller.signal),expiry]);}
 finally{clearTimeout(timer);controller.abort();}
}
