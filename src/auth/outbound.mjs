// Addresses Auth itself calls (SCIM services, event subscribers): https on a
// public host name; a local install may also call loopback http. IP literals,
// private ranges and internal names are refused, so a subscriber or connector
// cannot point Auth at its own network.
import {fail,isLoopback} from './core.mjs';

const PRIVATE=/^(10|127|169\.254|192\.168|172\.(1[6-9]|2\d|3[01]))\.|^\[?(fc|fd|fe80|::1)/i;
export function outboundUrl(ctx,value,code,{query=false}={}) {
 let url;try{url=new URL(String(value||'').trim());}catch{fail(code);}
 if(url.username||url.password||url.hash||(!query&&url.search))fail(code);
 if(ctx.local&&url.protocol==='http:'&&isLoopback(url.hostname))return url;
 if(url.protocol!=='https:'||isLoopback(url.hostname)||PRIVATE.test(url.hostname)||/^\d+\.\d+\.\d+\.\d+$/.test(url.hostname)||url.hostname.startsWith('[')||!url.hostname.includes('.')||/\.(internal|local|lan|home|corp)$/i.test(url.hostname))fail(code);
 return url;
}
