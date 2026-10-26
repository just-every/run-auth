import {fail} from '../core.mjs';
import {outboundUrl} from '../outbound.mjs';
import {checkedDestination,withinTimeout,readBounded} from '../hooks/network.mjs';

// Approved configuration still passes public-network checks on every request.
// A resolver may be injected at the DNS network edge; no approval bypass exists.
export function federationUrl(ctx,value) {
 const url=outboundUrl({...ctx,local:false},value,'invalid_federation_url');
 if(url.origin===ctx.origin)fail('federation_loop',403);
 return url.href;
}
export async function checkedFederationUrl(ctx,value,signal) {
 const url=federationUrl(ctx,value);
 return checkedDestination({...ctx,hookResolve:ctx.federationResolve??ctx.hookResolve,
  connectorFetch:ctx.federationDnsFetch??ctx.connectorFetch},url,signal);
}
export function federationFetch(ctx) {
 return async(value,init={})=>{
  const url=typeof value==='string'?value:value instanceof URL?value.href:value.url;
  const check=async signal=>checkedFederationUrl(ctx,url,signal);
  const destination=init.signal?await check(init.signal):await withinTimeout(5000,check);
  const response=await (ctx.upstreamFetch??fetch)(destination,{...init,redirect:'manual'});
  if(response.status>=300&&response.status<400||response.redirected||response.url&&response.url!==destination){await response.body?.cancel();fail('federation_redirect_refused',502);}
  return response;
 };
}
export async function fetchFederationMetadata(ctx,value) {
 return withinTimeout(10000,async signal=>{
  const response=await federationFetch(ctx)(value,{signal,headers:{accept:'application/samlmetadata+xml, application/xml, text/xml'}});
  if(response.status!==200||!/^application\/(?:samlmetadata\+xml|xml)(?:\s*;|$)|^text\/xml(?:\s*;|$)/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();fail('invalid_federation_metadata',502);}
  return readBounded(response,signal,262144);
 });
}
