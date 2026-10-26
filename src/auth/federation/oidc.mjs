import {createOidcProviders,createOidcHandler} from '../../modules/operator-auth/identity/oidc/index.mjs';
import {configurationHash} from '../domain-policy.mjs';
import {hash,fail} from '../core.mjs';
import {federationFetch,federationUrl} from './network.mjs';

// Only reviewed subject associations admit generic OIDC identities. The Base
// legacy preset supplies protocol validation, never its verified-email policy.
export function normalizeOidcProvider(ctx,provider) {
 if(provider.preset!=='oidc')return provider;
 const pins=provider.endpointPins;
 if(!pins||Object.keys(pins).some(k=>!['authorization','token','jwks'].includes(k)))fail('invalid_federation_endpoints');
 federationUrl(ctx,provider.issuer);
 const issuer=provider.issuer;
 for(const name of ['authorization','token','jwks'])federationUrl(ctx,pins[name]);
 return {...provider,issuer,preset:'legacy-rs256',endpointPins:{...pins},
  endpointOrigins:[...new Set([issuer,...Object.values(pins)].map(value=>new URL(value).origin))],
  redirectUri:provider.redirectUri??`${ctx.issuer??ctx.origin}/auth/oidc/${provider.id}/callback`};
}

export function createFederationOidc(ctx,{providers=ctx.upstreamProviders??[],admission}={}) {
 const selected=providers.filter(provider=>provider.preset!=='saml');
 if(selected.some(provider=>!['google','microsoft','okta','oidc'].includes(provider.preset)))fail('unsupported_upstream',503);
 const originals=new Map(selected.map(provider=>[provider.id,provider]));
 let runtime;
 const ready=()=>runtime??=(async()=>{
  const revision=await Promise.all(selected.map(configurationHash));
  const base=createOidcProviders({db:ctx.db,admission:{async admit(request,principal,options){
   const original=originals.get(principal.provider);
   if(original?.preset==='oidc'||original?.federationSetupId) {
    const associatedEmail=Object.hasOwn(original.subjectEmails??{},principal.subject)?principal.associatedEmail:undefined;
    if(!associatedEmail)fail('federation_subject_unmapped',403);
    principal={...principal,email:undefined,emailVerified:false,emailVerifiedAt:undefined,associatedEmail,protocol:'oidc'};
   }
   return admission.admit(request,principal,options);
  }},enabled:async()=>true,config:{origin:ctx.origin,local:ctx.local,transactionSecret:await hash(ctx.secret+'\0'+JSON.stringify(revision)),providers:selected.map(provider=>normalizeOidcProvider(ctx,provider))},
  clock:ctx.now,clientIp:request=>request.headers.get('cf-connecting-ip')||'',fetch:federationFetch(ctx),waitUntil:ctx.waitUntil});
  return {providers:base,fetch:createOidcHandler(base)};
 })();
 const proxies=['list','links','relink','unlink','begin','callback'];
 const providerApi=Object.fromEntries(proxies.map(name=>[name,async(...args)=>(await ready()).providers[name](...args)]));
 providerApi.list=async()=>((await (await ready()).providers.list()).map(provider=>({...provider,preset:originals.get(provider.id)?.preset??provider.preset})));
 providerApi.ids=Object.freeze(selected.map(provider=>provider.id));
 return {providers:providerApi,async fetch(request){
  if(ctx.basePath&&/^\/auth\/oidc\/[a-z][a-z0-9-]{0,31}\/callback$/.test(new URL(request.url).pathname)){
   const url=new URL(request.url);url.pathname=ctx.basePath+url.pathname;request=new Request(url,request);
  }
  return (await ready()).fetch(request);
 }};
}
