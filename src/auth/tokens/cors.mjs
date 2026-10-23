import {all} from '../core.mjs';

// Public SDKs carry no Auth cookies. Only explicitly enabled general profiles
// with a registered HTTPS (or local-loopback) callback admit that web origin.
export async function refreshCors(ctx,request,response=null) {
 const path=new URL(request.url).pathname;
 if(!['/oidc/token','/api/auth/resource-apis/check'].includes(path))return response;
 const origin=request.headers.get('origin');if(!origin||origin==='null'||origin===ctx.origin)return response;
 const clients=await all(ctx,'SELECT c.redirect_uris FROM auth_oidc_clients c JOIN auth_refresh_profiles p ON p.client_id=c.client_id JOIN auth_apps a ON a.id=c.app_id WHERE p.enabled=1 AND a.disabled_at IS NULL');
 if(!clients.some(c=>JSON.parse(c.redirect_uris).some(uri=>{const u=new URL(uri);return ['https:','http:'].includes(u.protocol)&&u.origin===origin;})))return response;
 const headers={'access-control-allow-origin':origin,'access-control-allow-methods':'POST','access-control-allow-headers':'content-type,authorization,dpop','access-control-expose-headers':'dpop-nonce','vary':'Origin'};
 if(request.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(!response)return null;
 for(const [key,value] of Object.entries(headers))response.headers.set(key,value);
 return response;
}
