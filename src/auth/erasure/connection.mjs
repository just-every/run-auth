import {one} from '../core.mjs';
import {unseal} from '../keys.mjs';
import {outboundUrl} from '../outbound.mjs';

export const organizationOf=ctx=>ctx.organizationId||'root';
export const issuerOf=ctx=>ctx.issuer||ctx.origin;
const boundContext=(ctx,work)=>work.organization===organizationOf(ctx)&&work.issuer===issuerOf(ctx);
export const scimEndpoint=work=>work.baseUrl+'/'+work.resource+'/'+encodeURIComponent(work.remoteId);
export const blocked=(error,status=null)=>({state:'blocked',error,status});

// The endpoint, resource and remote account always come from sealed server
// state. A caller supplies one bearer token, never a URL or a resource ID.
export async function scimRequest(ctx,work,token,method,body,assertAuthority) {
 const url=outboundUrl(ctx,scimEndpoint(work),'invalid_erasure_remote_url').href;
 if(method!=='GET')await assertAuthority?.();
 try {
  const response=await (ctx.connectorFetch||ctx.fetch||fetch)(url,{method,redirect:'manual',signal:AbortSignal.timeout(15000),headers:{authorization:'Bearer '+token,accept:'application/scim+json',...(body?{'content-type':'application/scim+json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
  let parsed=null;
  if(method==='GET'){const text=await response.text();if(text.length<=1048576)try{parsed=JSON.parse(text);}catch{}}
  else await response.body?.cancel();
  return {status:response.status,body:parsed};
 }catch{return {status:0,body:null};}
}
export function validateFreshConnection(connection) {
 if(!connection||typeof connection!=='object'||Array.isArray(connection)||Object.keys(connection).length!==1||typeof connection.token!=='string'||!connection.token||connection.token.length>16384||/[\r\n]/.test(connection.token))return false;
 return Object.keys(connection)[0]==='token';
}
async function verifyBinding(ctx,work,token) {
 if(!work.externalId||!work.remoteId||!['Users','Groups'].includes(work.resource))return blocked('remote_connection_binding_unavailable');
 const read=await scimRequest(ctx,work,token,'GET');
 // Absence with an unknown credential cannot identify a tenant. It must never
 // turn into successful deletion, nor authorize a DELETE against that tenant.
 if(read.status!==200||String(read.body?.id)!==work.remoteId||read.body?.externalId!==work.externalId)return blocked('remote_connection_binding_unverified',read.status);
 return {token};
}
export async function scimConnection(ctx,work,transient,fresh) {
 if(transient?.token)return {token:transient.token};
 if(fresh)return verifyBinding(ctx,work,fresh.token);
 if(!boundContext(ctx,work))return blocked('remote_connection_required');
 const connector=await one(ctx,'SELECT app_id,base_url,sealed_token FROM auth_scim_connectors WHERE app_id=?',work.appId);
 if(!connector||connector.base_url!==work.baseUrl)return blocked('remote_connection_required');
 const token=await unseal(ctx,'scim:'+connector.app_id,connector.sealed_token);
 return verifyBinding(ctx,work,token);
}
export async function fenceConnection(ctx,work,transient) {
 if(transient?.signing)return transient.signing;
 if(!boundContext(ctx,work))return blocked('remote_connection_required');
 const key=await one(ctx,'SELECT kid,public_jwk,encrypted_private FROM auth_signing_keys WHERE kid=? AND (retire_at IS NULL OR retire_at>?)',work.keyId,ctx.now());
 if(!key||JSON.parse(key.public_jwk).alg!==work.alg)return blocked('remote_connection_required');
 return {jwk:await unseal(ctx,key.kid,key.encrypted_private),kid:key.kid,alg:work.alg};
}
