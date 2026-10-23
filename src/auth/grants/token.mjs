import {employeePrincipal} from '../tokens/resource.mjs';
import {createLocalJWKSet,decodeJwt,jwtVerify} from 'jose';
import {AuthError,all,auditDetail,fail,hash,json,limit,one,random,run} from '../core.mjs';
import {ensureSigningKey,signToken} from '../keys.mjs';
import {CLIENT_PREFIX} from './config.mjs';
import {apiRow,guardHolds,issuer,organization,serviceGuard,serviceRow} from './authority.mjs';

const ASSERTION_TYPE='urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
function namedService(request,form) {
 const names=[form.get('client_id')],raw=form.get('client_assertion');
 if(raw&&raw.length<=16384){try{const c=decodeJwt(raw);names.push(c.iss,c.sub);}catch{}}
 // An incorrectly authenticated resource client still belongs to this namespace.
 const basic=/^Basic ([A-Za-z0-9+/=]+)$/i.exec(request.headers.get('authorization')||'');
 if(basic){try{const decoded=atob(basic[1]);names.push(decodeURIComponent(decoded.slice(0,decoded.indexOf(':',CLIENT_PREFIX.length))));}catch{}}
 return names.find(n=>typeof n==='string'&&n.startsWith(CLIENT_PREFIX))??null;
}
async function consumeAssertion(ctx,app,form) {
 let claims;
 const audience=issuer(ctx)+'/oidc/token';
 try {
  ({payload:claims}=await jwtVerify(form.get('client_assertion'),createLocalJWKSet(JSON.parse(app.jwks)),{issuer:app.client_id,subject:app.client_id,audience,algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['exp','iat','jti']}));
 }catch{fail('invalid_client',401);}
 const now=Math.floor(ctx.now()/1000);
 if(claims.aud!==audience||typeof claims.jti!=='string'||!claims.jti||claims.jti.length>256||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||claims.iat>now+30||claims.iat<now-300||claims.exp>now+300||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>300)fail('invalid_client',401);
 const g=serviceGuard(ctx,app);
 await run(ctx,`DELETE FROM auth_resource_assertions WHERE service_id=? AND expires_at<=? AND ${g.clause}`,app.id,ctx.now(),...g.args);
 let inserted;
 try {inserted=await run(ctx,`INSERT INTO auth_resource_assertions(service_id,jti,expires_at) SELECT ?,?,? WHERE ${g.clause}`,app.id,claims.jti,claims.exp*1000,...g.args);}catch{fail('invalid_client',401);}
 if(!inserted.meta.changes)fail('invalid_client',401);
}
export async function resourceToken(ctx,request) {
 const text=await request.clone().text(),form=new URLSearchParams(text),clientId=namedService(request,form);
 if(!clientId)return null;
 let service=null,scopes=[];
 try {
  if(!await limit(ctx,'resource-token:'+await hash(clientId),60,60000))fail('rate_limited',429);
  if(text.length>32768||!(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded')||[...form.keys()].some(k=>form.getAll(k).length!==1))fail('invalid_request');
  if(form.get('grant_type')!=='client_credentials')fail('unsupported_grant_type');
  service=await serviceRow(ctx,clientId);
  if(!service||request.headers.has('authorization')||form.has('client_secret')||form.get('client_assertion_type')!==ASSERTION_TYPE||!form.get('client_assertion')||form.get('client_assertion').length>16384||form.has('client_id')&&form.get('client_id')!==service.client_id||!await guardHolds(ctx,serviceGuard(ctx,service)))fail('invalid_client',401);
  const registered=JSON.parse(service.scopes),requested=form.get('scope');
  scopes=requested===null?[...registered]:[...new Set(requested.trim().split(/\s+/).filter(Boolean))];
  if(!scopes.length||scopes.some(s=>!registered.includes(s)))fail('invalid_scope');
  const api=await apiRow(ctx,service.api_id);
  if(!api||scopes.some(s=>!JSON.parse(api.policy).scopes.includes(s)))fail('invalid_scope');
  await consumeAssertion(ctx,service,form);
  const now=Math.floor(ctx.now()/1000),expiresAt=Math.min(now+300,Math.floor(service.expires_at/1000));
  if(expiresAt<=now)fail('invalid_client',401);
  await ensureSigningKey(ctx);
  // This profile is verified online using the tenant's current local JWKS.
  const token=await signToken({...ctx,origin:issuer(ctx)},{aud:api.audience,sub:CLIENT_PREFIX+service.id,client_id:service.client_id,resource_service:service.id,api_id:api.id,api_revision:api.revision,organization_id:organization(ctx),owner_id:service.owner_id,owner_version:service.owner_version,revision:service.revision,scope:scopes.join(' '),jti:random()},{typ:'at+jwt',expiresAt,published:true});
  const g=serviceGuard(ctx,service,expiresAt*1000,api.revision);
  if(!(await run(ctx,`UPDATE auth_resource_services SET last_used_at=? WHERE id=? AND ${g.clause}`,ctx.now(),service.id,...g.args)).meta.changes)fail('invalid_client',401);
  await auditDetail(ctx,service.client_id,'resource_service_token',service.api_id,{service:service.id,owner:service.owner_id,scope:scopes.join(' '),audience:api.audience,result:'issued'});
  return json({access_token:token,token_type:'Bearer',expires_in:expiresAt-Math.floor(ctx.now()/1000),scope:scopes.join(' ')});
 }catch(error) {
  await auditDetail(ctx,clientId.slice(0,256),'resource_service_token',service?.api_id??null,{service:service?.id??null,owner:service?.owner_id??null,result:error instanceof AuthError?error.message:'server_error'});
  if(!(error instanceof AuthError))throw error;
  return json({error:error.message},error.status,error.status===429?{'retry-after':'60'}:{});
 }
}
export async function resourcePrincipal(ctx,request,apiId) {
 const raw=/^(?:Bearer|DPoP) ([A-Za-z0-9._~-]+)$/i.exec(request.headers.get('authorization')||'');
 if(!raw||raw[1].length>16384)fail('invalid_resource_token',401);
 const api=await apiRow(ctx,apiId);
 if(!api)fail('invalid_resource_token',401);
 let claims,header;
 try {
  const keys=(await all(ctx,'SELECT public_jwk FROM auth_signing_keys WHERE retire_at IS NULL OR retire_at>?',ctx.now())).map(r=>JSON.parse(r.public_jwk));
  const verified=await jwtVerify(raw[1],createLocalJWKSet({keys}),{issuer:issuer(ctx),audience:api.audience,algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['exp','iat','jti']});
  claims=verified.payload;header=verified.protectedHeader;
 }catch{fail('invalid_resource_token',401);}
 if(header.typ!=='at+jwt'||claims.aud!==api.audience||claims.organization_id!==organization(ctx)||claims.api_id!==api.id||claims.api_revision!==api.revision||typeof claims.client_id!=='string'||typeof claims.scope!=='string'||!Number.isSafeInteger(claims.exp)||!Number.isSafeInteger(claims.iat)||claims.exp-claims.iat>300||claims.exp<=claims.iat||claims.iat>Math.floor(ctx.now()/1000)+30)fail('invalid_resource_token',401);
 if(claims.refresh_family) {
  if(!/^DPoP /i.test(request.headers.get('authorization')))fail('invalid_resource_token',401);
  return employeePrincipal(ctx,request,api,claims,raw[1]);
 }
 if(!claims.client_id.startsWith(CLIENT_PREFIX)||!/^Bearer /i.test(request.headers.get('authorization')))fail('invalid_resource_token',401);
 const service=await serviceRow(ctx,claims.client_id);
 if(!service||claims.resource_service!==service.id||claims.sub!==CLIENT_PREFIX+service.id||claims.revision!==service.revision||claims.owner_id!==service.owner_id||claims.owner_version!==service.owner_version||service.api_id!==api.id||!await guardHolds(ctx,serviceGuard(ctx,service,claims.exp*1000,api.revision)))fail('invalid_resource_token',401);
 const scopes=claims.scope.split(' '),registered=JSON.parse(service.scopes);
 if(!scopes.length||scopes.some(s=>!s||!registered.includes(s)))fail('invalid_resource_token',401);
 return {kind:'service',id:service.id,clientId:service.client_id,ownerId:service.owner_id,ownerVersion:service.owner_version,scopes,resources:JSON.parse(service.resources),service,api,expiresAt:claims.exp*1000};
}
