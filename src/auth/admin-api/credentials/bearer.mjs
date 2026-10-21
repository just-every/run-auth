import {createLocalJWKSet,jwtVerify} from 'jose';
import {one,fail,AuthError} from '../../core.mjs';
import {jwks} from '../../keys.mjs';
import {SCOPES} from './config.mjs';
import {requireLive,principalFor} from './authority.mjs';

export async function authenticateAdmin(ctx,request,scope,resource) {
 const match=/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(request.headers.get('authorization')||'');
 if(!match||match[1].length>16384)fail('admin_service_token_required',401);
 let claims,header;
 try {
  const verified=await jwtVerify(match[1],createLocalJWKSet(await jwks(ctx)),{issuer:(ctx.issuer??ctx.origin),audience:(ctx.issuer??ctx.origin)+'/api/auth/admin/v1',typ:'at+jwt',algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['exp','iat','sub','admin_service_app','revision','scope']});
  claims=verified.payload;header=verified.protectedHeader;
 }catch(error){if(error instanceof AuthError)throw error;fail('admin_service_token_refused',401);}
 const sec=Math.floor(ctx.now()/1000);
 if(header.typ!=='at+jwt'||claims.aud!==(ctx.issuer??ctx.origin)+'/api/auth/admin/v1'||typeof claims.admin_service_app!=='string'||!claims.admin_service_app||claims.admin_service_app.length>256||claims.sub!=='admin-service:'+claims.admin_service_app||!Number.isSafeInteger(claims.revision)||claims.revision<1||typeof claims.scope!=='string'||claims.scope.length>2048||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||claims.iat>sec+30||claims.exp-claims.iat>300||claims.amr!==undefined||claims.sid!==undefined||claims.role!==undefined)fail('admin_service_token_refused',401);
 const app=await one(ctx,'SELECT * FROM auth_admin_service_apps WHERE id=?',claims.admin_service_app);
 if(!app)fail('admin_service_token_refused',401);
 const tokenScopes=claims.scope.split(' ').filter(Boolean),registered=JSON.parse(app.scopes);
 const granted=[...new Set(tokenScopes.filter(s=>registered.includes(s)&&SCOPES.includes(s)))];
 try {
  if(app.revision!==claims.revision)fail('admin_service_token_refused',401);
  let state;
  try{state=await requireLive(ctx,app,request,claims.exp*1000);}catch(error){
   if(error instanceof AuthError&&error.message!=='admin_service_ip_refused')fail('admin_service_token_refused',401);
   throw error;
  }
  if(!tokenScopes.length||tokenScopes.some(s=>!SCOPES.includes(s)))fail('admin_service_token_refused',401);
  const principal=await principalFor(ctx,app,granted,claims.exp*1000,state);
  if(scope&&!principal.scopes.includes(scope))fail('admin_service_scope_required',403);
  if(resource&&!principal.permits(resource.kind,resource.id))fail('admin_service_resource_refused',403);
  return principal;
 }catch(error) {
  // Only signature-verified machine claims can name the failed call's actor.
  if(error instanceof AuthError)error.adminAudit={id:app.id,ownerId:app.owner_id,scopes:granted};
  throw error;
 }
}
