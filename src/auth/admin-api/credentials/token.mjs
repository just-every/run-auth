import {createLocalJWKSet,decodeJwt,jwtVerify} from 'jose';
import {AuthError,auditDetail,fail,hash,json,limit,random,run} from '../../core.mjs';
import {signToken,ensureSigningKey} from '../../keys.mjs';
import {CLIENT_PREFIX,SCOPES} from './config.mjs';
import {serviceRow,requireLive,liveGuard} from './authority.mjs';

const ASSERTION_TYPE='urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const RATE=60,WINDOW=60000;
const rateHeaders={'ratelimit-limit':String(RATE),'ratelimit-reset':'60','ratelimit-policy':`${RATE};w=60`,pragma:'no-cache'};
function namedService(request,form) {
 const names=[form.get('client_id')];
 const assertion=form.get('client_assertion');
 if(assertion&&assertion.length<=16384){try{const claims=decodeJwt(assertion);names.push(claims.iss,claims.sub);}catch{}}
 const basic=/^Basic ([A-Za-z0-9+/=]+)$/i.exec(request.headers.get('authorization')||'');
 if(basic){try{const value=atob(basic[1]),at=value.indexOf(':',value.startsWith(CLIENT_PREFIX)?CLIENT_PREFIX.length:0);names.push(decodeURIComponent(value.slice(0,at<0?value.length:at)));}catch{}}
 return names.find(name=>typeof name==='string'&&name.startsWith(CLIENT_PREFIX))??null;
}
async function record(ctx,app,clientId,scopes,result) {
 const id=app?.id??clientId.slice(0,256);
 await auditDetail(ctx,'admin-service:'+id,'admin_service_token',id,{serviceApp:app?.id??null,clientId:clientId.slice(0,256),owner:app?.owner_id??null,scope:scopes.join(' '),result});
}
async function assertion(ctx,app,form) {
 let claims;
 try {
  ({payload:claims}=await jwtVerify(form.get('client_assertion'),createLocalJWKSet(JSON.parse(app.jwks)),{issuer:app.client_id,subject:app.client_id,audience:(ctx.issuer??ctx.origin)+'/oidc/token',algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['exp','iat','jti']}));
 }catch{fail('invalid_client',401);}
 const now=Math.floor(ctx.now()/1000);
 if(claims.aud!==(ctx.issuer??ctx.origin)+'/oidc/token'||typeof claims.jti!=='string'||!claims.jti||claims.jti.length>256||!Number.isSafeInteger(claims.iat)||!Number.isSafeInteger(claims.exp)||claims.iat>now+30||claims.iat<now-300||claims.exp>now+300||claims.exp<=now||claims.exp<=claims.iat||claims.exp-claims.iat>300)fail('invalid_client',401);
 const guard=liveGuard(ctx,app,app.expires_at);
 let consumed;
 try {
  consumed=await run(ctx,`INSERT INTO auth_admin_service_assertions(service_app_id,jti,expires_at) SELECT ?,?,? WHERE ${guard.clause}`,app.id,claims.jti,claims.exp*1000,...guard.args);
 }catch{fail('invalid_client',401);}
 if(!consumed.meta.changes)fail('invalid_client',401);
}
// A clone lets the existing general and RER token profiles read their own body
// when this request does not name the separate machine administration namespace.
export async function adminToken(ctx,request) {
 const text=await request.clone().text(),form=new URLSearchParams(text),clientId=namedService(request,form);
 if(!clientId)return null;
 let app=null,scopes=[];
 try {
  app=await serviceRow(ctx,clientId);
  if(!await limit(ctx,'admin-service-token:'+await hash(clientId),RATE,WINDOW))fail('rate_limited',429);
  if(text.length>32768||!(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded')||[...form.keys()].some(k=>form.getAll(k).length!==1))fail('invalid_request');
  if(form.get('grant_type')!=='client_credentials')fail('unsupported_grant_type');
  if(!app||request.headers.has('authorization')||form.has('client_secret')||form.get('client_assertion_type')!==ASSERTION_TYPE||!form.get('client_assertion')||form.get('client_assertion').length>16384||form.has('client_id')&&form.get('client_id')!==app.client_id)fail('invalid_client',401);
  try{await requireLive(ctx,app,request);}catch(error){if(!(error instanceof AuthError))throw error;fail('invalid_client',401);}
  const registered=JSON.parse(app.scopes),given=form.get('scope');
  scopes=given===null?[...registered]:[...new Set(given.trim().split(/\s+/).filter(Boolean))];
  if(!scopes.length||scopes.some(s=>!SCOPES.includes(s)||!registered.includes(s)))fail('invalid_scope');
  await assertion(ctx,app,form);
  const now=Math.floor(ctx.now()/1000),expiresAt=Math.min(now+300,Math.floor(app.expires_at/1000));
  if(expiresAt<=now)fail('invalid_client',401);
  // Admin tokens are accepted only by this issuer's REST API, whose verifier
  // reads the authoritative local JWKS on every call rather than a cached RP copy.
  await ensureSigningKey(ctx);
  const accessToken=await signToken(ctx,{aud:(ctx.issuer??ctx.origin)+'/api/auth/admin/v1',sub:'admin-service:'+app.id,client_id:app.client_id,admin_service_app:app.id,revision:app.revision,scope:scopes.join(' '),jti:random()},{typ:'at+jwt',expiresAt,published:true});
  // Signing awaits cryptography. Recheck live authority in the last committing
  // statement, so demotion, reassignment, revocation or expiry wins that race.
  const guard=liveGuard(ctx,app,expiresAt*1000);
  const updated=await run(ctx,`UPDATE auth_admin_service_apps SET last_used_at=? WHERE id=? AND ${guard.clause}`,ctx.now(),app.id,...guard.args);
  if(!updated.meta.changes)fail('invalid_client',401);
  await record(ctx,app,clientId,scopes,'issued');
  return json({access_token:accessToken,token_type:'Bearer',expires_in:expiresAt-Math.floor(ctx.now()/1000),scope:scopes.join(' ')},200,rateHeaders);
 }catch(error) {
  const requested=(form.get('scope')||'').split(/\s+/).filter(s=>SCOPES.includes(s));
  await record(ctx,app,clientId,scopes.length?scopes.filter(s=>SCOPES.includes(s)):requested,error instanceof AuthError?error.message:'server_error');
  if(!(error instanceof AuthError))throw error;
  return json({error:error.message},error.status,{...rateHeaders,...(error.status===429?{'retry-after':'60'}:{})});
 }
}
