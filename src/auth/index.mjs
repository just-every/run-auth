import {AuthError,input,json,fail,requireSession,validateClientOrigin} from './core.mjs';
import {requestEmail,confirmEmail,confirmationPage} from './email.mjs';
import {registrationOptions,registrationVerify,authenticationOptions,authenticationVerify} from './passkeys.mjs';
import {startRecovery,changeRecovery,redeemRecoveryToken} from './recovery.mjs';
import {discovery,authorize,resumeAuthorization,token} from './protocol.mjs';
import {userinfo} from './userinfo.mjs';
import {jwks,JWKS_CACHE_SECONDS,ensureSigningKey} from './keys.mjs';
import {adminAction,model} from './admin.mjs';
import {createUpstreams} from './upstreams.mjs';
import {stage,moveInAction,formerSubjects} from './move-in/routes.mjs';
import {preparer,agentsAction} from './agents/routes.mjs';
import {linkRoute,LINK_PATHS,isAppAction,appAction} from './links/routes.mjs';
import {signOutEverywhere} from './links/logout.mjs';
import {endSession,END_SESSION} from './links/end-session.mjs';
import {rememberIssuer} from './links/grant-map.mjs';
import {isTrustAction,trustAction} from './links/rer-trust.mjs';
import {samlRoute,isSamlPath} from './saml/routes.mjs';
import {isWorkforceAction,workforceAction,workforceRead,WORKFORCE_READS} from './workforce/routes.mjs';
export {stageSigningKey,retireSigningKey,ensureSigningKey} from './keys.mjs';
export {maintainAuth} from './maintenance.mjs';
export {installRecoveryToken} from './recovery.mjs';
export function createAuthRuntime(options) {
 const ctx={...options,origin:new URL(options.origin).origin,now:options.now||Date.now,local:options.local===true};
 validateClientOrigin(ctx,ctx.origin);
 const upstreams=ctx.upstreamProviders?.length?createUpstreams(ctx):null;
 return {context:ctx,upstreamProviders:()=>upstreams?upstreams.providers.list():Promise.resolve([]),model:(request,page)=>model(ctx,request,page),async fetch(request) {
  const url=new URL(request.url),path=url.pathname;
  if(path.startsWith('/auth/oidc/')&&upstreams)return upstreams.fetch(request);
  if(!path.startsWith('/auth/identity/')&&!path.startsWith('/auth/passkeys/')&&!path.startsWith('/api/auth/')&&!path.startsWith('/oidc/')&&path!=='/.well-known/openid-configuration'&&!LINK_PATHS.includes(path)&&!isSamlPath(path))return null;
  try {
   if(url.origin!==ctx.origin)fail('wrong_issuer',400);
   if(path==='/oidc/userinfo')return await userinfo(ctx,request);
   // SAML messages arrive from apps' pages; each door checks its own signed or bound input.
   if(isSamlPath(path))return await samlRoute(ctx,request,path);
   // Apps and RER call these server to server; each verifies its own signed input.
   if(LINK_PATHS.includes(path))return await linkRoute(ctx,request,path);
   if(path===END_SESSION&&['GET','POST'].includes(request.method))return await endSession(ctx,request);
   // The preparer API reads only its key, never a cookie.
   if(path==='/api/auth/preparer')return await preparer(ctx,request);
   if(request.method==='GET') {
    if(path==='/.well-known/openid-configuration'){await ensureSigningKey(ctx);await rememberIssuer(ctx);return json(discovery(ctx));}
    if(path==='/oidc/jwks'){await ensureSigningKey(ctx);return json(await jwks(ctx),200,{'cache-control':`public, max-age=${JWKS_CACHE_SECONDS}`});}
    if(path==='/oidc/authorize')return await authorize(ctx,request);
    if(path==='/oidc/authorize/resume')return await resumeAuthorization(ctx,request);
    if(path==='/auth/identity/email/confirm')return await confirmationPage(ctx,request);
    if(path==='/api/auth/move-in/subjects.csv')return await formerSubjects(ctx,request);
    if(WORKFORCE_READS.includes(path))return await workforceRead(ctx,request,path);
    if(path.startsWith('/api/auth/')) {
     const section=path.slice('/api/auth/'.length);if(!['me','people','move-in','agents','apps','activity','methods','notices'].includes(section))fail('not_found',404);
     await requireSession(ctx,request,['people','move-in','agents','apps','activity'].includes(section));const data=await model(ctx,request,['move-in','agents'].includes(section)?section:undefined);return json(section==='me'?data:section==='move-in'?data.moveIn:data[section]);
    }
   }
   if(request.method==='POST') {
    if(path==='/oidc/token')return await token(ctx,request);
    if(path==='/api/auth/move-in/stage')return await stage(ctx,request);
    const data=await input(ctx,request);
    if(path==='/auth/identity/email/request')return await requestEmail(ctx,request,data);
    if(path==='/auth/identity/email/confirm')return await confirmEmail(ctx,request,{...data,token:data.token||url.searchParams.get('token')});
    const passkeyPath=path.replace('/auth/identity/passkeys/','/auth/passkeys/');
    if(passkeyPath==='/auth/passkeys/register/options')return await registrationOptions(ctx,request);
    if(passkeyPath==='/auth/passkeys/register/verify')return await registrationVerify(ctx,request,data);
    if(passkeyPath==='/auth/passkeys/authenticate/options')return await authenticationOptions(ctx,request,data);
    if(passkeyPath==='/auth/passkeys/authenticate/verify')return await authenticationVerify(ctx,request,data);
    if(path.startsWith('/api/auth/')) {
     const action=path.slice('/api/auth'.length);
     if(['/recovery/start','/recovery/request'].includes(action))return await startRecovery(ctx,request);
     if(['/recovery/cancel','/recovery/approve','/recovery/complete'].includes(action))return await changeRecovery(ctx,request,data,action.split('/').at(-1));
     if(action==='/recovery/token')return await redeemRecoveryToken(ctx,request,data);
     if(action.startsWith('/move-in/'))return await moveInAction(ctx,request,action,data);
     if(action.startsWith('/agents/'))return await agentsAction(ctx,request,action,data);
     if(action==='/signout-everywhere')return await signOutEverywhere(ctx,request);
     if(isAppAction(action))return await appAction(ctx,request,action,data);
     if(isTrustAction(action))return await trustAction(ctx,request,action,data);
     if(isWorkforceAction(action))return await workforceAction(ctx,request,action,data);
     return await adminAction(ctx,request,action,data);
    }
   }
   fail('not_found',404);
  } catch(error) {
   if(!(error instanceof AuthError))throw error;
   if(path==='/oidc/authorize'||path==='/oidc/authorize/resume'||path===END_SESSION)return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><title>Auth request could not continue</title><h1>Auth request could not continue</h1><p>Check the app and its sign-in address.</p></html>',{status:error.status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}});
   return json({error:error.message},error.status);
  }
 }};
}
