import {attestCase,cancelCase,redeemEnrollment} from './recovery-cases/index.mjs';
import {enforceAbuse,abuseRead,configureAbuse,trustedSource} from './abuse/index.mjs';
import {auditPage} from './audit/query.mjs';
import {DIRECTORY_SOURCES,isDirectorySourceAction,directorySourceRead,directorySourceAction,directorySourceScim} from './directory-sources/routes.mjs';
import {FEDERATION_READ,isFederationAction,federationRead,federationAction,federationSetupRoute} from './federation/setup.mjs';
import {sendDelivery} from './delivery/send.mjs';
import {sendgridEvents} from './delivery/events.mjs';
import {deliveryRead} from './delivery/routes.mjs';
import {NOTIFICATIONS_READ,NOTIFICATION_REPORT,isNotificationAction,notificationRead,notificationAction,notificationReport} from './notifications/index.mjs';
import {DOMAIN_PATH,isDomainAction,domainRead,domainAction} from './domains/routes.mjs';
import {HR_FEEDS,isHrFeedAction,hrFeedAction,hrFeedRead,hrFeedIngress} from './hris/files/routes.mjs';
import {REPORTS,reportsRead} from './reporting/reports.mjs';
import {BRIDGE,bridgeRegister,bridgeDisable,legacyLogin} from './migration/bridge.mjs';
import {EMPLOYER_PROVIDERS,configureEmployerProvider} from './tenancy/providers.mjs';
import {PAIRS_PREFIX,isPairPath,pairAction,pairModel} from './erasure/pairs.mjs';
import {releaseRead,releaseAction} from './erasure/pair-erasure.mjs';
import {refreshCors} from './tokens/cors.mjs';
import {isRefreshAction,refreshAction,refreshInventory} from './tokens/routes.mjs';
import {DECISIONS_READ,isDecisionAction,decisionsRead,decisionAction} from './decisions/routes.mjs';
import {REVIEWS_READS,isReviewAction,reviewsRead,reviewAction} from './reviews/routes.mjs';
import {REQUESTS_READ,isRequestAction,requestsRead,requestAction} from './requests/index.mjs';
import {personReceipt,receiptAction} from './erasure/personal-receipts.mjs';
import {RETENTION_READS,isRetentionAction,retentionRead,retentionAction} from './retention/index.mjs';
import {syncObligations} from './obligations/sources.mjs';
import {FOLLOWUP_READ,isFollowupAction,followupRead,followupAction} from './obligations/routes.mjs';
import {ERASURE_READS,isErasureAction,erasureRead,erasureAction} from './erasure/index.mjs';
import {isDelegationPath,delegationRoute} from './agents/delegation/index.mjs';
import {ROLE_READS,isRoleAction,roleRead,roleAction} from './roles/index.mjs';
import {isGrantAction,grantAction,grantRead,resourceToken,grantCheck} from './grants/index.mjs';
import {organizationRequest,organizationContext,organizationResponse,organizationError} from './tenancy/context.mjs';
import {TENANCY_READ,isTenancyAction,tenancyAction,tenancyRead} from './tenancy/routes.mjs';
import {resolveProviders} from './admin-api/providers.mjs';
import {adminToken,isAdminServiceAction,adminServiceAction} from './admin-api/credentials/index.mjs';
import {adminApi} from './admin-api/routes.mjs';
import {isHookAction,hookAction,hookModel} from './hooks/index.mjs';
import {isMappingAction,mappingAction} from './mapping/routes.mjs';
import {AuthError,input,json,fail,requireSession,validateClientOrigin} from './core.mjs';
import {requestEmail,confirmEmail,confirmationPage,confirmationError} from './email.mjs';
import {registrationOptions,registrationVerify,authenticationOptions,authenticationVerify} from './passkeys.mjs';
import {startRecovery,changeRecovery,redeemRecoveryToken} from './recovery.mjs';
import {discovery,authorize,resumeAuthorization,token,delegationToken} from './protocol.mjs';
import {userinfo} from './userinfo.mjs';
import {genericToken} from './oidc-apps/flow.mjs';
import {jwks,JWKS_CACHE_SECONDS,ensureSigningKey} from './keys.mjs';
import {adminAction,model,sendInvitation} from './admin.mjs';
import {createUpstreams} from './upstreams.mjs';
import {stage,moveInAction,formerSubjects} from './move-in/routes.mjs';
import {CAMPAIGNS} from './migration/campaign-state.mjs';
import {campaignRead,campaignAction} from './migration/campaign-routes.mjs';
import {preparer,agentsAction} from './agents/routes.mjs';
import {linkRoute,LINK_PATHS,isAppAction,appAction} from './links/routes.mjs';
import {signOutEverywhere} from './links/logout.mjs';
import {endSession,END_SESSION} from './links/end-session.mjs';
import {rememberIssuer} from './links/grant-map.mjs';
import {isTrustAction,trustAction} from './links/rer-trust.mjs';
import {samlRoute,isSamlPath} from './saml/routes.mjs';
import {isWorkforceAction,workforceAction,workforceRead,WORKFORCE_READS} from './workforce/routes.mjs';
import {isProfileAction,profileAction,profileRead,PROFILE_READS} from './profiles/routes.mjs';
import {isDirectoryAction,directoryAction,directoryRead,DIRECTORY_READS} from './workforce/people/routes.mjs';
import {isEventsAction,eventsAction,eventsRead,EVENTS_READ} from './events/routes.mjs';
export {stageSigningKey,retireSigningKey,ensureSigningKey} from './keys.mjs';
export {maintainAuth} from './maintenance.mjs';
export {installRecoveryToken} from './recovery.mjs';
function scopedRuntime(options) {
 const ctx={...options,origin:new URL(options.origin).origin,now:options.now||Date.now,local:options.local===true};
 validateClientOrigin(ctx,ctx.origin);
 const resolved=()=>resolveProviders(ctx);
 return {context:ctx,async upstreamProviders(){const current=await resolved();return current.upstreamProviders?.length?createUpstreams(current).providers.list():[];},async model(request,page){return model(await resolved(),request,page);},async fetch(request) {
  const ctx=await resolved(),upstreams=ctx.upstreamProviders?.length?createUpstreams(ctx):null;
  const url=new URL(request.url),path=url.pathname;
  if(request.method==='OPTIONS'){const cors=await refreshCors(ctx,request);if(cors)return cors;}
  if(path.startsWith(DIRECTORY_SOURCES+'/scim/'))return await directorySourceScim(ctx,request,path);
  const setupResponse=await federationSetupRoute(ctx,request);if(setupResponse)return setupResponse;
  if((path.startsWith('/auth/oidc/')||path.startsWith('/auth/saml/'))&&upstreams)return upstreams.fetch(request);
  if(!path.startsWith('/auth/identity/')&&!path.startsWith('/auth/passkeys/')&&!path.startsWith('/api/auth/')&&!path.startsWith('/oidc/')&&path!=='/.well-known/openid-configuration'&&!LINK_PATHS.includes(path)&&!isSamlPath(path))return null;
  try {
   if(url.origin!==ctx.origin)fail('wrong_issuer',400);
   const limited=await enforceAbuse(ctx,request,path);if(limited)return limited;
   if(path==='/api/auth/delivery/sendgrid')return await sendgridEvents(ctx,request);
   if(path===NOTIFICATION_REPORT)return await notificationReport(ctx,request);
   if(path==='/oidc/userinfo')return await userinfo(ctx,request);
   // SAML messages arrive from apps' pages; each door checks its own signed or bound input.
   if(isSamlPath(path))return await samlRoute(ctx,request,path);
   // Apps and RER call these server to server; each verifies its own signed input.
   if(LINK_PATHS.includes(path))return await linkRoute(ctx,request,path);
   if(path===END_SESSION&&['GET','POST'].includes(request.method))return await endSession(ctx,request);
   // The preparer API reads only its key, never a cookie.
   if(isDelegationPath(path))return await delegationRoute(ctx,request,path);
   if(path.startsWith('/api/auth/admin/v1'))return await adminApi(ctx,request);
   if(path==='/api/auth/preparer')return await preparer(ctx,request);
   if(request.method==='GET') {
    if(path==='/api/auth/abuse')return await abuseRead(ctx,request);
    if(path==='/api/auth/audit')return json(await auditPage(ctx,await requireSession(ctx,request),request));
    if(path===DIRECTORY_SOURCES)return await directorySourceRead(ctx,request);
    if(path===FEDERATION_READ)return await federationRead(ctx,request);
    if(path===CAMPAIGNS||path===CAMPAIGNS+'/export.csv')return await campaignRead(ctx,request);
    if(path==='/api/auth/delivery')return await deliveryRead(ctx,request);
    if(path===NOTIFICATIONS_READ)return await notificationRead(ctx,request);
    if(path===DOMAIN_PATH)return await domainRead(ctx,request);
    if(path==='/.well-known/openid-configuration'){await ensureSigningKey(ctx);await rememberIssuer(ctx);return json(discovery(ctx));}
    if(path==='/oidc/jwks'){await ensureSigningKey(ctx);return json(await jwks(ctx),200,{'cache-control':`public, max-age=${JWKS_CACHE_SECONDS}`});}
    if(path==='/oidc/authorize')return await authorize(ctx,request);
    if(path==='/oidc/authorize/resume')return await resumeAuthorization(ctx,request);
    if(path==='/auth/identity/email/confirm')return await confirmationPage(ctx,request);
    if(path===PAIRS_PREFIX||path===PAIRS_PREFIX+'/export')return json(await pairModel(ctx,request),200,path.endsWith('/export')?{'content-disposition':'attachment; filename="auth-identity-links.json"'}:{});
    if(path==='/api/auth/identity-release-notices')return releaseRead(ctx,request);
    if(path===DECISIONS_READ)return await decisionsRead(ctx,request);
    if(REVIEWS_READS.includes(path))return await reviewsRead(ctx,request,path);
    if(path===REQUESTS_READ)return await requestsRead(ctx,request);
    if(RETENTION_READS.includes(path))return await retentionRead(ctx,request,path);
    if(path===FOLLOWUP_READ)return await followupRead(ctx,request);
    if(ERASURE_READS.includes(path))return await erasureRead(ctx,request,path);
    if(ROLE_READS.includes(path))return await roleRead(ctx,request,path);
    if(path==='/api/auth/refresh')return json(await refreshInventory(ctx,request));
    if(path==='/api/auth/resource-apis')return await grantRead(ctx,request,path);
    if(path===TENANCY_READ)return await tenancyRead(ctx,request);
    if(path==='/api/auth/move-in/subjects.csv')return await formerSubjects(ctx,request);
    if(path==='/api/auth/hooks'){await requireSession(ctx,request,true);return json(await hookModel(ctx));}
    if(WORKFORCE_READS.includes(path))return await workforceRead(ctx,request,path);
    if(path===HR_FEEDS)return await hrFeedRead(ctx,request);
    if(path===REPORTS||path.startsWith(REPORTS+'/'))return await reportsRead(ctx,request,path);
    if(DIRECTORY_READS.includes(path))return await directoryRead(ctx,request,path);
    if(PROFILE_READS.includes(path))return await profileRead(ctx,request);
    // The event cursor reads its own read key, never a cookie.
    if(path===EVENTS_READ)return await eventsRead(ctx,request);
    if(path.startsWith('/api/auth/')) {
     const section=path.slice('/api/auth/'.length);if(!['me','people','move-in','agents','apps','activity','methods','notices'].includes(section))fail('not_found',404);
     await requireSession(ctx,request,['people','move-in','agents','apps','activity'].includes(section));const data=await model(ctx,request,['move-in','agents'].includes(section)?section:undefined);return json(section==='me'?data:section==='move-in'?data.moveIn:data[section]);
    }
   }
   if(request.method==='POST') {
    if(path==='/oidc/token')return await delegationToken(ctx,request)??await resourceToken(ctx,request)??await adminToken(ctx,request)??await genericToken(ctx,request)??await token(ctx,request);
    if(path==='/api/auth/move-in/stage')return await stage(ctx,request);
    if(path==='/api/auth/resource-apis/check')return await grantCheck(ctx,request);
    if(path===HR_FEEDS+'/ingest'||path===HR_FEEDS+'/upload') {
     if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
     if(!(request.headers.get('content-type')??'').startsWith('application/json'))fail('unsupported_content_type',415);
     if(Number(request.headers.get('content-length')??0)>2*1024*1024)fail('request_too_large',413);
     const text=await request.text();if(new TextEncoder().encode(text).length>2*1024*1024)fail('request_too_large',413);
     let body;try{body=JSON.parse(text);}catch{fail('invalid_json');}
     if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).some(key=>!['feedId','fileName','text'].includes(key)))fail('invalid_hr_upload');
     return path.endsWith('/ingest')?await hrFeedIngress(ctx,request,body):await hrFeedAction(ctx,request,'/hr-feeds/upload',body);
    }
    if(['/receipt','/receipt-key','/receipt-revoke'].some(suffix=>path===PAIRS_PREFIX+suffix)&&url.search)fail('receipt_body_required',400);
    const data=await input(ctx,request);
    if(path==='/api/auth/abuse/configure')return await configureAbuse(ctx,request,data);
    if(isDirectorySourceAction(path.slice('/api/auth'.length)))return await directorySourceAction(ctx,request,path.slice('/api/auth'.length),data);
    if(isFederationAction(path.slice('/api/auth'.length)))return await federationAction(ctx,request,path.slice('/api/auth'.length),data);
    if(path.startsWith(CAMPAIGNS+'/'))return await campaignAction(ctx,request,path,data);
    if(isDomainAction(path.slice('/api/auth'.length)))return await domainAction(ctx,request,path.slice('/api/auth'.length),data);
    if(path===BRIDGE+'/register')return bridgeRegister(ctx,request,data);
    if(path===BRIDGE+'/disable')return bridgeDisable(ctx,request,data);
    if(path===BRIDGE+'/login')return legacyLogin(ctx,request,data);
    if(path===EMPLOYER_PROVIDERS)return configureEmployerProvider(ctx,request,data);
    if(path===PAIRS_PREFIX+'/receipt')return personReceipt(ctx,request,data);
    if(path===PAIRS_PREFIX+'/receipt-key'||path===PAIRS_PREFIX+'/receipt-revoke')return receiptAction(ctx,request,path,data);
    if(isPairPath(path))return pairAction(ctx,request,path,data);
    if(path==='/api/auth/identity-release-notices/hold')return releaseAction(ctx,request,data);
    if(path==='/auth/identity/email/request')return await requestEmail(ctx,request,data);
    if(path==='/auth/identity/email/confirm')return await confirmEmail(ctx,request,{...data,token:data.token||url.searchParams.get('token')});
    const passkeyPath=path.replace('/auth/identity/passkeys/','/auth/passkeys/');
    if(passkeyPath==='/auth/passkeys/register/options')return await registrationOptions(ctx,request);
    if(passkeyPath==='/auth/passkeys/register/verify')return await registrationVerify(ctx,request,data);
    if(passkeyPath==='/auth/passkeys/authenticate/options')return await authenticationOptions(ctx,request,data);
    if(passkeyPath==='/auth/passkeys/authenticate/verify')return await authenticationVerify(ctx,request,data);
    if(path.startsWith('/api/auth/')) {
     const action=path.slice('/api/auth'.length);
     if(isRefreshAction(action))return await refreshAction(ctx,request,action,data);
     if(isDecisionAction(action))return await decisionAction(ctx,request,action,data);
     if(isReviewAction(action))return await reviewAction(ctx,request,action,data);
     if(isRequestAction(action))return await requestAction(ctx,request,action,data);
     if(isNotificationAction(action))return await notificationAction(ctx,request,action,data);
     if(isRetentionAction(action))return await retentionAction(ctx,request,action,data);
     if(isFollowupAction(action))return await followupAction(ctx,request,action,data);
     if(isErasureAction(action))return await erasureAction(ctx,request,action,data);
     if(isRoleAction(action))return await roleAction(ctx,request,action,data);
     if(isGrantAction(action))return await grantAction(ctx,request,action,data);
     if(isTenancyAction(action)){const response=await tenancyAction(ctx,request,action,data);if(['/organizations/invite','/organizations/cancel-invitation'].includes(action))await syncObligations(ctx);return response;}
     if(['/recovery/start','/recovery/request'].includes(action))return await startRecovery(ctx,request);
     if(['/recovery/cancel','/recovery/approve','/recovery/complete'].includes(action))return await changeRecovery(ctx,request,data,action.split('/').at(-1));
     if(action==='/recovery/case-attest')return await attestCase(ctx,request,data);
     if(action==='/recovery/case-cancel')return await cancelCase(ctx,request,data);
     if(action==='/recovery/enroll')return await redeemEnrollment(ctx,request,data);
     if(action==='/recovery/token')return await redeemRecoveryToken(ctx,request,data);
     if(action.startsWith('/move-in/'))return await moveInAction(ctx,request,action,data);
     if(action.startsWith('/agents/'))return await agentsAction(ctx,request,action,data);
     if(isAdminServiceAction(action))return await adminServiceAction(ctx,request,action,data);
     if(action==='/signout-everywhere')return await signOutEverywhere(ctx,request);
     if(isAppAction(action))return await appAction(ctx,request,action,data);
     if(isTrustAction(action))return await trustAction(ctx,request,action,data);
     if(isProfileAction(action))return await profileAction(ctx,request,action,data,{upstreams});
     if(isHrFeedAction(action))return await hrFeedAction(ctx,request,action,data);
     if(isDirectoryAction(action))return await directoryAction(ctx,request,action,data,{notify:sendInvitation});
     if(isHookAction(action))return await hookAction(ctx,request,action,data);
     if(isMappingAction(action))return await mappingAction(ctx,request,action,data);
     if(isWorkforceAction(action))return await workforceAction(ctx,request,action,data);
     if(isEventsAction(action))return await eventsAction(ctx,request,action,data);
     return await adminAction(ctx,request,action,data);
    }
   }
   fail('not_found',404);
  } catch(error) {
   if(!(error instanceof AuthError))throw error;
   if(path==='/auth/identity/email/confirm'&&(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded'))return confirmationError(ctx,error);
   if(error.message==='email_rate_limited')return json({error:error.message,retryAfter:error.retryAfter,message:`Too many email confirmation requests. Try again in ${Math.ceil(error.retryAfter/60)} minute${error.retryAfter<=60?'':'s'}. Your current email confirmation is not extended.`},429,{'retry-after':String(error.retryAfter)});
   if(error.message==='email_delivery_failed')return json({error:error.message,message:'Auth could not send your confirmation email. Try again later or contact your administrator. Your current email confirmation is not extended.'},503);
   if(path==='/oidc/authorize'||path==='/oidc/authorize/resume'||path===END_SESSION)return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Auth request could not continue</title><h1>Auth request could not continue</h1><p>${error.message==='hook_timeout'?'An inline sign-in hook timed out. Try signing in again.':error.message==='hook_refused'?'Your employer’s inline hook refused sign-in.':'Check the app and its sign-in address.'}</p></html>`,{status:error.status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}});
   const message=error.message==='hook_timeout'?'An inline sign-in hook timed out. Try signing in again.':error.message==='hook_refused'?'Your employer’s inline hook refused sign-in.':error.message==='hook_invalid_response'?'The inline hook attempted a protected or unapproved change.':undefined;
   return json({error:error.message,...(message?{message,error_description:message}:{})},error.status);
  }
 }};
}

// Every HTTP and page door selects its organization before touching product
// storage. Credentials and identifiers from a different namespace never match.
export function createAuthRuntime(options) {
 const root={...options,origin:new URL(options.origin).origin,now:options.now||Date.now,local:options.local===true};
 if(options.mail)root.mail=(message,store)=>sendDelivery({...root,db:store?.db??root.db},message,prepared=>options.mail(prepared,store));
 const select=async request=>{
  const selected=organizationRequest(request),id=options.organizationId??selected.id;
  return {request:selected.request,ctx:{...await organizationContext(root,id),abuseSource:trustedSource(root,request)}};
 };
 return {context:root,
  async upstreamProviders(){return scopedRuntime(await organizationContext(root,options.organizationId??'root')).upstreamProviders();},
  async model(request,page){const selected=await select(request);return scopedRuntime(selected.ctx).model(selected.request,page);},
  async fetch(request){return organizationError(async()=>{if(new URL(request.url).origin!==root.origin)fail('wrong_issuer',400);const selected=await select(request);const response=await scopedRuntime(selected.ctx).fetch(selected.request);return organizationResponse(selected.ctx,await refreshCors(selected.ctx,selected.request,response));});},
 };
}
