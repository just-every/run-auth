import {notificationApp} from './notifications/index.mjs';
import {permitsProvider,configuredProvider,configurationHash,matchesConfiguredPin} from './domain-policy.mjs';
import {emit} from './events/store.mjs';
import {createOidcProviders,createOidcHandler} from '../modules/operator-auth/identity/oidc/index.mjs';
import {trustedEmail} from '../modules/operator-auth/identity/principal.mjs';
import {one,run,random,hash,cookie,bindingName,createSession,EMAIL_MAX_AGE,returnPath,fail,audit,SESSION_MAX_AGE} from './core.mjs';
import {sendProof} from './email.mjs';
import {pendingAuthorizationLogin} from './authorization-login.mjs';
import {openIntent,completeLink} from './profiles/links.mjs';
import {createFederationOidc} from './federation/oidc.mjs';
import {createFederationSaml} from './federation/saml.mjs';
import {evaluatePerson} from './workforce/people/evaluate.mjs';
import {campaignAdmission,recordCampaignProof} from './migration/campaign-state.mjs';
export function createUpstreams(ctx) {
 const configured=ctx.upstreamProviders||[],deviceCookies=new WeakMap();
 if(configured.some(p=>!['google','microsoft','okta','oidc','saml'].includes(p.preset)))fail('unsupported_upstream',503);
 const admission={async admit(request,principal,{returnTo}={}) {
  // Only the maintained Base verifier invokes this closed-over admission adapter.
  // subjectEmails is trusted server configuration, never a token email assertion.
  // An open request from the signed-in account to connect this identity is a link, never a sign-in.
  const intent=await openIntent(ctx,request);
  if(intent)return completeLink(ctx,request,principal,intent);
  const provider=configuredProvider(ctx,principal.provider);
  if(!provider||!await matchesConfiguredPin(ctx,provider,principal.issuer))fail('upstream_configuration_changed',403);
  const campaign=await campaignAdmission(ctx,principal);
  const proven=trustedEmail(principal,ctx.now()),associated=principal.associatedEmail;
  const address=campaign?.row.email||associated||proven;
  let person=await one(ctx,'SELECT p.* FROM oa_external_identities i JOIN oa_operators p ON p.id=i.operator_id WHERE i.issuer=? AND i.subject=?',principal.issuer,principal.subject);
  if(campaign&&person&&person.id!==campaign.row.person_id)fail('campaign_subject_mismatch',403);
  if(person && address && address!==person.email)fail('upstream_binding_changed',403);
  if(!person && address)person=await one(ctx,"SELECT * FROM oa_operators WHERE email=? AND status IN ('active','invited')",address);
  if(!address||person?.status==='inactive')fail('upstream_identity_untrusted',403);
  if(!await permitsProvider(ctx,person||{email:address,role:'member'},principal.provider))fail('required_provider',403);
  if(!person&&await one(ctx,'SELECT domain FROM auth_domains WHERE domain=?',address.split('@')[1])) {
   await run(ctx,"INSERT OR IGNORE INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES(?,?,?,'member','invited',1,?)",random(),address,address,ctx.now());
   person=await one(ctx,"SELECT * FROM oa_operators WHERE email=? AND status IN ('active','invited')",address);
  }
  if(!person)fail('upstream_identity_untrusted',403);
  if(campaign){if(person.id!==campaign.row.person_id)fail('campaign_subject_mismatch',403);await recordCampaignProof(ctx,campaign);}
  await run(ctx,'INSERT OR IGNORE INTO oa_external_identities(issuer,subject,operator_id) VALUES(?,?,?)',principal.issuer,principal.subject,person.id);
  const binding=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',principal.issuer,principal.subject);if(binding.operator_id!==person.id)fail('upstream_binding_changed',403);
  const upstreamProofId=random();
  await run(ctx,'INSERT INTO auth_upstream_proofs(id,person_id,provider_id,issuer,subject,configuration_hash,verified_at,expires_at) VALUES(?,?,?,?,?,?,?,?)',upstreamProofId,person.id,principal.provider,principal.issuer,principal.subject,await configurationHash(provider),ctx.now(),Math.min(ctx.now()+SESSION_MAX_AGE,campaign?.campaign.cutover_at??Infinity));
  if(person.status==='invited') {
   const activated=await run(ctx,"UPDATE oa_operators SET status='active' WHERE id=? AND status='invited'",person.id);
   if(activated.meta.changes){await emit(ctx,'person.activated',{type:'person',id:person.id,email:person.email},{method:'upstream'});await evaluatePerson(ctx,person.id);}
   person=await one(ctx,"SELECT * FROM oa_operators WHERE id=? AND status='active'",person.id);
   if(!person)fail('account_unavailable',403);
  }
  if(proven)await run(ctx,'INSERT INTO auth_emails(person_id,verified_at) VALUES(?,?) ON CONFLICT(person_id) DO UPDATE SET verified_at=excluded.verified_at',person.id,ctx.now());
  const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',person.id);
  const login=await pendingAuthorizationLogin(ctx,request,returnTo);
  if(!proof||ctx.now()-proof.verified_at>=EMAIL_MAX_AGE||login?.reauthenticate) {
   const browser=random();await sendProof(ctx,person,await hash(browser),['oidc','email'],returnTo,upstreamProofId);
   return {returnTo:login?`/signin?reproof=1&returnTo=${encodeURIComponent(returnPath(returnTo))}`:'/signin?reproof=1',cookie:cookie(ctx,bindingName(ctx),browser,900)};
  }
  const session=await createSession(ctx,person.id,['oidc'],upstreamProofId,{request,app:await notificationApp(ctx,returnTo,request)});await audit(ctx,person.id,'upstream_authenticated',principal.provider);
  if(session.deviceHeader)deviceCookies.set(request,session.deviceHeader);
  return {returnTo:returnPath(returnTo),cookie:session.header};
 }};
 const oidc=configured.some(provider=>provider.preset==='oidc'||provider.federationSetupId)?createFederationOidc(ctx,{providers:configured,admission}):(()=>{
  const providers=createOidcProviders({admission,enabled:async()=>true,db:ctx.db,config:{origin:ctx.origin,local:ctx.local,transactionSecret:ctx.secret,providers:configured.filter(provider=>provider.preset!=='saml')},clock:ctx.now,clientIp:r=>r.headers.get('cf-connecting-ip')||'',...(ctx.upstreamFetch?{fetch:ctx.upstreamFetch}: {})});
  const handler=createOidcHandler(providers);
  return {providers,fetch:async request=>{
   if(ctx.basePath&&/^\/auth\/oidc\/[a-z][a-z0-9-]{0,31}\/callback$/.test(new URL(request.url).pathname)){const url=new URL(request.url);url.pathname=ctx.basePath+url.pathname;request=new Request(url,request);}
   return handler(request);
  }};
 })();
 const saml=createFederationSaml(ctx,{providers:configured,admission});
 const providers={...oidc.providers,list:async()=>[...await oidc.providers.list(),...await saml.list()]};
 return {providers,fetch:async request=>{
  const response=new URL(request.url).pathname.includes('/auth/saml/')?await saml.fetch(request):await oidc.fetch(request);
  const deviceCookie=deviceCookies.get(request);
  if(!deviceCookie||!response)return response;
  const headers=new Headers(response.headers);headers.append('set-cookie',deviceCookie);
  return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
 }};
}
