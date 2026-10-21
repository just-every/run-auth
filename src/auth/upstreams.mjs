import {permitsProvider,configuredProvider,configurationHash,matchesConfiguredPin} from './domain-policy.mjs';
import {emit} from './events/store.mjs';
import {createOidcProviders,createOidcHandler} from '../modules/operator-auth/identity/oidc/index.mjs';
import {trustedEmail} from '../modules/operator-auth/identity/principal.mjs';
import {one,run,random,hash,cookie,bindingName,createSession,EMAIL_MAX_AGE,returnPath,fail,audit,SESSION_MAX_AGE} from './core.mjs';
import {sendProof} from './email.mjs';
import {pendingAuthorizationLogin} from './authorization-login.mjs';
import {openIntent,completeLink} from './profiles/links.mjs';
import {evaluatePerson} from './workforce/people/evaluate.mjs';
export function createUpstreams(ctx) {
 const configured=ctx.upstreamProviders||[];
 if(configured.some(p=>!['google','microsoft','okta'].includes(p.preset)))fail('unsupported_upstream',503);
 const admission={async admit(request,principal,{returnTo}={}) {
  // Only the maintained Base verifier invokes this closed-over admission adapter.
  // subjectEmails is trusted server configuration, never a token email assertion.
  // An open request from the signed-in account to connect this identity is a link, never a sign-in.
  const intent=await openIntent(ctx,request);
  if(intent)return completeLink(ctx,request,principal,intent);
  const provider=configuredProvider(ctx,principal.provider);
  if(!provider||!await matchesConfiguredPin(ctx,provider,principal.issuer))fail('upstream_configuration_changed',403);
  const proven=trustedEmail(principal,ctx.now()),associated=principal.associatedEmail;
  const address=associated||proven;
  let person=await one(ctx,'SELECT p.* FROM oa_external_identities i JOIN oa_operators p ON p.id=i.operator_id WHERE i.issuer=? AND i.subject=?',principal.issuer,principal.subject);
  if(person && address && address!==person.email)fail('upstream_binding_changed',403);
  if(!person && address)person=await one(ctx,"SELECT * FROM oa_operators WHERE email=? AND status IN ('active','invited')",address);
  if(!address||person?.status==='inactive')fail('upstream_identity_untrusted',403);
  if(!await permitsProvider(ctx,person||{email:address,role:'member'},principal.provider))fail('required_provider',403);
  if(!person&&await one(ctx,'SELECT domain FROM auth_domains WHERE domain=?',address.split('@')[1])) {
   await run(ctx,"INSERT OR IGNORE INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES(?,?,?,'member','invited',1,?)",random(),address,address,ctx.now());
   person=await one(ctx,"SELECT * FROM oa_operators WHERE email=? AND status IN ('active','invited')",address);
  }
  if(!person)fail('upstream_identity_untrusted',403);
  await run(ctx,'INSERT OR IGNORE INTO oa_external_identities(issuer,subject,operator_id) VALUES(?,?,?)',principal.issuer,principal.subject,person.id);
  const binding=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',principal.issuer,principal.subject);if(binding.operator_id!==person.id)fail('upstream_binding_changed',403);
  const upstreamProofId=random();
  await run(ctx,'INSERT INTO auth_upstream_proofs(id,person_id,provider_id,issuer,subject,configuration_hash,verified_at,expires_at) VALUES(?,?,?,?,?,?,?,?)',upstreamProofId,person.id,principal.provider,principal.issuer,principal.subject,await configurationHash(provider),ctx.now(),ctx.now()+SESSION_MAX_AGE);
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
  const session=await createSession(ctx,person.id,['oidc'],upstreamProofId);await audit(ctx,person.id,'upstream_authenticated',principal.provider);
  return {returnTo:returnPath(returnTo),cookie:session.header};
 }};
 // Auth's configured upstreams are its owner's own choice: configured means offered.
 const providers=createOidcProviders({admission,enabled:async()=>true,db:ctx.db,config:{origin:ctx.origin,local:ctx.local,transactionSecret:ctx.secret,providers:configured},clock:ctx.now,clientIp:r=>r.headers.get('cf-connecting-ip')||'',...(ctx.upstreamFetch?{fetch:ctx.upstreamFetch}: {})});
 return {providers,fetch:createOidcHandler(providers)};
}
