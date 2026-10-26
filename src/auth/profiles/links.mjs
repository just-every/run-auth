// Connecting and disconnecting another upstream identity (Google, Microsoft,
// Okta) on the signed-in account. A link needs the existing account's proof (this
// session, with a fresh local email confirmation) and the new identity's proof (the
// provider's verified response), one explicit confirmation, and refuses anything
// a matching email alone would suggest: an issuer/subject pair has one binding.
import {AuthError,random,hash,one,all,cookies,cookie,fail,session,auditDetail} from '../core.mjs';
import {freshLocalEmail,requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {configuredProvider,matchesConfiguredPin,requiredProvider} from '../domain-policy.mjs';
import {trustedEmail} from '../../modules/operator-auth/identity/principal.mjs';
import {sessionGuard} from './profile.mjs';

const INTENT_MAX_AGE=10*60000;
const linkCookie=ctx=>ctx.local?'auth_link':'__Host-auth_link';

// The explicit request behind this browser's provider round trip, if one is open.
export async function openIntent(ctx,request) {
 const raw=cookies(request)[linkCookie(ctx)];if(!raw)return null;
 return one(ctx,'SELECT * FROM auth_link_intents WHERE id=? AND consumed_at IS NULL AND expires_at>?',await hash(raw),ctx.now());
}

export async function linksOf(ctx,personId) {
 const rows=await all(ctx,"SELECT p.provider_id AS providerId,i.issuer FROM oa_external_identities i LEFT JOIN oa_identity_providers p ON p.issuer=i.issuer AND p.status='linked' WHERE i.operator_id=? ORDER BY i.issuer",personId);
 return rows.map(row=>({...row,providerId:row.providerId??(ctx.upstreamProviders??[]).find(provider=>provider.issuer===row.issuer)?.id??null}));
}

// Begin: store the intent for this session and return the cookie that carries it through the provider.
export async function beginLink(ctx,request,data,upstreams) {
 const s=await session(ctx,request);if(!s)fail('sign_in_required',401);
 requireLocalEmail(ctx,s);
 if(data.confirm!==true&&data.confirm!=='true'&&data.confirm!=='on')fail('confirmation_required');
 const provider=configuredProvider(ctx,String(data.providerId||''));if(!provider||!upstreams)fail('unknown_provider');
 const raw=random(),guard=sessionGuard(ctx,s);
 const stored=await ctx.db.prepare(`INSERT INTO auth_link_intents(id,person_id,session_id,provider_id,created_at,expires_at) SELECT ?,?,?,?,?,? WHERE ${guard.clause}`).bind(await hash(raw),s.person_id,s.id,provider.id,ctx.now(),ctx.now()+INTENT_MAX_AGE,...guard.args).run();
 if(!stored.meta.changes)fail('session_authority_changed',403);
 return {raw,provider,header:cookie(ctx,linkCookie(ctx),raw,INTENT_MAX_AGE/1000)};
}

// The provider's verified response, for a browser with an open intent: bind it to the signed-in person or
// refuse. Either way the browser returns to My account, which names the outcome; a refusal binds nothing.
export async function completeLink(ctx,request,principal,intent) {
 const back=outcome=>({returnTo:`/app/account?link=${outcome}`,cookie:cookie(ctx,linkCookie(ctx),'',0)});
 try {
  await bind(ctx,request,principal,intent);
  return back('connected');
 } catch(error) {
  if(!(error instanceof AuthError))throw error;
  await auditDetail(ctx,intent.person_id,'identity_link_refused',intent.person_id,{provider:intent.provider_id,reason:error.message});
  return back(error.message);
 }
}
async function bind(ctx,request,principal,intent) {
 const s=await session(ctx,request);
 // One use: a repeated callback finds the intent spent.
 const spent=await one(ctx,'UPDATE auth_link_intents SET consumed_at=? WHERE id=? AND consumed_at IS NULL RETURNING id',ctx.now(),intent.id);
 if(!spent)fail('link_intent_used',409);
 if(!s||s.id!==intent.session_id||s.person_id!==intent.person_id)fail('link_session_changed',403);
 if(!freshLocalEmail(ctx,s))fail('local_email_step_up_required',403);
 const provider=configuredProvider(ctx,principal.provider);
 if(!provider||provider.id!==intent.provider_id||!await matchesConfiguredPin(ctx,provider,principal.issuer))fail('upstream_configuration_changed',403);
 const address=principal.associatedEmail||trustedEmail(principal,ctx.now());
 if(!address)fail('upstream_identity_untrusted',403);
 const person=await one(ctx,"SELECT id,email FROM oa_operators WHERE id=? AND status='active'",s.person_id)||fail('account_unavailable',403);
 // The identity must not already belong to anyone, and its address must not name another person.
 const held=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',principal.issuer,principal.subject);
 if(held)fail(held.operator_id===person.id?'already_linked':'upstream_subject_bound',409);
 if(await one(ctx,'SELECT 1 FROM oa_operators WHERE email=? AND id!=?',address,person.id))fail('upstream_email_collision',409);
 if(address!==person.email)fail('upstream_email_mismatch',409);
 if(await one(ctx,'SELECT 1 FROM oa_external_identities WHERE issuer=? AND operator_id=?',principal.issuer,person.id))fail('provider_already_linked',409);
 const guard=sessionGuard(ctx,s);
 // The binding, the spent intent and every refusal above commit as one: two requests for the same identity have one winner.
 const [bound]=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO oa_external_identities(issuer,subject,operator_id) SELECT ?,?,? WHERE NOT EXISTS(SELECT 1 FROM oa_external_identities WHERE issuer=? AND (subject=? OR operator_id=?)) AND ${guard.clause}`).bind(principal.issuer,principal.subject,person.id,principal.issuer,principal.subject,person.id,...guard.args),
 ]);
 if(!bound.meta.changes) {
  const owner=await one(ctx,'SELECT operator_id FROM oa_external_identities WHERE issuer=? AND subject=?',principal.issuer,principal.subject);
  fail(owner&&owner.operator_id!==person.id?'upstream_subject_bound':owner?'already_linked':'provider_already_linked',409);
 }
 await auditDetail(ctx,person.id,'identity_linked',person.id,{provider:provider.id,issuer:principal.issuer});
}

// What still lets the person sign in once this binding is gone. A required provider is the only way in
// for everyone but the owner; otherwise the account's email address, passkeys and other providers remain.
export async function remainingSignIns(ctx,person,removedIssuer) {
 const rule=await requiredProvider(ctx,person);
 const others=(await linksOf(ctx,person.id)).filter(l=>l.issuer!==removedIssuer&&l.providerId&&configuredProvider(ctx,l.providerId));
 if(rule)return others.filter(l=>l.providerId===rule.provider_id).map(l=>'provider:'+l.providerId);
 return ['email',...(await one(ctx,'SELECT 1 AS n FROM auth_passkeys WHERE person_id=?',person.id)?['passkey']:[]),...others.map(l=>'provider:'+l.providerId)];
}

export async function unlink(ctx,request,data) {
 const s=await session(ctx,request);if(!s)fail('sign_in_required',401);
 requireLocalEmail(ctx,s);
 if(data.confirm!==true&&data.confirm!=='true'&&data.confirm!=='on')fail('confirmation_required');
 const pin=await one(ctx,"SELECT issuer FROM oa_identity_providers WHERE provider_id=? AND status='linked'",String(data.providerId||''));
 const link=pin&&await one(ctx,'SELECT subject FROM oa_external_identities WHERE issuer=? AND operator_id=?',pin.issuer,s.person_id);
 if(!link)fail('link_not_found',404);
 const person={id:s.person_id,email:s.email,role:s.role};
 if(!(await remainingSignIns(ctx,person,pin.issuer)).length)fail('last_sign_in',409);
 const guard=authority(ctx,s);
 const [removed]=await ctx.db.batch([
  ctx.db.prepare(`DELETE FROM oa_external_identities WHERE issuer=? AND operator_id=? AND ${guard.clause}`).bind(pin.issuer,s.person_id,...guard.args),
  ctx.db.prepare(`DELETE FROM auth_upstream_proofs WHERE issuer=? AND person_id=? AND ${guard.clause}`).bind(pin.issuer,s.person_id,...guard.args),
 ]);
 if(!removed.meta.changes){await requireAuthority(ctx,s,guard);fail('link_not_found',404);}
 await auditDetail(ctx,s.person_id,'identity_unlinked',s.person_id,{provider:String(data.providerId),issuer:pin.issuer});
}
