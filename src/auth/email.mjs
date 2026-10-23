import {syncObligations} from './obligations/sources.mjs';
import {invitationAdmitted} from './tenancy/routes.mjs';
import {invokeHooks} from './hooks/index.mjs';
import {permitsSession,requirePolicy,upstreamProof} from './domain-policy.mjs';
import {framedPage,FRAME_SOURCES} from './page-frame.mjs';
import {emit} from './events/store.mjs';
import {evaluatePerson} from './workforce/people/evaluate.mjs';
import {email,hash,random,binding,bindingName,cookie,challenge,consumeChallenge,one,run,limitState,json,createSession,audit,fail,AuthError,returnPath,session,sessionById} from './core.mjs';
export async function sendProof(ctx, person, bindingHash, amr = ['email'], returnTo = '/app/account', upstreamProofId = null, hardwareSessionId = null, report = false) {
 await requirePolicy(ctx,person,upstreamProofId);
 if(upstreamProofId&&!await upstreamProof(ctx,person.id,upstreamProofId))fail('upstream_proof_expired',403);
 const allowance=await limitState(ctx,`proof-mail:${person.id}`,5,3600000);
 if(!allowance.allowed){if(report)throw mailLimited(allowance.retryAfter);return false;}
 const token = await challenge(ctx,'email',person.id,bindingHash,{amr,upstreamProofId,hardwareSessionId,personVersion:person.version,returnTo:returnPath(returnTo)},900000);
 const link = `${ctx.origin}${ctx.basePath??''}/auth/identity/email/confirm?token=${encodeURIComponent(token)}`;
 if (!ctx.mail) fail('mail_not_configured',503);
 await ctx.mail({to:person.email,subject:'Your Auth sign-in link',text:`Confirm your email in the browser where you requested this link: ${link}`,html:`<p>Confirm your email in the browser where you requested this link:</p><p><a href="${link}">Continue to Auth</a></p>`});
}
function mailLimited(seconds) {
 return Object.assign(new AuthError('email_rate_limited',429),{retryAfter:seconds});
}
async function startProof(ctx, request, data, address, bound, report = false) {
 let person=await one(ctx,"SELECT * FROM oa_operators WHERE email=? AND status IN ('active','invited')",address);
 if(!person && await permitsSession(ctx,{email:address,role:'member'}) && await one(ctx,'SELECT domain FROM auth_domains WHERE domain=?',address.split('@')[1])) {
  let extension;
  try{extension=await invokeHooks(ctx,'registration',{email:address,name:address});}catch(error){if(error instanceof AuthError)return;throw error;}
  if(!await permitsSession(ctx,{email:address,role:'member'}))return;
  await run(ctx,"INSERT OR IGNORE INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE EXISTS(SELECT 1 FROM auth_domains WHERE domain=?) AND NOT EXISTS(SELECT 1 FROM oa_domain_rules WHERE domain=?)",random(),address,extension.profile?.name??address,ctx.now(),address.split('@')[1],address.split('@')[1]);
  person=await one(ctx,'SELECT * FROM oa_operators WHERE email=?',address);
 }
 if(!person||!await invitationAdmitted(ctx,person)){if(report)fail('account_unavailable',403);return;}
 if(person.status==='invited')await syncObligations(ctx);
 const current=await session(ctx,request),proofId=current?.person_id===person.id&&await upstreamProof(ctx,person.id,current.upstream_proof_id)?current.upstream_proof_id:null;
 const hardwareId=current?.person_id===person.id&&JSON.parse(current.amr).includes('hwk')?current.id:null;
 if(await permitsSession(ctx,person,proofId))try {await sendProof(ctx,person,bound,proofId?['oidc','email']:['email'],data.returnTo,proofId,hardwareId,report);}
 catch(error) {
  if(error instanceof AuthError&&error.message==='email_rate_limited'){if(report)throw error;return;}
  await audit(ctx,null,'email_delivery_failed',person.id);
  if(report)fail('email_delivery_failed',503);
 }
}
export async function requestEmail(ctx, request, data) {
 const address=email(data.email), raw=random(), bound=await hash(raw);
 const ip=request.headers.get('cf-connecting-ip') || 'unknown';
 const current=await session(ctx,request),ownAddress=current&&address===current.email;
 const ipLimit=await limitState(ctx,`mail-ip:${await hash(ip)}`,20,3600000);
 const addressLimit=await limitState(ctx,`mail-address:${await hash(address || '')}`,5,3600000);
 if(ownAddress) {
  if(!ipLimit.allowed||!addressLimit.allowed)throw mailLimited(Math.max(!ipLimit.allowed?ipLimit.retryAfter:0,!addressLimit.allowed?addressLimit.retryAfter:0));
  await startProof(ctx,request,data,address,bound,true);
 } else if(address&&ipLimit.allowed&&addressLimit.allowed) {
  // Only an existing session requesting its own address receives delivery details.
  // Every other address keeps the same answer before lookup and delivery finish.
  ctx.waitUntil(startProof(ctx,request,data,address,bound).catch(()=>audit(ctx,null,'email_delivery_failed')));
 }
 return json({message:'If this address can sign in, a link has been sent.'},202,{'set-cookie':cookie(ctx,bindingName(ctx),raw,900)});
}
export async function confirmEmail(ctx,request,data) {
 const proof=await consumeChallenge(ctx,data.token,'email',await binding(ctx,request));
 const person=await one(ctx,'SELECT * FROM oa_operators WHERE id=?',proof.person_id);
 if(!person||!await invitationAdmitted(ctx,person)||person.version!==proof.payload.personVersion)fail('email_proof_stale');
 await requirePolicy(ctx,person,proof.payload.upstreamProofId);
 if(proof.payload.upstreamProofId&&!await upstreamProof(ctx,person.id,proof.payload.upstreamProofId))fail('upstream_proof_expired',403);
 // The browser challenge refers to existing authority, never a caller's method label.
 const hardware=await sessionById(ctx,request,proof.payload.hardwareSessionId);
 if(proof.payload.hardwareSessionId&&(!hardware||hardware.person_id!==person.id||!JSON.parse(hardware.amr).includes('hwk')))fail('passkey_session_expired',403);
 await ctx.db.batch([
  ctx.db.prepare("UPDATE oa_operators SET status='active' WHERE id=? AND status='invited'").bind(proof.person_id),
  ctx.db.prepare('INSERT INTO auth_emails(person_id,verified_at) VALUES(?,?) ON CONFLICT(person_id) DO UPDATE SET verified_at=excluded.verified_at').bind(proof.person_id,ctx.now()),
 ]);
 const s=await createSession(ctx,proof.person_id,[...proof.payload.amr,...(hardware?['hwk']:[])],proof.payload.upstreamProofId,{localEmailVerifiedAt:ctx.now(),expiresAt:hardware?.expires_at,sourceSession:hardware,personVersion:person.status==='active'?person.version:null});
 await syncObligations(ctx);
 await audit(ctx,proof.person_id,'email_confirmed');
 if(person.status==='invited'){await emit(ctx,'person.activated',{type:'person',id:person.id,email:person.email},{method:'email'});await evaluatePerson(ctx,person.id);}
 const returnTo=returnPath(proof.payload.returnTo);
 if((request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded'))return new Response(null,{status:303,headers:{location:returnTo,'set-cookie':s.header,'cache-control':'no-store'}});
 return json({ok:true,returnTo},200,{'set-cookie':s.header});
}
// Confirming continues a pending app sign-in by redirect: browsers hold a form's
// whole redirect chain to its form-action, so that one app's origin is allowed too.
async function continuingClient(ctx,token) {
 const proof=token&&await one(ctx,'SELECT payload FROM auth_challenges WHERE id=? AND purpose=? AND expires_at>?',await hash(token),'email',ctx.now());
 const next=proof&&new URL(JSON.parse(proof.payload).returnTo,ctx.origin),transaction=next?.pathname==='/oidc/authorize/resume'&&next.searchParams.get('transaction');
 const login=transaction&&await one(ctx,'SELECT payload FROM auth_challenges WHERE id=? AND purpose=? AND expires_at>?',await hash(transaction),'authorize-login',ctx.now());
 const clientId=login&&new URL(JSON.parse(login.payload).path,ctx.origin).searchParams.get('client_id');
 const client=clientId&&await one(ctx,'SELECT origin FROM auth_clients WHERE id=? AND disabled_at IS NULL',clientId);
 return client?.origin??null;
}
export async function confirmationPage(ctx,request) {
 const app=await continuingClient(ctx,new URL(request.url).searchParams.get('token'));
 return new Response(framedPage('Confirm your Auth email','<h1>Confirm your email</h1><form method="post"><button class="primary-button">Continue to Auth</button></form>'),{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'strict-origin','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'${app?' '+app:''}; frame-ancestors 'none'; base-uri 'none'`}});
}

export function confirmationError(ctx,error) {
 const message=error.message==='invalid_challenge'
  ? 'This link has expired, was already used, or belongs to another browser. Open the latest link in the browser that requested it, or request a fresh link here.'
  : 'This email link can no longer confirm your sign-in. Request a fresh link and try again. If you still cannot sign in, contact your administrator.';
 return new Response(framedPage('Email link could not continue',`<h1>Email link could not continue</h1><p role="alert">${message}</p><a class="primary-button" href="${ctx.basePath??''}/signin">Request a fresh link</a>`),{status:error.status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`}});
}
