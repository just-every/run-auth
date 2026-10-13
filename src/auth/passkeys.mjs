import {requirePolicy,upstreamProof} from './domain-policy.mjs';
import {freshLocalEmail,requireLocalEmail,authority,requireAuthority} from './local-email.mjs';
import {prepareSession} from './session-write.mjs';
import {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {utf8,b64,unb64,random,hash,binding,bindingName,cookie,challenge,consumeChallenge,requireSession,session,sessionById,one,all,run,json,fail,createSession,EMAIL_MAX_AGE,audit,returnPath} from './core.mjs';
import {sendProof} from './email.mjs';
async function enrollmentSession(ctx,request) {
 const s=await session(ctx,request);
 if(!s) fail('sign_in_required',401);
 const existing=await one(ctx,'SELECT id FROM auth_passkeys WHERE person_id=? LIMIT 1',s.person_id);
 const methods=JSON.parse(s.amr);
 if(!methods.includes('hwk')) {
  if(existing) fail('passkey_required',403);
  if(!methods.includes('email')) fail('email_proof_required',403);
 }
 requireLocalEmail(ctx,s);
 return s;
}
export async function registrationOptions(ctx,request) {
 const s=await enrollmentSession(ctx,request), raw=random();
 const options=await generateRegistrationOptions({rpName:'Auth',rpID:new URL(ctx.origin).hostname,userID:utf8.encode(s.person_id),userName:s.email,userDisplayName:s.display_name,supportedAlgorithmIDs:[-7,-257],attestationType:'none',authenticatorSelection:{residentKey:'required',userVerification:'required'},excludeCredentials:(await all(ctx,'SELECT id,transports FROM auth_passkeys WHERE person_id=?',s.person_id)).map(p=>({id:p.id,transports:JSON.parse(p.transports)}))});
 // The challenge belongs to this session and its authority snapshot; it is stored
 // only while that authority and its fresh local proof hold.
 const guard=authority(ctx,s),token=await challenge(ctx,'register',s.person_id,await hash(raw),{challenge:options.challenge,sessionId:s.id,amr:s.amr,personVersion:s.person_version},600000,guard);
 if(!token){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
 return json({options,transaction:token},200,{'set-cookie':cookie(ctx,bindingName(ctx),raw,600)});
}
export async function registrationVerify(ctx,request,data) {
 const s=await enrollmentSession(ctx,request);
 const tx=await consumeChallenge(ctx,data.transaction,'register',await binding(ctx,request)); if(tx.person_id!==s.person_id) fail('account_mismatch');
 if(tx.payload.sessionId!==s.id||tx.payload.amr!==s.amr||tx.payload.personVersion!==s.person_version) fail('enrollment_session_changed',403);
 let checked; try { checked=await verifyRegistrationResponse({response:data.response,expectedChallenge:tx.payload.challenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,supportedAlgorithmIDs:[-7,-257]}); } catch {fail('invalid_passkey');}
 if(!checked.verified || !checked.registrationInfo) fail('invalid_passkey');
 const c=checked.registrationInfo.credential;
 const established=await prepareSession(ctx,s.person_id,s.upstream_proof_id?['oidc','hwk']:['hwk'],s.upstream_proof_id,{localEmailVerifiedAt:s.local_email_verified_at,sourceSession:s,enrollment:true,guard:authority(ctx,s)});
 const response=json({ok:true},200,{'set-cookie':established.header});
 // D1 commits this batch together or rolls it all back. Both dependent inserts
 // select the new session, which exists only while the issuing session keeps its
 // authority and fresh local proof: a refused gate creates neither credential nor audit.
 const [inserted]=await ctx.db.batch([
  established.statement,
  ctx.db.prepare('INSERT INTO auth_passkeys(id,person_id,public_key,counter,transports,created_at) SELECT ?,person_id,?,?,?,? FROM auth_sessions WHERE id=?').bind(c.id,b64(c.publicKey),c.counter,JSON.stringify(c.transports||[]),established.now,established.id),
  ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT person_id,'passkey_registered',?,? FROM auth_sessions WHERE id=?").bind(c.id,established.now,established.id),
 ]);
 if(!inserted.meta.changes)fail('session_authority_changed',403);
 return response;
}
export async function authenticationOptions(ctx,request,data={}) {
 const current=await session(ctx,request);
 const raw=random(), options=await generateAuthenticationOptions({rpID:new URL(ctx.origin).hostname,userVerification:'required'});
 const token=await challenge(ctx,'authenticate',null,await hash(raw),{challenge:options.challenge,returnTo:returnPath(data.returnTo),upstreamProofId:current?.upstream_proof_id||null,localEmailSessionId:freshLocalEmail(ctx,current)?current.id:null});
 return json({options,transaction:token},200,{'set-cookie':cookie(ctx,bindingName(ctx),raw,600)});
}
export async function authenticationVerify(ctx,request,data) {
 const bound=await binding(ctx,request),tx=await consumeChallenge(ctx,data.transaction,'authenticate',bound);
 const key=await one(ctx,'SELECT * FROM auth_passkeys WHERE id=?',data.response?.id || ''); if(!key) fail('invalid_passkey');
 let checked; try {checked=await verifyAuthenticationResponse({response:data.response,expectedChallenge:tx.payload.challenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,credential:{id:key.id,publicKey:unb64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});} catch{fail('invalid_passkey');}
 if(!checked.verified) fail('invalid_passkey');
 const person=await one(ctx,"SELECT * FROM oa_operators WHERE id=? AND status='active'",key.person_id);if(!person)fail('account_unavailable',403);
 await requirePolicy(ctx,person,tx.payload.upstreamProofId);
 if(tx.payload.upstreamProofId&&!await upstreamProof(ctx,person.id,tx.payload.upstreamProofId))fail('upstream_proof_expired',403);
 const result=await run(ctx,'UPDATE auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND counter=?',checked.authenticationInfo.newCounter,ctx.now(),key.id,key.counter); if(!result.meta.changes) fail('passkey_changed');
 const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',person.id);
 if(!proof || ctx.now()-proof.verified_at>=EMAIL_MAX_AGE){await sendProof(ctx,person,bound,tx.payload.upstreamProofId?['oidc','hwk','email']:['hwk','email'],tx.payload.returnTo,tx.payload.upstreamProofId);return json({reproof:true},202);}
 const emailSession=await sessionById(ctx,request,tx.payload.localEmailSessionId);
 const localEmailVerifiedAt=emailSession?.person_id===person.id&&freshLocalEmail(ctx,emailSession)?emailSession.local_email_verified_at:null;
 const s=await createSession(ctx,person.id,tx.payload.upstreamProofId?['oidc','hwk']:['hwk'],tx.payload.upstreamProofId,{localEmailVerifiedAt,sourceSession:localEmailVerifiedAt?emailSession:null,personVersion:person.version});await audit(ctx,person.id,'passkey_authenticated');return json({ok:true,returnTo:returnPath(tx.payload.returnTo)},200,{'set-cookie':s.header});
}
