import {notifyNewDevice} from './notifications/index.mjs';
import {one,fail,random,hash,cookie,cookieName,SESSION_MAX_AGE,EMAIL_MAX_AGE} from './core.mjs';
import {requirePolicy,upstreamProof} from './domain-policy.mjs';

export async function prepareSession(ctx,personId,amr,upstreamProofId=null,{localEmailVerifiedAt=null,expiresAt=Infinity,sourceSession=null,personVersion=null,enrollment=false,guard=null}={}) {
 const person=await one(ctx,"SELECT * FROM oa_operators WHERE id=? AND status='active'",personId);if(!person)fail('account_unavailable',403);
 if(personVersion!==null&&person.version!==personVersion)fail('session_authority_changed',403);
 await requirePolicy(ctx,person,upstreamProofId);
 const proof=await upstreamProof(ctx,personId,upstreamProofId);
 if(upstreamProofId&&!proof)fail('upstream_proof_expired',403);
 const raw=random(),id=random(),now=ctx.now();
 const devOnly=ctx.local&&amr.every(method=>method==='dev');
 const emailProof=devOnly?null:await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',personId);
 if(!devOnly&&(!emailProof||emailProof.verified_at+EMAIL_MAX_AGE<=now))fail('email_proof_expired',403);
 const deadline=Math.min(now+SESSION_MAX_AGE,proof?.expires_at??Infinity,expiresAt,emailProof?emailProof.verified_at+EMAIL_MAX_AGE:Infinity);
 // The session write is also the enrollment gate. All dependent writes use its
 // new id in the same transaction, so a zero-row refusal persists nothing.
 const firstEnrollment=enrollment&&!JSON.parse(sourceSession.amr).includes('hwk');
 const statement=ctx.db.prepare(`INSERT INTO auth_sessions(id,token_hash,person_id,person_version,amr,created_at,expires_at,upstream_proof_id,local_email_verified_at)
 SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status='active')
 AND (?=1 OR EXISTS(SELECT 1 FROM auth_emails WHERE person_id=? AND verified_at=? AND verified_at+?>?))
 AND (? IS NULL OR EXISTS(SELECT 1 FROM auth_sessions WHERE id=? AND person_id=? AND person_version=? AND person_version=? AND amr=? AND revoked_at IS NULL AND expires_at>? AND expires_at=?))
 AND (?=0 OR NOT EXISTS(SELECT 1 FROM auth_passkeys WHERE person_id=?))${guard?` AND ${guard.clause}`:''}`).bind(
 id,await hash(raw),personId,person.version,JSON.stringify([...new Set(ctx.local?['dev',...amr]:amr)]),now,deadline,proof?.id||null,localEmailVerifiedAt,
 personId,person.version,devOnly?1:0,personId,emailProof?.verified_at??null,EMAIL_MAX_AGE,now,
 sourceSession?.id||null,sourceSession?.id||null,personId,person.version,sourceSession?.person_version??null,sourceSession?.amr||null,now,sourceSession?.expires_at??null,
 firstEnrollment?1:0,personId,...(guard?guard.args:[]));
 return {id,header:cookie(ctx,cookieName(ctx),raw,Math.floor((deadline-now)/1000)),statement,now};
}

export async function createSession(ctx,...args) {
 const prepared=await prepareSession(ctx,...args),inserted=await prepared.statement.run();
 if(!inserted.meta.changes)fail('session_authority_changed',403);
 const deviceHeader=await notifyNewDevice(ctx,{personId:args[0],sessionId:prepared.id,request:args[3]?.request,app:args[3]?.app});
 return {id:prepared.id,header:prepared.header,deviceHeader};
}
