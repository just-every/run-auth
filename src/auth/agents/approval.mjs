// One exact approval by a person. The approver is an administrator with a
// passkey session and fresh local email proof (AUTH-IDENTITY-001) who also
// signs a passkey challenge bound to this proposal. Execution rechecks, in its
// committing statement, the approver's authority, the proposal being pending
// and unexpired, and the target's state being exactly what was filed; one
// claim runs the effect, so a double click or a second approver changes nothing.
import {generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {random,hash,unb64,binding,bindingName,cookie,challenge,consumeChallenge,one,all,run,json,fail,auditDetail} from '../core.mjs';
import {requireAuthority} from '../local-email.mjs';
import {sendInvitation} from '../admin.mjs';
import {administrator} from './keys.mjs';
import {KINDS,digest,changes} from './kinds.mjs';

const pending=async(ctx,id)=>{
 const p=await one(ctx,'SELECT p.*,k.label AS key_label FROM auth_agent_proposals p JOIN auth_agent_keys k ON k.id=p.key_id WHERE p.id=?',String(id||''))||fail('proposal_not_found',404);
 if(p.status!=='pending')fail('proposal_decided',409);
 return p;
};
const targetName=p=>{const effect=JSON.parse(p.effect);return effect.person?.email??effect.domain??p.target;};

// Close a pending proposal without running it and say why, in the proposal and in Activity.
async function close(ctx,s,guard,p,status,outcome) {
 const closed=await run(ctx,`UPDATE auth_agent_proposals SET status=?,decided_by=?,decided_at=?,outcome=? WHERE id=? AND status='pending' AND ${guard.clause}`,status,s.person_id,ctx.now(),JSON.stringify(outcome),p.id,...guard.args);
 if(!closed.meta.changes){await requireAuthority(ctx,s,guard);fail('proposal_decided',409);}
 await auditDetail(ctx,s.person_id,`agent_proposal_${status}`,p.id,{key:p.key_label,proposal:p.kind.replace(/_/g,' '),target:targetName(p),result:status,...outcome});
}

export async function approvalOptions(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),p=await pending(ctx,data.proposalId);
 const passkeys=await all(ctx,'SELECT id,transports FROM auth_passkeys WHERE person_id=?',s.person_id);
 const raw=random(),options=await generateAuthenticationOptions({rpID:new URL(ctx.origin).hostname,userVerification:'required',allowCredentials:passkeys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
 // The challenge names this proposal, this session and the state the person is shown.
 const token=await challenge(ctx,'approve',s.person_id,await hash(raw),{challenge:options.challenge,proposalId:p.id,sessionId:s.id,digest:p.state_digest},300000,guard);
 if(!token){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
 return json({options,transaction:token},200,{'set-cookie':cookie(ctx,bindingName(ctx),raw,300)});
}

async function passkeyProof(ctx,request,s,data) {
 const tx=await consumeChallenge(ctx,data.transaction,'approve',await binding(ctx,request));
 if(tx.person_id!==s.person_id||tx.payload.sessionId!==s.id)fail('approval_session_changed',403);
 const key=await one(ctx,'SELECT * FROM auth_passkeys WHERE id=? AND person_id=?',String(data.response?.id||''),s.person_id)||fail('invalid_passkey');
 let checked;try {checked=await verifyAuthenticationResponse({response:data.response,expectedChallenge:tx.payload.challenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,credential:{id:key.id,publicKey:unb64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});} catch {fail('invalid_passkey');}
 if(!checked.verified)fail('invalid_passkey');
 const used=await run(ctx,'UPDATE auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND counter=?',checked.authenticationInfo.newCounter,ctx.now(),key.id,key.counter);
 if(!used.meta.changes)fail('passkey_changed');
 return tx.payload;
}

export async function approve(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),proof=await passkeyProof(ctx,request,s,data);
 const p=await pending(ctx,proof.proposalId),kind=KINDS[p.kind],params=JSON.parse(p.params);
 if(proof.digest!==p.state_digest)fail('approval_session_changed',403);
 if(p.expires_at<=ctx.now()){await close(ctx,s,guard,p,'rejected',{reason:'expired'});fail('proposal_expired',409);}
 // A target that changed since filing closes the proposal as stale and says what changed.
 const stale=async state=>{
  if(await digest(state)===p.state_digest)return null;
  const changed=changes(JSON.parse(p.target_state),state);
  await close(ctx,s,guard,p,'rejected',{reason:'stale',changed});return json({error:'proposal_stale',changed},409);
 };
 const state=await kind.state(ctx,p.target),changed=await stale(state);
 if(changed)return changed;
 const refusal=await kind.check(state,ctx,params);
 if(refusal){await close(ctx,s,guard,p,'failed',{reason:refusal});fail(refusal,409);}
 // This approver cannot run it, but another administrator still may.
 const own=kind.approver?.(state,s.person_id);
 if(own){await auditDetail(ctx,s.person_id,'agent_proposal_refused',p.id,{key:p.key_label,proposal:p.kind.replace(/_/g,' '),target:targetName(p),reason:own});fail(own,403);}

 const execution=random(),now=ctx.now(),same=kind.same(state),requires=kind.requires?.(state)??{sql:'1',args:[]};
 const claimed={sql:'EXISTS(SELECT 1 FROM auth_agent_proposals WHERE id=? AND execution_id=?)',args:[p.id,execution]};
 const outcome={reason:'approved'},detail={key:p.key_label,proposal:p.kind.replace(/_/g,' '),target:targetName(p),result:'done'};
 let results;
 try {
  results=await ctx.db.batch([
   ctx.db.prepare(`UPDATE auth_agent_proposals SET status='done',decided_by=?,decided_at=?,outcome=?,execution_id=? WHERE id=? AND status='pending' AND expires_at>? AND state_digest=? AND ${same.sql} AND ${requires.sql} AND ${guard.clause}`)
    .bind(s.person_id,now,JSON.stringify(outcome),execution,p.id,now,p.state_digest,...same.args,...requires.args,...guard.args),
   ...kind.run(ctx,state,claimed,params,random(),s.person_id),
   ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'agent_proposal_done',?,? WHERE ${claimed.sql}`).bind(s.person_id,p.id,now,...claimed.args),
   ctx.db.prepare(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${claimed.sql}`).bind(JSON.stringify(detail),...claimed.args),
  ]);
 } catch(error) {
  // A store rule refused the effect (for example the last owner); nothing ran.
  const reason=/last_owner|invitation_required/.exec(String(error?.message))?.[0]??'execution_failed';
  await close(ctx,s,guard,p,'failed',{reason});fail(reason,409);
 }
 // Nothing ran: another approval won, the approver's authority lapsed, or the
 // target moved after the checks above. Say which.
 if(!results[0].meta.changes) {
  if((await one(ctx,'SELECT status FROM auth_agent_proposals WHERE id=?',p.id)).status!=='pending')fail('proposal_decided',409);
  await requireAuthority(ctx,s,guard);
  if(p.expires_at<=now){await close(ctx,s,guard,p,'rejected',{reason:'expired'});fail('proposal_expired',409);}
  const moved=await stale(await kind.state(ctx,p.target));if(moved)return moved;
  const blocked=kind.requires?'last_administrator':'proposal_unavailable';
  await close(ctx,s,guard,p,'failed',{reason:blocked});fail(blocked,409);
 }
 if(kind.mail) {
  try {await sendInvitation(ctx,p.target);}
  catch {await auditDetail(ctx,s.person_id,'agent_invitation_mail_failed',p.id,{target:p.target});}
 }
 return json({id:p.id,status:'done'});
}

export async function reject(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),p=await pending(ctx,data.proposalId);
 await close(ctx,s,guard,p,'rejected',{reason:'rejected_by_person'});
 return json({id:p.id,status:'rejected'});
}
