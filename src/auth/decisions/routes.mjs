import {submissionStatements} from '../requests/submission.mjs';
import {requestStatements,finishRequest} from '../requests/index.mjs';
import {generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {one,all,random,hash,challenge,consumeChallenge,binding,bindingName,cookie,unb64,requireSession,json,fail,auditDetail} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {decisionTarget,decisionsModel} from './policy.mjs';
import {groupChanged} from '../provisioning/obligations.mjs';
import {reviewStatements,finishRemediation} from '../reviews/items.mjs';

export const DECISIONS_READ='/api/auth/decisions';
export const isDecisionAction=p=>['/decisions/options','/decisions/commit','/decisions/privilege'].includes(p);
export async function decisionsRead(ctx,request) {return json(await decisionsModel(ctx,await requireSession(ctx,request)));}
export async function decisionAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request);
 if(path==='/decisions/privilege') {
  await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
  const kind=String(data.kind??''),id=String(data.targetId??'');
  if(!['group','app','app_role'].includes(kind)||typeof data.privileged!=='boolean')fail('invalid_privilege_mark');
  if(!await one(ctx,`SELECT 1 FROM ${kind==='group'?'auth_groups':'auth_apps'} WHERE id=?`,id))fail('resource_not_found',404);
  const g=authority(ctx,s,['owner','admin']);
  if(kind==='app_role') {
   const role=String(data.role??'').trim();if(!role||role.length>120||/[\u0000-\u001f\u007f]/.test(role))fail('invalid_privilege_role');
   const result=await ctx.db.prepare(`INSERT INTO auth_privileged_app_roles(app_id,role,privileged,marked_by,marked_at) SELECT ?,?,?,?,? WHERE ${g.clause} ON CONFLICT(app_id,role) DO UPDATE SET privileged=excluded.privileged,marked_by=excluded.marked_by,marked_at=excluded.marked_at`).bind(id,role,data.privileged?1:0,s.person_id,ctx.now(),...g.args).run();
   if(!result.meta.changes)fail('session_authority_changed',403);
   await auditDetail(ctx,s.person_id,'privilege_marked',id,{kind,role,privileged:data.privileged});return json({ok:true});
  }
  const result=await ctx.db.prepare(`INSERT INTO auth_privileged_resources(kind,target_id,privileged,marked_by,marked_at) SELECT ?,?,?,?,? WHERE ${g.clause} ON CONFLICT(kind,target_id) DO UPDATE SET privileged=excluded.privileged,marked_by=excluded.marked_by,marked_at=excluded.marked_at`).bind(kind,id,data.privileged?1:0,s.person_id,ctx.now(),...g.args).run();
  if(!result.meta.changes&&!await one(ctx,`SELECT 1 WHERE ${g.clause}`,...g.args))fail('session_authority_changed',403);
  await auditDetail(ctx,s.person_id,'privilege_marked',id,{kind,privileged:data.privileged});return json({ok:true});
 }
 if(path==='/decisions/options') {
  const target=await decisionTarget(ctx,s,data),raw=random();
  const keys=await all(ctx,'SELECT id,transports FROM auth_passkeys WHERE person_id=?',s.person_id);
  const options=await generateAuthenticationOptions({rpID:new URL(ctx.origin).hostname,userVerification:'required',allowCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
  const {snapshot,guard,...saved}=target;
  const transaction=await challenge(ctx,'decision',s.person_id,await hash(raw),{...saved,sessionId:s.id,challenge:options.challenge},15*60000,guard);
  if(!transaction)fail('decision_authority_changed',409);
  return json({options,transaction,decision:saved},200,{'set-cookie':cookie(ctx,bindingName(ctx),raw,900)});
 }
 const tx=await consumeChallenge(ctx,data.transaction,'decision',await binding(ctx,request)),saved=tx.payload;
 if(tx.person_id!==s.person_id||saved.sessionId!==s.id)fail('decision_session_changed',403);
 const current=await decisionTarget(ctx,s,saved);
 if(current.digest!==saved.digest||current.epoch!==saved.epoch)fail('decision_state_changed',409);
 const key=await one(ctx,'SELECT * FROM auth_passkeys WHERE id=? AND person_id=?',data.response?.id??'',s.person_id)??fail('invalid_passkey');
 let checked;try {checked=await verifyAuthenticationResponse({response:data.response,expectedChallenge:saved.challenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,credential:{id:key.id,publicKey:unb64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});}catch{fail('invalid_passkey');}
 if(!checked.verified)fail('invalid_passkey');
 const id=random(),now=ctx.now(),g=current.guard,won={clause:'EXISTS(SELECT 1 FROM auth_decision_operations WHERE id=?)',args:[id]},p=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const changes=current.kind==='request_submit'?submissionStatements(ctx,s,current,id,won,p):current.kind==='request'?requestStatements(ctx,s,current,id,won,p):current.kind==='review'?reviewStatements(ctx,s,current,id,won,p):[
  current.operation==='add'?p(`INSERT INTO auth_group_members(group_id,person_id,added_by,added_at,source) SELECT ?,?,?,?,'manual' WHERE ${won.clause} ON CONFLICT(group_id,person_id) DO UPDATE SET source='manual',added_by=excluded.added_by,added_at=excluded.added_at`,current.targetId,current.personId,s.person_id,now,id):p(`DELETE FROM auth_group_members WHERE group_id=? AND person_id=? AND ${won.clause}`,current.targetId,current.personId,id),
  current.operation==='add'?p(`DELETE FROM auth_group_exclusions WHERE group_id=? AND person_id=? AND ${won.clause}`,current.targetId,current.personId,id):p(`INSERT INTO auth_group_exclusions(group_id,person_id,reason,set_by,set_at) SELECT ?,?,?,?,? WHERE ${won.clause} ON CONFLICT(group_id,person_id) DO UPDATE SET reason=excluded.reason,set_by=excluded.set_by,set_at=excluded.set_at`,current.targetId,current.personId,current.reason,s.person_id,now,id),
 ];
 const results=await ctx.db.batch([
  p(`INSERT INTO auth_decision_operations(id,actor_id,session_id,kind,target_id,operation,person_id,reason,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM auth_passkeys WHERE id=? AND counter=?)`,id,s.person_id,s.id,current.kind,current.targetId,current.operation,current.personId,current.reason,now,...g.args,key.id,key.counter),
  p(`UPDATE auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND ${won.clause}`,checked.authenticationInfo.newCounter,now,key.id,id),
  ...changes,
  p(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'business_decision',?,? WHERE ${won.clause}`,s.person_id,current.targetId,now,id),
  p(`INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE ${won.clause}`,JSON.stringify({operationId:id,kind:current.kind,operation:current.operation,personId:current.personId,reason:current.reason,privileged:current.privileged}),id),
 ]);
 if(!results[0].meta.changes)fail('decision_authority_changed',409);
 if(current.kind==='group')await groupChanged(ctx,current.targetId,[current.personId],'owner_decision');
 else if(current.kind==='request')await finishRequest(ctx,current.targetId);
 else if(current.kind==='review')await finishRemediation(ctx,current.targetId);
 return json({ok:true,operationId:id,...(current.kind==='request_submit'?{id}:{})},current.kind==='request_submit'?201:200);
}
