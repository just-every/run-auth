import {one,all,random,hash,json,fail,requireSession,session,cookie,cookieName,limit,audit} from '../core.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {roleState} from '../roles/state.mjs';
import {requireHardware,roleGuard} from '../roles/policy.mjs';
import {commit} from '../roles/commit.mjs';
import {HOUR,managerOf,target,canIssue,hireGuard,verificationGuard,capabilityGuard} from './authority.mjs';
export {sessionValid,enrollmentGuard,completeEnrollment,rebindSession,sessionPass} from './enrollment.mjs';

function publicWrite(ctx,request) {
 if(request.method!=='POST')fail('method_not_allowed',405);
 if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
}
async function human(ctx,request) {
 publicWrite(ctx,request);
 const s=await requireSession(ctx,request);requireHardware(s);requireLocalEmail(ctx,s);
 return {s,state:await roleState(ctx,s)};
}
const combine=(first,second)=>({clause:`(${first.clause}) AND (${second.clause})`,args:[...first.args,...second.args]});
async function requestPassAction(ctx,request,data) {
 const {s,state}=await human(ctx,request),personId=String(data.personId??''),person=target(state,personId);
 if(personId===s.person_id||managerOf(state,personId)!==s.person_id)fail('current_manager_required',403);
 const reason=String(data.reason??'').trim();if(!reason||reason.length>500)fail('verification_reason_required');
 const guard=combine(roleGuard(ctx,s,state),await hireGuard(ctx,state,personId,person.version)),id=random();
 await commit(ctx,s,guard,'temporary_pass.requested',id,{personId,managerId:s.person_id,reason},(g,q)=>[
  q(`INSERT INTO auth_temporary_pass_requests(id,person_id,person_version,manager_id,manager_session_id,reason,created_at,expires_at) SELECT ?,?,?,?,?,?,?,? WHERE ${g.clause}`,id,personId,person.version,s.person_id,s.id,reason,ctx.now(),ctx.now()+HOUR,...g.args),
 ]);
 return json({ok:true,requestId:id,expiresAt:ctx.now()+HOUR},201);
}
async function issuePassAction(ctx,request,data) {
 const {s,state}=await human(ctx,request),review=await one(ctx,'SELECT * FROM auth_temporary_pass_requests WHERE id=?',String(data.requestId??''));
 if(!review||review.issued_at!==null)fail('temporary_pass_request_unavailable',403);
 if(!canIssue(state,review.person_id))fail('role_permission_required',403);
 let guard=combine(roleGuard(ctx,s,state),await verificationGuard(ctx,state,review));
 guard=combine(guard,{clause:'EXISTS(SELECT 1 FROM auth_temporary_pass_requests WHERE id=? AND issued_at IS NULL)',args:[review.id]});
 const id=random(),pass=random(),digest=await hash(pass),expiresAt=Math.min(ctx.now()+HOUR,review.expires_at);
 await commit(ctx,s,guard,'temporary_pass.issued',id,{personId:review.person_id,requestId:review.id,expiresAt},(g,q)=>[
  q(`UPDATE auth_temporary_passes SET revoked_at=COALESCE(revoked_at,?) WHERE person_id=? AND completed_at IS NULL AND ${g.clause}`,ctx.now(),review.person_id,...g.args),
  q(`UPDATE auth_temporary_pass_requests SET issued_at=? WHERE id=? AND ${g.clause}`,ctx.now(),review.id,...g.args),
  q(`INSERT INTO auth_temporary_passes(id,request_id,person_id,person_version,issuer_id,issuer_session_id,token_hash,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${g.clause}`,id,review.id,review.person_id,review.person_version,s.person_id,s.id,digest,ctx.now(),expiresAt,...g.args),
 ]);
 return json({ok:true,passId:id,pass,personId:review.person_id,expiresAt},201);
}
async function revokePassAction(ctx,request,data) {
 const {s,state}=await human(ctx,request),pass=await one(ctx,'SELECT * FROM auth_temporary_passes WHERE id=?',String(data.passId??''));
 if(!pass||!canIssue(state,pass.person_id))fail('role_permission_required',403);
 target(state,pass.person_id);
 const guard=roleGuard(ctx,s,state);
 await commit(ctx,s,guard,'temporary_pass.revoked',pass.id,{personId:pass.person_id},(g,q)=>[
  q(`UPDATE auth_temporary_passes SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND ${g.clause}`,ctx.now(),pass.id,...g.args),
  q(`UPDATE auth_sessions SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND ${g.clause}`,ctx.now(),pass.enrollment_session_id,...g.args),
 ]);
 return json({ok:true});
}
export async function redeemPass(ctx,request,data) {
 publicWrite(ctx,request);
 const source=ctx.abuseSource??'unavailable';
 if(!await limit(ctx,`temporary-pass:${await hash(source)}`,20,HOUR))fail('temporary_pass_rate_limited',429);
 const pass=await one(ctx,'SELECT * FROM auth_temporary_passes WHERE token_hash=?',await hash(String(data.pass??'')));
 try {
  if(!pass||pass.consumed_at!==null)fail('temporary_pass_unavailable',403);
  const current=await session(ctx,request);
  if(current&&current.person_id!==pass.person_id)fail('temporary_pass_person_mismatch',403);
  let guard=await capabilityGuard(ctx,pass);
  guard=combine(guard,{clause:'EXISTS(SELECT 1 FROM auth_temporary_passes WHERE id=? AND consumed_at IS NULL)',args:[pass.id]});
  const raw=random(),sessionId=random(),sessionDigest=await hash(raw),principal={person_id:pass.person_id,id:sessionId};
  await commit(ctx,principal,guard,'temporary_pass.used',pass.id,{personId:pass.person_id},(g,q)=>[
   q(`UPDATE auth_temporary_passes SET consumed_at=?,enrollment_session_id=? WHERE id=? AND ${g.clause}`,ctx.now(),sessionId,pass.id,...g.args),
   q(`UPDATE oa_operators SET status='active' WHERE id=? AND status='invited' AND ${g.clause}`,pass.person_id,...g.args),
   // Base advances the version when an invitation becomes active. Adopt only
   // that same atomic activation's version for the attested capability.
   q(`UPDATE auth_temporary_pass_requests SET person_version=(SELECT version FROM oa_operators WHERE id=?) WHERE id=? AND ${g.clause}`,pass.person_id,pass.request_id,...g.args),
   q(`UPDATE auth_temporary_passes SET person_version=(SELECT version FROM oa_operators WHERE id=?) WHERE id=? AND ${g.clause}`,pass.person_id,pass.id,...g.args),
   q(`INSERT INTO auth_sessions(id,token_hash,person_id,person_version,amr,created_at,expires_at) SELECT ?,?,id,version,'["tap","onboarding"]',?,? FROM oa_operators WHERE id=? AND ${g.clause}`,sessionId,sessionDigest,ctx.now(),pass.expires_at,pass.person_id,...g.args),
  ]);
  return json({ok:true,returnTo:'/app/methods'},200,{'set-cookie':cookie(ctx,cookieName(ctx),raw,Math.floor((pass.expires_at-ctx.now())/1000))});
 }catch(error){
  if(error.status&&pass)await audit(ctx,null,pass.expires_at<=ctx.now()?'temporary_pass.expired':'temporary_pass.refused',pass.id);
  throw error;
 }
}
async function administrativeAction(ctx,action,run) {
 try{return await run();}
 catch(error){if(error.status)await audit(ctx,null,`temporary_pass.${action}.refused`);throw error;}
}
export const requestPass=(ctx,request,data)=>administrativeAction(ctx,'request',()=>requestPassAction(ctx,request,data));
export const issuePass=(ctx,request,data)=>administrativeAction(ctx,'issue',()=>issuePassAction(ctx,request,data));
export const revokePass=(ctx,request,data)=>administrativeAction(ctx,'revoke',()=>revokePassAction(ctx,request,data));
export async function temporaryPassesModel(ctx,s) {
 const hires=await all(ctx,`SELECT h.person_id FROM auth_onboarding h JOIN oa_operators p ON p.id=h.person_id WHERE h.rescinded_at IS NULL AND p.status IN ('active','invited') AND NOT EXISTS(SELECT 1 FROM auth_passkeys k WHERE k.person_id=p.id)`);
 if(!hires.length)return {people:[],requests:[],passes:[]};
 const state=await roleState(ctx,s),hardware=JSON.parse(s.amr).includes('hwk');
 const people=hires.flatMap(({person_id:id})=>{
  const p=state.dir.people.get(id);if(!p||p.role!=='member'||state.rankOf(id)>0)return [];
  const canRequest=hardware&&managerOf(state,id)===s.person_id&&id!==s.person_id,canIssuePass=hardware&&canIssue(state,id);
  return canRequest||canIssuePass?[{personId:id,email:p.email,name:p.name,canRequest,canIssue:canIssuePass}]:[];
 });
 const visible=new Set(people.map(p=>p.personId));
 return {people,requests:(await all(ctx,'SELECT id,person_id AS personId,manager_id AS managerId,reason,created_at AS createdAt,expires_at AS expiresAt,issued_at AS issuedAt FROM auth_temporary_pass_requests ORDER BY created_at DESC')).filter(r=>visible.has(r.personId)),passes:(await all(ctx,'SELECT id,person_id AS personId,created_at AS createdAt,expires_at AS expiresAt,consumed_at AS consumedAt,completed_at AS completedAt,revoked_at AS revokedAt FROM auth_temporary_passes ORDER BY created_at DESC')).filter(p=>visible.has(p.personId))};
}
