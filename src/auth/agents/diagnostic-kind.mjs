import {fail} from '../core.mjs';
import {diagnosticStamp,stampArgs} from './diagnostic-guard.mjs';
import {certificateValidity} from '../saml/der.mjs';
import {diagnosticState} from './diagnostic-state.mjs';
import {diagnosticProbe} from './diagnostic-probe.mjs';
import {recoveryRequestedEmail} from '../recovery-notices.mjs';

export const DIAGNOSTIC_KINDS={repair_signin:{
 target:()=>fail('diagnostic_consent_required',403),
 state:diagnosticState,
 changes:()=>['The app, employee, assignment, certificate, policy or recovery state changed. Prepare a new diagnosis.'],
 check:(state,ctx,params)=>{
  if(!state.app||state.app.disabled_at)return 'app_unavailable';
  if(!state.person||state.person.status!=='active'||!state.assigned)return 'assigned_test_identity_required';
  if(params.repair&&params.issue==='certificate'){const next=state.keys.find(k=>k.kid===params.kid&&k.state==='next');if(!next||certificateValidity(next.certificate).notBefore>ctx.now()||certificateValidity(next.certificate).notAfter<=ctx.now())return 'replacement_certificate_unavailable';}
  return null;
 },
 approver:(state,approverId,params)=>!params.repair?'diagnostic_action_required':null,
 same:(state,params)=>({sql:`(${diagnosticStamp})=?`,args:[...stampArgs(state.app.id,params),state.stamp]}),
 effect:async(ctx,state,params)=>{
  const probe=diagnosticProbe(state,params);
  return {app:{name:state.app?.name??'Removed app',origin:ctx.issuer??ctx.origin},diagnostic:{
   probe,worker:state.person?.email??'Removed employee',issue:params.issue,diagnosis:params.result,
   repair:params.repair?{...params.repair,before:params.issue==='callback'?state.redirects:params.issue==='certificate'?state.keys.find(k=>k.state==='active')?.kid??null:state.mail?.event??'unknown'}:null,
   affectedApps:state.affectedApps,sources:params.sources,
   verification:!params.repair?'Unverified: follow the next diagnostic action before preparing a repair.':probe?'Unverified: run the scoped employee sign-in and logout probe. A configuration write is not proof of access.':'Unverified: use the app owner’s protocol consumer for this unsupported probe profile. Do not claim working access from a configuration write.',
  }};
 },
 run:(ctx,state,claim,params)=>{
  if(!params.repair)fail('diagnostic_action_required',409);
  const p=(sql,...args)=>ctx.db.prepare(sql).bind(...args,...claim.args);
  if(params.issue==='callback')return [p(`UPDATE auth_oidc_clients SET redirect_uris=? WHERE app_id=? AND ${claim.sql}`,JSON.stringify(params.repair.after),state.app.id),p(`UPDATE auth_apps SET version=version+1,updated_at=? WHERE id=? AND ${claim.sql}`,ctx.now(),state.app.id)];
  if(params.issue==='certificate')return [p(`UPDATE auth_saml_keys SET state='previous' WHERE kid=? AND state='active' AND ${claim.sql}`,params.repair.before),p(`UPDATE auth_saml_keys SET state='active',activated_at=? WHERE kid=? AND state='next' AND ${claim.sql}`,ctx.now(),params.repair.after)];
  return [];
 },
 after:async(ctx,state,params)=>{
  if(params.issue==='mail')await recoveryRequestedEmail(ctx,state.person.id,state.recovery.id);
 },
}};
