// Public settings and scoped employee facts; private key and token columns are
// deliberately absent from both the snapshot and every model source.
import {one,all,fail,hash} from '../core.mjs';
import {certificateValidity} from '../saml/der.mjs';
import {diagnosticStamp,stampArgs} from './diagnostic-guard.mjs';
import {assignment} from '../workforce/directory.mjs';

export async function diagnosticState(ctx,appId,params) {
 const stamp=(await one(ctx,diagnosticStamp,...stampArgs(appId,params))).stamp;
 const app=await one(ctx,'SELECT id,name,protocol,version,disabled_at,entity_id,acs,slo,sign,digest,name_id_format,sp_certificates FROM auth_apps WHERE id=?',appId);
 const person=await one(ctx,'SELECT id,email,status,version FROM oa_operators WHERE id=?',params.personId);
 const assigned=app&&person?await assignment(ctx,app.id,person.id):null;
 const client=app?.protocol==='oidc'?await one(ctx,'SELECT client_id,auth_method,redirect_uris,post_logout_redirect_uris FROM auth_oidc_clients WHERE app_id=?',app.id):null;
 const keys=params.issue==='certificate'?await all(ctx,"SELECT kid,certificate,state FROM auth_saml_keys WHERE state IN ('active','next') ORDER BY kid"):[];
 const recovery=params.issue==='mail'?await one(ctx,'SELECT id,person_id,created_at,ready_at,approved_by,cancelled_at,completed_at FROM auth_recoveries WHERE id=? AND person_id=?',params.recoveryId,params.personId):null;
 const mail=params.issue==='mail'?await one(ctx,"SELECT id,created_at,event FROM auth_activity WHERE subject_id=? AND event IN ('recovery_mail_failed','recovery_mail_resent') ORDER BY id DESC LIMIT 1",params.recoveryId):null;
 const traceRow=await one(ctx,"SELECT a.id,a.event,a.created_at,d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.actor_id=? AND a.subject_id=? AND a.event='oidc_callback_refused' ORDER BY a.id DESC LIMIT 1",params.personId,appId);
 const trace=traceRow?{id:traceRow.id,event:traceRow.event,created_at:traceRow.created_at,callbackMatches:JSON.parse(traceRow.detail).callbackDigest===await hash(params.callback??'')}:null;
 const changes=await all(ctx,"SELECT event,created_at FROM auth_activity WHERE subject_id=? AND event IN ('oidc_app_created','company_app_updated','company_app_created','app_assigned','app_unassigned') ORDER BY id DESC LIMIT 10",appId);
 const affectedApps=params.issue==='certificate'?await all(ctx,"SELECT id,name FROM auth_apps WHERE protocol='saml' AND disabled_at IS NULL ORDER BY id"):[];
 const policy=await all(ctx,'SELECT domain,provider_id FROM oa_domain_rules ORDER BY domain');
 return {stamp,app,person,assigned,client,redirects:client?JSON.parse(client.redirect_uris):null,keys,recovery,mail,policy,trace,affectedApps,changes};
}
export function diagnosticSources(ctx,state,params) {
 if(!state.app||state.app.disabled_at||!state.person||state.person.status!=='active'||!state.assigned)fail('assigned_test_identity_required',409);
 const source=(id,kind,facts)=>({id,kind,observedAt:ctx.now(),facts});
 const sources=[source('configuration','configuration',{protocol:state.app.protocol,version:state.app.version,registeredCallbackCount:state.redirects?.length??0,requestedCallbackRegistered:state.redirects?.includes(params.callback)??null}),source('policy','policy',{testIdentityActive:state.person.status==='active',assigned:Boolean(state.assigned),requiredProvider:Boolean(state.policy.find(p=>p.domain===state.person.email.split('@')[1]))})];
 sources.push(source('protocol-trace','protocol',{event:state.trace?.event??'not_observed',observedAt:state.trace?.created_at??null,expectedCallbackMatchedTrace:state.trace?.callbackMatches??false}));
 sources.push(source('change-history','configuration-change',{changes:state.changes,deployment:'not independently observed'}));
 if(params.issue==='certificate')sources.push(source('certificates','certificate',state.keys.map(k=>({id:k.kid,state:k.state,...certificateValidity(k.certificate)}))));
 if(params.issue==='mail')sources.push(source('recovery-mail','mail',{pending:Boolean(state.recovery&&!state.recovery.cancelled_at&&!state.recovery.completed_at),outcome:state.mail?.event??'unknown',observedAt:state.mail?.created_at??null}));
 return sources;
}
export function justifiedRepair(ctx,state,params,result) {
 if(result.diagnosis!==params.issue)return null;
 if(params.issue==='callback'&&state.app.protocol==='oidc'&&state.redirects.length===1&&params.callback!==state.redirects[0]&&state.trace?.callbackMatches&&result.citations.includes('configuration')&&result.citations.includes('protocol-trace'))return {field:'redirect_uris',before:state.redirects,after:[params.callback]};
 if(params.issue==='certificate'&&state.app.protocol==='saml'&&result.citations.includes('certificates')) {
  const active=state.keys.find(k=>k.state==='active'),next=state.keys.find(k=>k.kid===params.kid&&k.state==='next');
  if(active&&next&&certificateValidity(active.certificate).notAfter<=ctx.now()&&certificateValidity(next.certificate).notBefore<=ctx.now()&&certificateValidity(next.certificate).notAfter>ctx.now())return {field:'saml_signing_certificate',before:active.kid,after:next.kid};
 }
 if(params.issue==='mail'&&state.recovery&&!state.recovery.cancelled_at&&!state.recovery.completed_at&&state.mail?.event==='recovery_mail_failed'&&result.citations.includes('recovery-mail'))return {field:'recovery_notice',before:'failed',after:'resend once to the same verified mailbox'};
 return null;
}
