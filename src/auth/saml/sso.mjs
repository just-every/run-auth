// SAML single sign-on: SP-initiated requests over HTTP-Redirect and HTTP-POST,
// and IdP-initiated launches an app explicitly permits.
import {one,run,hash,random,session,cookie,cookies,challenge,consumeChallenge,audit,fail} from '../core.mjs';
import {parseXml,child,children,attr,textOf,NS} from './xml.mjs';
import {verifyBytes,verifyEnveloped} from './signing.mjs';
import {readMessage,sendMessage,samlPage,BINDINGS} from './bindings.mjs';
import {appOf,defaultAcs,FORMATS} from './apps.mjs';
import {signInResponse,statusResponse} from './assertion.mjs';
import {assignment} from '../workforce/directory.mjs';

export const SSO_PATH='/saml/sso',RESUME_PATH='/saml/resume';
const SKEW=300000,REQUEST_LIFETIME=900000;
const loginCookie=ctx=>ctx.local?'auth_saml_login':'__Host-auth_saml_login';
const ID=/^[A-Za-z_][\w.-]{0,255}$/;

export const activeApp=async(ctx,where,value)=>appOf(await one(ctx,`SELECT * FROM auth_apps WHERE ${where}=? AND disabled_at IS NULL`,value));
export function checkInstant(ctx,value) {
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value||'')||Math.abs(Date.parse(value)-ctx.now())>SKEW)fail('stale_saml_message');
}
// Returns whether the message was signed; refuses a bad signature, and an
// unsigned one when `required`.
export async function verifyMessage(ctx,app,message,root,required) {
 const sha1=Boolean(app.sha1_exception),certs=app.spCertificates;
 const embedded=children(root,'Signature',NS.ds).length>0;
 if(message.signature) {
  if(embedded||!certs.length||!await verifyBytes(certs,message.signature.algorithm,message.signature.signed,message.signature.value,sha1))fail('invalid_saml_signature');
  return true;
 }
 if(embedded) {
  if(message.binding!=='post'||!certs.length||!await verifyEnveloped(root,certs,sha1))fail('invalid_saml_signature');
  return true;
 }
 if(required)fail('saml_signature_required');
 return false;
}
// The common checks of an inbound protocol message from a known app.
export async function inbound(ctx,request,expected) {
 const message=await readMessage(request),root=parseXml(message.xml);
 if(root.uri!==NS.samlp||!expected.includes(root.local))fail('invalid_saml_message');
 const app=await activeApp(ctx,'entity_id',textOf(child(root,'Issuer',NS.saml)).trim())||fail('unknown_saml_app');
 const id=attr(root,'ID');if(!ID.test(id||'')||attr(root,'Version')!=='2.0')fail('invalid_saml_message');
 checkInstant(ctx,attr(root,'IssueInstant'));
 return {message,root,app,id};
}
export async function once(ctx,appId,id) {
 try{await run(ctx,'INSERT INTO auth_saml_requests(app_id,request_id,expires_at) VALUES(?,?,?)',appId,id,ctx.now()+REQUEST_LIFETIME);}catch{fail('saml_request_replayed');}
}

export async function sso(ctx,request) {
 const {message,root,app,id}=await inbound(ctx,request,['AuthnRequest']);
 if(message.kind!=='SAMLRequest')fail('invalid_saml_message');
 const signed=await verifyMessage(ctx,app,message,root,Boolean(app.want_requests_signed));
 const destination=attr(root,'Destination');if((destination!==null||signed)&&destination!==ctx.origin+SSO_PATH)fail('wrong_destination');
 const protocolBinding=attr(root,'ProtocolBinding'),binding=protocolBinding===null?null:Object.entries(BINDINGS).find(([,u])=>u===protocolBinding)?.[0]??fail('unsupported_binding');
 const requested=attr(root,'AssertionConsumerServiceURL');let url=null;if(requested!==null){try{url=new URL(requested).href;}catch{fail('acs_not_allowed');}}
 const acs=defaultAcs(app,{url,index:attr(root,'AssertionConsumerServiceIndex'),binding})||fail('acs_not_allowed');
 await once(ctx,app.id,id);
 const format=attr(child(root,'NameIDPolicy',NS.samlp),'Format');
 const pending={app:app.id,version:app.version,request:id,acs,relayState:message.relayState,forceAuthn:attr(root,'ForceAuthn')==='true',isPassive:attr(root,'IsPassive')==='true',formatRefused:Boolean(format&&format!==FORMATS.unspecified&&format!==FORMATS[app.name_id_format]),startedAt:ctx.now()};
 // A cross-site POST carries no Lax session cookie: continue on a top-level GET.
 return message.binding==='post'?park(ctx,pending,false):answer(ctx,request,pending);
}

async function park(ctx,pending,login) {
 const browser=random(),transaction=await challenge(ctx,'saml-sso',null,await hash(browser),pending,REQUEST_LIFETIME);
 const resume=`${RESUME_PATH}?transaction=${encodeURIComponent(transaction)}`;
 return new Response(null,{status:303,headers:{location:login?`/signin?returnTo=${encodeURIComponent(resume)}`:resume,'set-cookie':cookie(ctx,loginCookie(ctx),browser,900),'cache-control':'no-store','referrer-policy':'no-referrer'}});
}
export async function resume(ctx,request) {
 const browser=cookies(request)[loginCookie(ctx)];
 const proof=await consumeChallenge(ctx,new URL(request.url).searchParams.get('transaction'),'saml-sso',browser?await hash(browser):null);
 return answer(ctx,request,proof.payload);
}

async function answer(ctx,request,pending) {
 const app=await activeApp(ctx,'id',pending.app);
 if(!app||app.version!==pending.version)return samlPage('This app changed','Its sign-in settings changed while you were signing in. Start again from the app.',409);
 const reply=element=>sendMessage(ctx,{kind:'SAMLResponse',element,relayState:pending.relayState,endpoint:pending.acs,digest:app.digest,sign:app.sign!=='assertion'});
 if(pending.formatRefused)return reply(statusResponse(ctx,{acs:pending.acs,inResponseTo:pending.request,code:'Requester',detail:'InvalidNameIDPolicy'}));
 const s=await session(ctx,request);
 if(!s||(pending.forceAuthn&&s.created_at<pending.startedAt)) {
  if(pending.isPassive)return reply(statusResponse(ctx,{acs:pending.acs,inResponseTo:pending.request,code:'Responder',detail:'NoPassive'}));
  return park(ctx,pending,true);
 }
 return issue(ctx,app,s,pending.acs,pending.request,pending.relayState,reply);
}

async function issue(ctx,app,s,acs,inResponseTo,relayState,reply) {
 const assigned=await assignment(ctx,app.id,s.person_id);
 if(!assigned){await audit(ctx,s.person_id,'saml_refused_unassigned',app.id);return samlPage('You are not assigned to this app',`Ask an administrator for access to ${app.name}.`,403);}
 const element=await signInResponse(ctx,{app,s,acs,inResponseTo,role:assigned.role});
 await audit(ctx,s.person_id,'saml_assertion_issued',app.id);
 return reply(element);
}

// IdP-initiated: only for an app that permits it, to its default consumer.
export async function launch(ctx,request,appId) {
 const s=await session(ctx,request);
 if(!s)return new Response(null,{status:303,headers:{location:`/signin?returnTo=${encodeURIComponent(`/saml/launch/${appId}`)}`,'cache-control':'no-store'}});
 const app=await activeApp(ctx,'id',appId);
 if(!app||!app.idp_initiated)return samlPage('This app cannot be opened from Auth','Open it from its own sign-in page.',404);
 const acs=defaultAcs(app);
 return issue(ctx,app,s,acs,null,app.relay_state,element=>sendMessage(ctx,{kind:'SAMLResponse',element,relayState:app.relay_state,endpoint:acs,digest:app.digest,sign:app.sign!=='assertion'}));
}
