// SAML single logout. Auth ends its own session first, then visits each other
// app the session signed in to SAML (front channel, one at a time), and finally
// answers the app that asked, if one did. Logout messages must be signed.
import {one,all,run,random,session,cookie,cookieName,audit,fail} from '../core.mjs';
import {child,attr,textOf,el,NS} from './xml.mjs';
import {sendMessage,samlPage} from './bindings.mjs';
import {inbound,verifyMessage,once,activeApp} from './sso.mjs';
import {idpEntity,iso,messageId,STATUS} from './assertion.mjs';
import {queueLogouts} from '../links/logout.mjs';

export const SLO_PATH='/saml/slo',LOGOUT_PATH='/saml/logout';
const LIFETIME=900000;

async function endAuthSession(ctx,sessionId) {
 const s=await one(ctx,'UPDATE auth_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL RETURNING id,person_id',ctx.now(),sessionId);
 if(!s)return;
 const clients=await all(ctx,'SELECT c.id FROM auth_session_clients sc JOIN auth_clients c ON c.id=sc.client_id WHERE sc.session_id=? AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL',s.id);
 await queueLogouts(ctx,s.person_id,{sid:s.id,clients});
 await audit(ctx,s.person_id,'saml_signed_out',null);
}

async function start(ctx,sessionId,origin) {
 await endAuthSession(ctx,sessionId);
 const others=await all(ctx,"SELECT ss.app_id FROM auth_saml_sessions ss JOIN auth_apps a ON a.id=ss.app_id WHERE ss.session_id=? AND ss.ended_at IS NULL AND a.disabled_at IS NULL AND a.slo IS NOT NULL AND ss.app_id!=? ORDER BY ss.created_at,ss.rowid",sessionId,origin?.app??'');
 await run(ctx,'UPDATE auth_saml_sessions SET ended_at=? WHERE session_id=? AND app_id=? AND ended_at IS NULL',ctx.now(),sessionId,origin?.app??'');
 const id=random();
 await run(ctx,'INSERT INTO auth_saml_logouts(id,session_id,pending,origin_app,origin_request,origin_relay,expires_at) VALUES(?,?,?,?,?,?,?)',id,sessionId,JSON.stringify(others.map(o=>o.app_id)),origin?.app??null,origin?.request??null,origin?.relay??null,ctx.now()+LIFETIME);
 return advance(ctx,id);
}

const clear=ctx=>({'set-cookie':cookie(ctx,cookieName(ctx),'',0)});
async function advance(ctx,id) {
 const row=await one(ctx,'SELECT * FROM auth_saml_logouts WHERE id=? AND expires_at>?',id,ctx.now());
 if(!row)return samlPage('You are signed out','You have signed out of Auth on this browser.',200,clear(ctx));
 const pending=JSON.parse(row.pending);
 while(pending.length) {
  const appId=pending.shift(),app=await activeApp(ctx,'id',appId);
  const held=await one(ctx,'UPDATE auth_saml_sessions SET ended_at=? WHERE session_id=? AND app_id=? AND ended_at IS NULL RETURNING name_id,name_id_format,session_index',ctx.now(),row.session_id,appId);
  if(!app?.slo||!held)continue;
  const request=messageId();
  await run(ctx,'UPDATE auth_saml_logouts SET pending=?,awaiting_app=?,awaiting_request=? WHERE id=?',JSON.stringify(pending),appId,request,id);
  const element=el('samlp:LogoutRequest',{Destination:app.slo.url,ID:request,IssueInstant:iso(ctx.now()),NotOnOrAfter:iso(ctx.now()+300000),Version:'2.0'},[el('saml:Issuer',{},[idpEntity(ctx)]),el('saml:NameID',{Format:held.name_id_format,SPNameQualifier:app.name_id_format==='persistent'?app.entity_id:undefined},[held.name_id]),el('samlp:SessionIndex',{},[held.session_index])]);
  return sendMessage(ctx,{kind:'SAMLRequest',element,endpoint:app.slo,digest:app.digest,sign:true,headers:clear(ctx)});
 }
 await run(ctx,'DELETE FROM auth_saml_logouts WHERE id=?',id);
 const origin=row.origin_app?await activeApp(ctx,'id',row.origin_app):null;
 if(!origin?.slo)return samlPage('You are signed out','You have signed out of Auth and of your apps on this browser.',200,clear(ctx));
 const endpoint={url:origin.slo.responseUrl||origin.slo.url,binding:origin.slo.binding};
 const element=el('samlp:LogoutResponse',{Destination:endpoint.url,ID:messageId(),InResponseTo:row.origin_request,IssueInstant:iso(ctx.now()),Version:'2.0'},[el('saml:Issuer',{},[idpEntity(ctx)]),el('samlp:Status',{},[el('samlp:StatusCode',{Value:STATUS+'Success'})])]);
 return sendMessage(ctx,{kind:'SAMLResponse',element,relayState:row.origin_relay,endpoint,digest:origin.digest,sign:true,headers:clear(ctx)});
}

// /saml/slo: an app's LogoutRequest, or its LogoutResponse to Auth's request.
export async function slo(ctx,request) {
 const {message,root,app,id}=await inbound(ctx,request,['LogoutRequest','LogoutResponse']);
 await verifyMessage(ctx,app,message,root,true);
 const destination=attr(root,'Destination');if(destination!==null&&destination!==ctx.origin+SLO_PATH)fail('wrong_destination');
 if(root.local==='LogoutResponse') {
  const row=await one(ctx,'SELECT id FROM auth_saml_logouts WHERE awaiting_app=? AND awaiting_request=? AND expires_at>?',app.id,attr(root,'InResponseTo')||'',ctx.now())||fail('saml_logout_not_awaited');
  const status=attr(child(child(root,'Status',NS.samlp),'StatusCode',NS.samlp),'Value');
  await audit(ctx,null,status===STATUS+'Success'?'saml_app_signed_out':'saml_app_signout_failed',app.id);
  await run(ctx,'UPDATE auth_saml_logouts SET awaiting_app=NULL,awaiting_request=NULL WHERE id=?',row.id);
  return advance(ctx,row.id);
 }
 if(message.kind!=='SAMLRequest')fail('invalid_saml_message');
 const notAfter=attr(root,'NotOnOrAfter');if(notAfter&&Date.parse(notAfter)<=ctx.now()-300000)fail('stale_saml_message');
 await once(ctx,app.id,id);
 const nameId=textOf(child(root,'NameID',NS.saml)).trim(),index=textOf(child(root,'SessionIndex',NS.samlp)).trim();
 const held=index?await one(ctx,'SELECT session_id FROM auth_saml_sessions WHERE app_id=? AND session_index=? AND name_id=? AND ended_at IS NULL',app.id,index,nameId)
  :await (async()=>{const s=await session(ctx,request);return s&&one(ctx,'SELECT session_id FROM auth_saml_sessions WHERE app_id=? AND session_id=? AND name_id=? AND ended_at IS NULL',app.id,s.id,nameId);})();
 if(!held) {
  // Nothing of that session is still signed in here; answer as done.
  const endpoint={url:app.slo?.responseUrl||app.slo?.url,binding:app.slo?.binding};
  if(!endpoint.url)return samlPage('You are signed out','You have signed out of Auth on this browser.',200,clear(ctx));
  const element=el('samlp:LogoutResponse',{Destination:endpoint.url,ID:messageId(),InResponseTo:id,IssueInstant:iso(ctx.now()),Version:'2.0'},[el('saml:Issuer',{},[idpEntity(ctx)]),el('samlp:Status',{},[el('samlp:StatusCode',{Value:STATUS+'Success'})])]);
  return sendMessage(ctx,{kind:'SAMLResponse',element,relayState:message.relayState,endpoint,digest:app.digest,sign:true,headers:clear(ctx)});
 }
 return start(ctx,held.session_id,{app:app.id,request:id,relay:message.relayState});
}

// /saml/logout: a person signs out of Auth and every SAML app from Auth itself.
export async function logout(ctx,request) {
 const s=await session(ctx,request);
 if(!s)return samlPage('You are signed out','You have signed out of Auth on this browser.',200);
 if(request.method==='GET')return samlPage('Sign out of Auth and your apps?',`Signed in as ${s.email}.`,200,{},`<form method="post" action="${LOGOUT_PATH}"><button type="submit">Sign out</button></form>`);
 if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
 return start(ctx,s.id,null);
}
