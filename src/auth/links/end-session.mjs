// RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0). A valid
// id_token_hint for this browser's session ends it at once; anything else asks
// the person to confirm with a same-origin POST. Apps that received tokens in
// the ended session get a back-channel logout naming its sid.
import {compactVerify,createLocalJWKSet} from 'jose';
import {one,all,run,session,cookie,cookieName,audit} from '../core.mjs';
import {jwks} from '../keys.mjs';
import {queueLogouts} from './logout.mjs';
import {framedPage,FRAME_SOURCES} from '../page-frame.mjs';
import {genericClient} from '../oidc-apps/clients.mjs';
import {endGenericSessions} from '../oidc-apps/session.mjs';

export const END_SESSION='/oidc/logout';
const headers={'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`};
const escape=v=>String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
const page=(title,body,status=200,extra={})=>new Response(framedPage(title,`<h1>${title}</h1>${body}`),{status,headers:{...headers,...extra}});

// Signature and issuer only: an expired hint still names the session it came from.
async function hint(ctx,token) {
 try {
  const {payload}=await compactVerify(token,createLocalJWKSet(await jwks(ctx)),{algorithms:['ES256','RS256']});
  const claims=JSON.parse(new TextDecoder().decode(payload));
  return claims.iss===ctx.origin&&typeof claims.aud==='string'?claims:null;
 } catch {return null;}
}

async function finish(ctx,s) {
 await run(ctx,'UPDATE auth_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL',ctx.now(),s.id);
 const clients=await all(ctx,'SELECT c.id FROM auth_session_clients sc JOIN auth_clients c ON c.id=sc.client_id WHERE sc.session_id=? AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL',s.id);
 await queueLogouts(ctx,s.person_id,{sid:s.id,clients});
 await audit(ctx,s.person_id,'signed_out_from_app',null);
 // General OIDC apps: back-channel tokens now, front-channel frames on the page.
 return endGenericSessions(ctx,s);
}
// Each front-channel logout URI loads in a frame; then the browser goes on.
const framesPage=(frames,target,clear)=>new Response(framedPage('You are signed out',`<h1>You are signed out</h1><p>You have signed out of Auth on this browser.</p>${frames.map(src=>`<iframe src="${escape(src)}" title="Signing out of an app" width="0" height="0" hidden></iframe>`).join('')}${target?`<p><a href="${escape(target.href)}">Continue to the app</a></p>`:''}`).replace('<head>',target?`<head><meta http-equiv="refresh" content="2;url=${escape(target.href)}">`:'<head>'),{status:200,headers:{...headers,'content-security-policy':`${headers['content-security-policy']}; frame-src ${[...new Set(frames.map(src=>new URL(src).origin))].join(' ')}`,...clear}});

export async function endSession(ctx,request) {
 const url=new URL(request.url);
 // An app may POST its request too; only Auth's own confirmation form counts as consent.
 const posted=request.method==='POST'?Object.fromEntries(new URLSearchParams((await request.text()).slice(0,16384))):null;
 const params=posted??Object.fromEntries(url.searchParams),confirmed=posted?.confirm==='yes'&&request.headers.get('origin')===ctx.origin;
 const claims=params.id_token_hint?await hint(ctx,params.id_token_hint):null;
 if(params.id_token_hint&&!claims)return page('Sign-out could not continue','<p>The app sent a sign-in token Auth did not issue.</p>',400);
 const clientId=claims?.aud??params.client_id??null;
 if(params.client_id&&claims&&params.client_id!==claims.aud)return page('Sign-out could not continue','<p>The app and its token do not match.</p>',400);
 const client=clientId?await one(ctx,'SELECT id,post_logout_redirect_uris FROM auth_clients WHERE id=? AND disabled_at IS NULL',clientId):null;
 const generic=!client&&clientId?await genericClient(ctx,clientId):null,allowed=client?JSON.parse(client.post_logout_redirect_uris):generic?.postLogout??[];
 let target=null;
 if(params.post_logout_redirect_uri) {
  if(!allowed.includes(params.post_logout_redirect_uri))return page('Sign-out could not continue','<p>Check the app and its sign-out address.</p>',400);
  target=new URL(params.post_logout_redirect_uri);if(params.state)target.searchParams.set('state',params.state);
 }
 const s=await session(ctx,request);
 const matches=s&&claims&&claims.sid===s.id;
 if(s&&!matches&&!confirmed) {
  const fields=Object.entries(params).filter(([k])=>['id_token_hint','post_logout_redirect_uri','state','client_id'].includes(k)).map(([k,v])=>`<input type="hidden" name="${k}" value="${escape(v)}">`).join('');
  return page('Sign out of Auth?',`<p>Signed in as ${escape(s.email)}.</p><form method="post" action="${END_SESSION}">${fields}<input type="hidden" name="confirm" value="yes"><button type="submit">Sign out</button></form>`);
 }
 const clear={'set-cookie':cookie(ctx,cookieName(ctx),'',0)};
 const frames=s?await finish(ctx,s):[];
 if(frames.length)return framesPage(frames,target,clear);
 if(target)return new Response(null,{status:302,headers:{location:target.href,'cache-control':'no-store','referrer-policy':'no-referrer',...clear}});
 return page('You are signed out','<p>You have signed out of Auth on this browser.</p>',200,clear);
}
