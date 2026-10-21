import {scopedCookieName,random,hash,cookies,cookie,challenge,consumeChallenge,one,fail} from './core.mjs';

const loginCookie=ctx=>scopedCookieName(ctx,ctx.local?'auth_oidc_login':'__Host-auth_oidc_login');

// The original request stays server-side. A return URL alone cannot waive
// prompt=login or max_age=0, and email/passkey binding cookies remain independent.
export async function beginAuthorizationLogin(ctx,request,previousSession,reauthenticate=false) {
 const browser=random(),url=new URL(request.url);
 const transaction=await challenge(ctx,'authorize-login',null,await hash(browser),{
  path:url.pathname+url.search,previousSessionId:previousSession?.id||null,startedAt:ctx.now(),reauthenticate,
 },900000);
 const returnTo=`/oidc/authorize/resume?transaction=${encodeURIComponent(transaction)}`;
 return new Response(null,{status:303,headers:{
  location:`/signin?returnTo=${encodeURIComponent(returnTo)}`,
  'set-cookie':cookie(ctx,loginCookie(ctx),browser,900),
  'cache-control':'no-store','referrer-policy':'no-referrer',
 }});
}

// Upstream SSO alone need not involve active user authentication. Its admission
// completes a local email proof for a pending forced-reauthentication request.
export async function pendingAuthorizationLogin(ctx,request,returnTo) {
 if(typeof returnTo!=='string')return null;
 const url=new URL(returnTo,ctx.origin),browser=cookies(request)[loginCookie(ctx)],transaction=url.searchParams.get('transaction');
 if(url.origin!==ctx.origin||url.pathname!=='/oidc/authorize/resume'||!browser||!transaction)return null;
 const row=await one(ctx,'SELECT payload FROM auth_challenges WHERE id=? AND purpose=? AND binding_hash=? AND expires_at>?',await hash(transaction),'authorize-login',await hash(browser),ctx.now());
 return row?JSON.parse(row.payload):null;
}

export async function authorizationLogin(ctx,request) {
 const browser=cookies(request)[loginCookie(ctx)];
 const proof=await consumeChallenge(ctx,new URL(request.url).searchParams.get('transaction'),'authorize-login',browser?await hash(browser):null);
 const url=new URL(proof.payload.path,ctx.origin);
 if(url.origin!==ctx.origin||url.pathname!=='/oidc/authorize')fail('invalid_challenge');
 return {request:new Request(url,{headers:request.headers}),proof:proof.payload};
}

export const completedAuthorizationLogin=ctx=>cookie(ctx,loginCookie(ctx),'',0);
