import {one} from '../core.mjs';
import {pendingAuthorizationLogin} from '../authorization-login.mjs';

// Resolve only the original browser-bound request. User-supplied app names and
// arbitrary return paths never become trusted event context.
export async function notificationApp(ctx,returnTo,request) {
 if(!request)return 'Auth';
 const pending=await pendingAuthorizationLogin(ctx,request,returnTo);
 if(!pending)return 'Auth';
 let url;try{url=new URL(pending.path,ctx.origin);}catch{return 'Auth';}
 if(url.origin!==ctx.origin||url.pathname!=='/oidc/authorize')return 'Auth';
 const clientId=url.searchParams.get('client_id');if(!clientId)return 'Auth';
 const linked=await one(ctx,'SELECT name FROM auth_clients WHERE id=? AND disabled_at IS NULL',clientId);
 if(linked)return linked.name;
 const app=await one(ctx,'SELECT a.name FROM auth_oidc_clients c JOIN auth_apps a ON a.id=c.app_id WHERE c.client_id=? AND a.disabled_at IS NULL',clientId);
 return app?.name??'Auth';
}
