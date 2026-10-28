// A linked app made only of Base's application side (operator-auth with
// dependencies), as a seed such as Spool composes it.
import {createOperatorAuth,createAuthHandler} from '../../../src/modules/operator-auth/index.mjs';
import {createDependencies} from '../../../src/modules/dependencies/index.mjs';
const AUTH_ORIGIN='https://auth.example.com',ORIGIN='https://app.example.com';
const config={origin:ORIGIN,local:false,dependencies:true,OWNER_EMAIL:'owner@example.com',SESSION_SECRET:'2b'.repeat(32),SETUP_TOKEN:'app-setup-token-0123456789abcdef',MAIL_FROM:'app@example.com',branding:{productName:'App',accentColor:'#222222',signInPath:'/sign-in'}};
export default {
 async fetch(request,env) {
  // Miniflare's dispatch replaces Host with its loopback listener; a real edge keeps the addressed host.
  const headers=new Headers(request.headers);headers.set('host',new URL(request.url).host);request=new Request(request,{headers});
  const fetcher=(input,init)=>env.AUTH.fetch(new Request(input,init));
  const auth=createOperatorAuth({db:env.DB,config,clientIp:()=>'192.0.2.20',fetch:fetcher,mailSender:{send:async()=>({status:'accepted',id:'synthetic-auth-411'})}});
  const dependencies=createDependencies({db:env.DB,origin:ORIGIN,name:'App',provider:AUTH_ORIGIN,auth,fetch:fetcher});
  if(new URL(request.url).pathname==='/')return new Response('App home');
  return await dependencies.handle(request)??await createAuthHandler(auth)(request)??new Response(null,{status:404});
 },
};
