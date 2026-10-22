import {createMailSender} from '../../src/modules/mail/index.mjs';
import {createD1DevelopmentOutbox} from '../../src/modules/mail/src/development/index.mjs';
import {createAuthRuntime,stageSigningKey,retireSigningKey,installRecoveryToken,maintainAuth} from '../../src/auth/index.mjs';
import {signedToken} from './signed-token.mjs';
// Requests sent with the same barrier wait at their first D1 batch until all
// have arrived, so each has passed every check before any one commits.
const barriers=new Map();
function atBarrier(db,{name,size}) {
 let passed=false;
 const arrive=()=>{const b=barriers.get(name)??{count:0,release:null,ready:null};if(!b.ready)b.ready=new Promise(done=>{b.release=done;});barriers.set(name,b);if(++b.count>=size)b.release();return b.ready;};
 return new Proxy(db,{get(target,prop){
  if(prop==='batch')return async statements=>{if(!passed){passed=true;await arrive();}return target.batch(statements);};
  const value=target[prop];return typeof value==='function'?value.bind(target):value;
 }});
}
export default {async fetch(request,env,execution) {
 const envelope=await request.json(),background=[];
 const runtime=createAuthRuntime({db:envelope.barrier?atBarrier(env.DB,envelope.barrier):env.DB,origin:envelope.origin||'https://auth.example.com',secret:'1a'.repeat(32),local:envelope.local||false,allowDevSession:envelope.allowDevSession===true?()=>true:undefined,now:()=>envelope.now,waitUntil:work=>{background.push(work);execution.waitUntil(work);},upstreamProviders:envelope.upstreamProviders,upstreamFetch:async uri=>{const u=new URL(uri),up=envelope.upstreams?.[u.origin]??envelope.upstream;return Response.json(u.pathname.endsWith('openid-configuration')?up.discovery:u.pathname.endsWith('/keys')?up.jwks:up.tokens);},
  // Company apps are the network edge: their public hosts are served by the test's own servers.
  connectorFetch:(uri,init)=>{const edges={...(envelope.scimServer?{'https://scim.example.com':envelope.scimServer}:{}),...envelope.edges},origin=Object.keys(edges).find(o=>String(uri).startsWith(o+'/'));return fetch(origin?edges[origin]+String(uri).slice(origin.length):uri,init);},mail:async message=>{if(envelope.mailEdge){const response=await fetch(envelope.mailEdge,{method:'POST',body:JSON.stringify(message)});if(!response.ok)throw new Error('mail_edge_refused');}if(envelope.realOutbox)return createMailSender({provider:'development',mode:'development'},{outbox:createD1DevelopmentOutbox({db:env.DB,clock:()=>envelope.now})}).send({...message,deliveryId:crypto.randomUUID(),from:'auth@example.com',to:[message.to],headers:{}});if(envelope.mailDelay)await new Promise(done=>setTimeout(done,envelope.mailDelay));await env.DB.prepare('INSERT INTO test_mail(message) VALUES(?)').bind(JSON.stringify(message)).run();}});
 if(envelope.action==='stage')return Response.json(await stageSigningKey(runtime.context));
 // The scheduled handler's work, as the Worker's cron runs it.
 if(envelope.action==='maintain'){await maintainAuth(runtime.context);await Promise.allSettled(background);return Response.json({ok:true});}
 if(envelope.action==='retire'){await retireSigningKey(runtime.context,envelope.kid);return Response.json({ok:true});}
 if(envelope.action==='recovery-token'){await installRecoveryToken(env.DB,envelope.token,envelope.now);return Response.json({ok:true});}
 if(envelope.action==='signed-token')return Response.json({token:await signedToken(runtime.context,envelope.claims,envelope.options,envelope.tokenIssuer)});
 const response=await runtime.fetch(new Request(new URL(envelope.path,runtime.context.origin),{method:envelope.method,headers:envelope.headers,body:envelope.body})) || new Response(null,{status:404});
 // Tests observe finished deliveries unless one asks to time the response alone.
 if(!envelope.detached)await Promise.allSettled(background);
 return response;
}};
