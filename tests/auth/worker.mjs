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
function beforeBatch(db,change) {
 let applied=false;
 return new Proxy(db,{get(target,key){
  if(key==='batch')return async statements=>{if(!applied){applied=true;await db.prepare(change.sql).bind(...(change.args??[])).run();}return target.batch(statements);};
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
}
function expireAbuseProof(db,change) {
 const wrap=statement=>new Proxy(statement,{get(target,key){
  if(key==='bind')return (...args)=>wrap(target.bind(...args));
  if(key==='run')return async()=>{await db.prepare(change==='hardware'?`UPDATE auth_sessions SET amr='["email"]'`:'UPDATE auth_sessions SET local_email_verified_at=0').run();return target.run();};
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
 return new Proxy(db,{get(target,key){
  if(key==='prepare')return sql=>sql.startsWith('INSERT INTO auth_settings(key,value) SELECT')?wrap(target.prepare(sql)):target.prepare(sql);
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
}
// Mutate only the test-owned D1 edge after preflight and before the named write.
function onboardingRace(db,race) {
 let used=false;
 const wrap=statement=>new Proxy(statement,{get(target,key){
  if(key==='bind')return (...args)=>wrap(target.bind(...args));
  if(['run','first','all'].includes(key))return async(...args)=>{if(!used){used=true;await db.prepare(race.sql).run();}return target[key](...args);};
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
 return new Proxy(db,{get(target,key){
  if(key==='prepare')return sql=>sql.startsWith(race.prefix)?wrap(target.prepare(sql)):target.prepare(sql);
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
}
// A test-owned database edge withdraws authority after preflight, before commit.
function factorRace(db,sql) {
 let used=false;
 return new Proxy(db,{get(target,key){
  if(key==='batch')return async statements=>{if(!used){used=true;await target.prepare(sql).run();}return target.batch(statements);};
  const value=target[key];return typeof value==='function'?value.bind(target):value;
 }});
}
export default {async fetch(request,env,execution) {
 const envelope=await request.json(),background=[];
 const runtime=createAuthRuntime({trustedSource:envelope.sourceIdentity?()=>envelope.sourceIdentity:undefined,mailProvider:envelope.mailProvider,sendgridWebhookKey:envelope.sendgridWebhookKey,db:envelope.beforeBatchSql?beforeBatch(env.DB,envelope.beforeBatchSql):envelope.factorRace?factorRace(env.DB,envelope.factorRace):envelope.onboardingRace?onboardingRace(env.DB,envelope.onboardingRace):envelope.expireAbuseProof?expireAbuseProof(env.DB,envelope.expireAbuseProof):envelope.barrier?atBarrier(env.DB,envelope.barrier):env.DB,agentModelKey:envelope.agentModelEdge?'synthetic-auth-1':undefined,agentModelFetch:envelope.agentModelEdge?(_uri,init)=>fetch(envelope.agentModelEdge,init):undefined,notificationSlackWebhook:envelope.notificationSlackWebhook,notificationFetch:envelope.notificationEdge?(_uri,init)=>fetch(envelope.notificationEdge,init):undefined,dnsFetch:envelope.dnsEdge?(uri,init)=>fetch(envelope.dnsEdge+'?'+new URL(uri).searchParams,init):undefined,origin:envelope.origin||'https://auth.example.com',secret:'1a'.repeat(32),local:envelope.local||false,allowDevSession:envelope.allowDevSession===true?()=>true:undefined,now:()=>envelope.now,waitUntil:work=>{background.push(work);execution.waitUntil(work);},federationResolve:async()=>['93.184.216.34'],upstreamProviders:envelope.upstreamProviders,upstreamFetch:async uri=>{const u=new URL(uri),up=envelope.upstreams?.[u.origin]??envelope.upstream;return Response.json(u.pathname.endsWith('openid-configuration')?up.discovery:u.pathname.endsWith('/keys')?up.jwks:up.tokens);},
  // Company apps are the network edge: their public hosts are served by the test's own servers.
  connectorFetch:async(uri,init)=>{
   const url=new URL(uri);
   // Only the automation service's test-owned host gets synthetic DNS answers.
   if(envelope.edges?.['https://automation.example.com']&&url.origin==='https://cloudflare-dns.com'&&url.pathname==='/dns-query'&&url.searchParams.get('name')==='automation.example.com')return Response.json({Status:0,Answer:url.searchParams.get('type')==='A'?[{type:1,data:envelope.privateAutomationDns?'127.0.0.1':'93.184.216.34'}]:[]});
   const edges={...(envelope.scimServer?{'https://scim.example.com':envelope.scimServer}:{}),...envelope.edges},origin=Object.keys(edges).find(o=>String(uri).startsWith(o+'/'));const response=await fetch(origin?edges[origin]+String(uri).slice(origin.length):uri,init);return origin?new Response(response.body,{status:response.status,headers:response.headers}):response;},mail:async message=>{if(envelope.mailEdge){const response=await fetch(envelope.mailEdge,{method:'POST',body:JSON.stringify(message)});if(!response.ok)throw new Error('mail_edge_refused');if(envelope.mailProvider==='sendgrid')return response.json();}if(envelope.realOutbox)return createMailSender({provider:'development',mode:'development'},{outbox:createD1DevelopmentOutbox({db:env.DB,clock:()=>envelope.now})}).send({...message,deliveryId:crypto.randomUUID(),from:'auth@example.com',to:[message.to],headers:{}});if(envelope.mailDelay)await new Promise(done=>setTimeout(done,envelope.mailDelay));await env.DB.prepare('INSERT INTO test_mail(message) VALUES(?)').bind(JSON.stringify(message)).run();}});
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
