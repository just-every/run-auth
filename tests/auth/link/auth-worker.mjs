// Auth's runtime on a real clock. Apps are reached through the APP binding;
// mail lands in test_mail (the only faked edge besides that network hop).
import {createAuthRuntime,maintainAuth} from '../../../src/auth/index.mjs';
import {AUTH_ORIGIN,APP_ORIGIN} from './origins.mjs';
function runtime(env,background) {
 return createAuthRuntime({db:env.DB,origin:AUTH_ORIGIN,secret:'1a'.repeat(32),local:false,waitUntil:work=>background.push(work),
  linkFetch:(input,init)=>{const url=new URL(input instanceof Request?input.url:input);if(url.origin!==APP_ORIGIN)throw new TypeError('network unreachable');return env.APP.fetch(new Request(input,init));},
  mail:async message=>{await env.DB.prepare('INSERT INTO test_mail(message) VALUES(?)').bind(JSON.stringify(message)).run();}});
}
export default {
 async fetch(request,env) {
  // Tests observe finished background work (mail, logout deliveries) with each response.
  const background=[],url=new URL(request.url);
  const response=url.pathname==='/__test/maintain'?(await maintainAuth(runtime(env,background).context),new Response(null,{status:204})):await runtime(env,background).fetch(request)??new Response(null,{status:404});
  await Promise.allSettled(background);
  return response;
 },
};
