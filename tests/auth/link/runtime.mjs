// Auth and one Base app in one Miniflare, each with its own D1 database,
// talking only HTTP through service bindings.
import {createRequire} from 'node:module';
import {mkdtemp,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {apply} from './schema.mjs';
import {AUTH_ORIGIN,APP_ORIGIN} from './origins.mjs';
const root=fileURLToPath(new URL('../../../',import.meta.url));
const require=createRequire(await realpath(join(root,'node_modules/wrangler/package.json')));
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const {build}=require('esbuild');
const src=new URL('../../../',import.meta.url);
const AUTH_SCHEMA=['src/modules/operator-auth/accounts/schema/operator-auth.sql','migrations/core/0005_identity_providers.sql','migrations/core/0010_auth.sql','migrations/core/0011_auth_upstream_proofs.sql','migrations/core/0012_auth_local_email.sql','migrations/core/0013_auth_token_algorithms.sql','migrations/core/0014_auth_move_in.sql','migrations/core/0015_auth_move_in_restage.sql','migrations/core/0016_auth_agents.sql','migrations/core/0017_auth_agent_key_owner_version.sql','migrations/core/0021_dependencies.sql','migrations/core/0022_dependency_approval.sql','migrations/core/0023_owner_claim.sql','migrations/core/0024_auth_links.sql','migrations/core/0025_auth_rer_trust.sql','migrations/core/0026_auth_link_replacements.sql','migrations/core/0027_auth_rer_withdrawals.sql','migrations/core/0028_auth_workforce_apps.sql','migrations/core/0029_auth_oidc_apps.sql','migrations/core/0030_auth_events.sql'];
const APP_SCHEMA=['src/modules/operator-auth/accounts/schema/operator-auth.sql','src/modules/operator-auth/identity/oidc/schema/oidc.sql','src/modules/dependencies/schema/dependencies.sql','src/modules/dependencies/schema/approval-attempt.sql','src/modules/owner-claim/schema/owner-claim.sql','src/modules/owner-claim/schema/idp.sql'];
const bundle=async file=>(await build({entryPoints:[fileURLToPath(new URL(file,import.meta.url))],bundle:true,write:false,format:'esm',platform:'browser',target:'es2022',conditions:['workerd','browser'],external:['node:crypto']})).outputFiles[0].text;

// scripted: optional handler for every other app origin (scripted-app.mjs).
export async function openLink({scripted}={}) {
 const directory=await mkdtemp(join(tmpdir(),'auth-link-'));
 const worker=(name,script,bindings,origin)=>({name,routes:[new URL(origin).host+'/*'],modules:true,script,compatibilityDate:'2026-09-01',compatibilityFlags:['nodejs_compat'],d1Databases:{DB:name+'-db'},serviceBindings:bindings});
 const relay={name:'scripted',modules:true,script:'export default {fetch(request,env){return env.NODE.fetch(request);}}',compatibilityDate:'2026-09-01',serviceBindings:{NODE:async request=>{try{return await scripted.handle(request);}catch{return new Response(null,{status:599});}}}};
 const mf=new Miniflare({...convertV4MiniflareOptions({workers:[worker('auth',await bundle('./auth-worker.mjs'),{APP:'app',...(scripted?{SCRIPTED:'scripted'}:{})},AUTH_ORIGIN),worker('app',await bundle('./app-worker.mjs'),{AUTH:'auth'},APP_ORIGIN),...(scripted?[relay]:[])]}),resourcePersistencePath:join(directory,'state')});
 const [authDb,appDb]=[await mf.getD1Database('DB','auth'),await mf.getD1Database('DB','app')];
 await apply(authDb,src,AUTH_SCHEMA);await authDb.exec('CREATE TABLE test_mail(id INTEGER PRIMARY KEY AUTOINCREMENT,message TEXT NOT NULL);');
 await apply(appDb,src,APP_SCHEMA);
 // One browser: cookies per origin, following redirects across both origins.
 const jar={[AUTH_ORIGIN]:new Map(),[APP_ORIGIN]:new Map()};
 async function send(url,{method='GET',json,form,headers={},cookies=true}={}) {
  const target=new URL(url);
  const cookie=cookies?[...jar[target.origin]].map(([k,v])=>`${k}=${v}`).join('; '):'';
  const body=json!==undefined?JSON.stringify(json):form?new URLSearchParams(form).toString():undefined;
  const response=await mf.dispatchFetch(target.href,{method,redirect:'manual',body,headers:{...(method==='POST'?{origin:target.origin,'content-type':json!==undefined?'application/json':'application/x-www-form-urlencoded'}:{}),...(cookie?{cookie}:{}),host:target.host,'cf-connecting-ip':'192.0.2.10',...headers}});
  for(const value of response.headers.getSetCookie()){const [pair,...attrs]=value.split(';'),[k,...v]=pair.split('=');if(attrs.some(a=>/max-age=0/i.test(a)))jar[target.origin].delete(k.trim());else jar[target.origin].set(k.trim(),v.join('='));}
  const copy=new Response([204,304].includes(response.status)?null:await response.arrayBuffer(),{status:response.status,headers:response.headers});
  return copy;
 }
 async function follow(url,options) {
  let response=await send(url,options),hops=0;
  while([302,303].includes(response.status)&&hops++<10){url=new URL(response.headers.get('location'),url).href;response=await send(url);}
  return response;
 }
 // The envelope-free shape the passkey and email helpers expect.
 const r={origin:AUTH_ORIGIN,db:authDb,appDb,jar,send,follow,
  async call(path,{method='GET',data,cookie,form,headers={}}={}) {
   const response=await mf.dispatchFetch(AUTH_ORIGIN+path,{method,redirect:'manual',body:form?new URLSearchParams(form).toString():data===undefined?undefined:JSON.stringify(data),headers:{host:new URL(AUTH_ORIGIN).host,'cf-connecting-ip':'192.0.2.10',...(method==='POST'?{origin:AUTH_ORIGIN,'content-type':form?'application/x-www-form-urlencoded':'application/json'}:{}),...(cookie?{cookie}:{}),...headers}});
   const copy=new Headers(response.headers);copy.delete('set-cookie');for(const v of response.headers.getSetCookie())copy.append('set-cookie',v);
   return new Response([204,304].includes(response.status)?null:await response.arrayBuffer(),{status:response.status,headers:copy});
  },
  async person(id,email,role='member'){await authDb.prepare("INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES(?,?,?,?,'active',1,?)").bind(id,email,id,role,Date.now()).run();},
  async mails(){return (await authDb.prepare('SELECT message FROM test_mail ORDER BY id').all()).results.map(row=>JSON.parse(row.message));},
  async close(){await mf.dispose();await rm(directory,{recursive:true,force:true});},
 };
 Object.defineProperty(r,'now',{get:()=>Date.now()});
 return r;
}
