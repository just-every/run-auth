import {createRequire} from 'node:module';
import {readFile,mkdtemp,rm,readdir,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {apply} from './link/schema.mjs';
const root=fileURLToPath(new URL('../../',import.meta.url));
const require=createRequire(await realpath(join(root,'node_modules/wrangler/package.json')));
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const {build}=require('esbuild');
export async function openRuntime() {
 const output=await build({entryPoints:[fileURLToPath(new URL('./worker.mjs',import.meta.url))],bundle:true,write:false,format:'esm',platform:'browser',target:'es2022',conditions:['workerd','browser'],external:['node:crypto']});
 const directory=await mkdtemp(join(tmpdir(),'auth-security-'));
 const mf=new Miniflare({...convertV4MiniflareOptions({modules:true,script:output.outputFiles[0].text,compatibilityDate:'2026-09-01',compatibilityFlags:['nodejs_compat'],d1Databases:{DB:'auth-tests'}}),resourcePersistencePath:join(directory,'state')});
 const db=await mf.getD1Database('DB');
 const base=await readFile(new URL('../../src/modules/operator-auth/accounts/schema/operator-auth.sql',import.meta.url),'utf8');
 const oidc=await readFile(new URL('../../migrations/core/0005_identity_providers.sql',import.meta.url),'utf8');
 const own=await readFile(new URL('../../migrations/core/0010_auth.sql',import.meta.url),'utf8');
 for(const sql of (base+'\n'+oidc+'\n'+own).replace(/^--.*$/gm,'').match(/CREATE TRIGGER[\s\S]*?END;|CREATE (?:UNIQUE )?(?:TABLE|INDEX)[\s\S]*?;/g))await db.prepare(sql).run();
 for(const name of ['0011_auth_upstream_proofs.sql','0012_auth_local_email.sql','0013_auth_token_algorithms.sql','0014_auth_move_in.sql','0015_auth_move_in_restage.sql','0016_auth_agents.sql','0017_auth_agent_key_owner_version.sql'])for(const sql of (await readFile(new URL('../../migrations/core/'+name,import.meta.url),'utf8')).replace(/^--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
 await apply(db,new URL('../../migrations/core/',import.meta.url),['0021_dependencies.sql','0022_dependency_approval.sql','0023_owner_claim.sql','0024_auth_links.sql','0025_auth_rer_trust.sql','0026_auth_link_replacements.sql','0027_auth_rer_withdrawals.sql','0028_auth_workforce_apps.sql','0029_auth_oidc_apps.sql','0030_auth_events.sql','0031_auth_directory.sql','0032_auth_profile.sql','0033_auth_mapping.sql','0034_auth_hooks.sql','0035_auth_admin_services.sql','0036_auth_admin_api.sql']);
 await db.exec('CREATE TABLE test_mail(id INTEGER PRIMARY KEY AUTOINCREMENT,message TEXT NOT NULL);');
 const api={db,now:1800000000000,origin:'https://auth.example.com',local:false,async call(path,{method='GET',data,cookie,headers={},form,action,...extra}={}) {
  const body=form?new URLSearchParams(form).toString():data===undefined?undefined:JSON.stringify(data);
  const response=await mf.dispatchFetch('http://localhost',{method:'POST',redirect:'manual',body:JSON.stringify({path,method,body,action,now:api.now,origin:api.origin,local:api.local,upstreamProviders:api.upstreamProviders,upstream:api.upstream,upstreams:api.upstreams,scimServer:api.scimServer,edges:api.edges,headers:{'cf-connecting-ip':'192.0.2.10',...(method==='POST'?{'origin':api.origin,'content-type':form?'application/x-www-form-urlencoded':'application/json'}:{}),...(cookie?{cookie}:{}),...headers},...extra})});
  // Buffer the HTTP boundary before another dispatch can close the original stream.
  const headersCopy=new Headers(response.headers);headersCopy.delete('set-cookie');for(const value of response.headers.getSetCookie())headersCopy.append('set-cookie',value);
  return new Response([204,304].includes(response.status)?null:await response.arrayBuffer(),{status:response.status,headers:headersCopy});
 },async person(id,email,role='member'){await db.prepare("INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES(?,?,?,?,'active',1,?)").bind(id,email,id,role,api.now).run();},async mails(){return (await db.prepare('SELECT message FROM test_mail ORDER BY id').all()).results.map(r=>JSON.parse(r.message));},async close(){await mf.dispose();await rm(directory,{recursive:true,force:true});}};
 return api;
}
export const cookieOf = response => response.headers.get('set-cookie')?.split(';')[0];
export async function emailSession(r,address,extra={}) {
 const requested=await r.call('/auth/identity/email/request',{method:'POST',data:{email:address,...extra}});
 const message=(await r.mails()).at(-1),token=new URL(message.text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 const response=await r.call('/auth/identity/email/confirm',{method:'POST',data:{token},cookie:cookieOf(requested)});
 if(response.status!==200)throw new Error(`email session ${response.status}: ${await response.text()}`);
 return cookieOf(response);
}
