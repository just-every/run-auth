import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createServer} from 'node:net';
import {randomBytes} from 'node:crypto';
import {mkdtemp, rm, writeFile, symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {productionPlan,projectMiniflare} from '@runeditrun/rer/internal/onboarding/production-options.mjs';

// The emitted Worker under the same Miniflare plan rer preview serves, in this process.
async function productionRuntime(directory,origin,port,host,outboundService) {
 const {Miniflare,convertV4MiniflareOptions}=await projectMiniflare(directory);
 const plan=await productionPlan(directory,origin,port,host);
 if(outboundService){if(plan.workers)for(const worker of plan.workers)worker.outboundService=outboundService;else plan.outboundService=outboundService;}
 const runtime=new Miniflare({...convertV4MiniflareOptions(plan),resourcePersistencePath:join(directory,'.wrangler/state/v3')});
 return {ready:runtime.ready,dispose:()=>runtime.dispose()};
}

const root=fileURLToPath(new URL('../../',import.meta.url));
export async function openApp({upstreamProviders,outboundService,agentModelKey,mail}={}) {
 const socket=createServer();await new Promise(resolve=>socket.listen(0,'127.0.0.1',resolve));
 const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));
 const origin=`http://localhost:${port}`,directory=await mkdtemp(join(tmpdir(),'auth-integration-'));
 const secret=()=>randomBytes(32).toString('base64url');
 const vars={AUTH_LOCAL:'true',AUTH_ORIGIN:origin,OWNER_EMAIL:'owner@example.com',AUTH_ENCRYPTION_KEY:secret(),SESSION_SECRET:secret(),SETUP_TOKEN:secret(),MAIL_PROVIDER:'development',MAIL_FROM:'auth@localhost.test',RER_DEV_KEY:secret()};
 if(mail)Object.assign(vars,{MAIL_PROVIDER:mail.provider,MAIL_API_KEY:mail.key,MAIL_FROM:'auth@example.com',MAIL_SENDGRID_WEBHOOK_KEY:mail.verificationKey});
 if(agentModelKey)vars.AUTH_AGENT_MODEL_KEY=agentModelKey;
 if(upstreamProviders)vars.AUTH_UPSTREAM_PROVIDERS=JSON.stringify(upstreamProviders);
 await writeFile(join(directory,'.dev.vars'),Object.entries(vars).map(([k,v])=>`${k}=${v}`).join('\n')+'\n',{mode:0o600});
 await symlink(join(root,'node_modules'),join(directory,'node_modules'),'dir');
 await symlink(join(root,'dist'),join(directory,'dist'),'dir');
 let runtime;
 const cleanup=async()=>{
  try {await runtime?.dispose();} finally {
   try {await rm(directory,{recursive:true,force:true});} finally {
    // Wrangler keeps scratch (.wrangler/tmp) beside the emitted config; the artifact producer refuses that folder, so leave the build output as rer build wrote it.
    await rm(join(root,'dist/server/.wrangler'),{recursive:true,force:true});
   }
  }
 };
 try {
  execFileSync(process.execPath,[join(root,'node_modules/wrangler/bin/wrangler.js'),'d1','migrations','apply','DB','--local','--persist-to',join(directory,'.wrangler/state'),'--config',join(root,'dist/server/wrangler.json')],{stdio:'ignore',env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',X_LOCAL_EXPLORER:'false'}});
  // Use the same emitted-Worker runtime as rer setup/preview. Wrangler dev's
  // own trigger endpoint is deliberately not a public application listener.
  runtime=await productionRuntime(directory,origin,port,'127.0.0.1',outboundService);await runtime.ready;
 }catch(error){await cleanup();throw error;}
 const app={origin,vars,directory,async pause(){await runtime?.dispose();runtime=null;},async resume(){runtime=await productionRuntime(directory,origin,port,'127.0.0.1',outboundService);await runtime.ready;},close:cleanup,
  get:(path,headers={})=>fetch(origin+path,{headers,redirect:'manual'}),
  post:(path,data={},cookie)=>fetch(origin+path,{method:'POST',redirect:'manual',headers:{origin,'content-type':'application/json',...(cookie?{cookie}:{})},body:JSON.stringify(data)}),
  async claim(){const response=await app.post('/auth/bootstrap',{token:vars.SETUP_TOKEN,displayName:'Owner'});assert.equal(response.status,303);return cookieOf(response);},
  async link(prefix='',purpose='email'){const listing=await(await app.get(prefix+'/__dev/outbox',{'x-rer-dev-key':vars.RER_DEV_KEY})).text();const path=listing.match(/href="((?:\/org\/[a-f0-9]{32})?\/__dev\/outbox\?message=[^"]+)"/)?.[1];assert.ok(path,'real outbox has a message');const detail=await(await app.get((path.startsWith('/org/')?'':prefix)+path.replaceAll('&amp;','&'),{'x-rer-dev-key':vars.RER_DEV_KEY})).text();const value=detail.match(purpose==='onboarding'?/href="([^"]*\/auth\/identity\/onboarding\?[^"]+)"/:/href="([^"]*\/auth\/identity\/email\/confirm\?token=[^"]+)"/)?.[1];assert.ok(value,'outbox has Auth confirmation link');return new URL(value.replaceAll('&amp;','&'),origin);},
  async signIn(returnTo='/app/account',address=vars.OWNER_EMAIL){const response=await app.post('/auth/identity/email/request',{email:address,returnTo});assert.equal(response.status,202);const link=await app.link();const confirmed=await app.post('/auth/identity/email/confirm',{token:link.searchParams.get('token')},cookieOf(response));assert.equal(confirmed.status,200);return cookieOf(confirmed);}
 };
 return app;
}
export const cookieOf=response=>response.headers.getSetCookie().map(line=>line.split(';')[0]).join('; ');
