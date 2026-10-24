import { fileURLToPath as __rerTestEntryPath } from 'node:url';
const __rerTestEntry = __rerTestEntryPath(import.meta.resolve('@runeditrun/rer/internal/bin/rer.mjs'));
const __rerTestEntryArgs = args => ['dev', 'preview'].includes(args[1]) && !args.some(arg => ['--foreground', '--detach', '--stop', '--help'].includes(arg)) ? [...args, '--foreground'] : args;
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {cp,mkdtemp,readFile,rm,symlink,writeFile,access,mkdir,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createServer} from 'node:net';
import {chromium,expect} from '@playwright/test';

const root=fileURLToPath(new URL('../../',import.meta.url));
test('fresh rer setup chooses localhost; rer dev bridges only the gated real owner and refuses private paths',async t=>{
 const directory=await mkdtemp(join(tmpdir(),'auth-rer-'));const processes=[];let browser;
 t.after(async()=>{await browser?.close();for(const child of processes){if(child.exitCode===null && child.signalCode===null){child.kill('SIGTERM');await new Promise(resolve=>child.once('exit',resolve));}}await rm(directory,{recursive:true,force:true});});
 const excluded=new Set(['node_modules','.git','.rer','.seed','.wrangler','.cache','dist','test-results','.dev.vars','.dev.vars.previous']);
 await cp(root,directory,{recursive:true,filter:path=>!excluded.has(relative(root,path).split('/')[0])});
 await symlink(join(root,'node_modules'),join(directory,'node_modules'),'dir');
 const socket=createServer();await new Promise(resolve=>socket.listen(0,'127.0.0.1',resolve));const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));
 const env={...process.env,CI:'true',RER_SERVER_JOURNEY:'1',WRANGLER_SEND_METRICS:'false',X_LOCAL_EXPLORER:'false'};
 // The copied checkout owns its local-operation lock, independently of verify.
 delete env.RER_LOCAL_OPERATION;

 function command(args,argv=__rerTestEntryArgs([__rerTestEntry,...args])){const child=spawn(process.execPath,argv,{cwd:directory,env,stdio:['ignore','pipe','pipe']});processes.push(child);let output='';for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{output+=chunk;});return {child,output:()=>output};}
 const setup=command(['setup','--owner-email','owner@example.com','--port',String(port),'--non-interactive','--json']);
 const setupExit=await new Promise(resolve=>setup.child.once('exit',resolve));
 if(setupExit!==0){const error=setup.output().split('\n').flatMap(line=>{try{return [JSON.parse(line)];}catch{return [];}}).find(event=>event.event==='error');throw new Error(`fresh rer setup failed (${setupExit}): ${error?.message ?? 'no structured diagnostic'}`);}
 const vars=await readFile(join(directory,'.dev.vars'),'utf8');assert.match(vars,/AUTH_ORIGIN=.*http:\/\/localhost:/,'fresh setup chose a domain RP ID');
 await mkdir(join(directory,'exports'),{recursive:true});
 await writeFile(join(directory,'private.rer'),'private test archive');
 await writeFile(join(directory,'exports/private.rer'),'private test archive');
 const key=(await readFile(join(directory,'.rer/local/dev-key.env'),'utf8')).match(/^RER_DEV_KEY=(.+)$/m)[1];
 const secrets=[key,...vars.split('\n').flatMap(line=>{
  const match=/^[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*=(.+)$/.exec(line);if(!match)return [];
  try{return [JSON.parse(match[1])];}catch{return [match[1]];}
 })].filter(value=>typeof value==='string'&&value.length>0);
 // Readiness carries the dev key; report only the CLI's structured error.
 function startupDiagnostic(command){
  const error=command.output().split('\n').flatMap(line=>{try{return [JSON.parse(line)];}catch{return [];}}).find(event=>event.event==='error');
  if(!error)return 'no structured diagnostic';
  let message=typeof error.message==='string'?error.message:'no error message';
  for(const secret of secrets)message=message.replaceAll(secret,'[redacted]');
  message=message.replace(/https?:\/\/\S+/g,'[redacted URL]');
  return JSON.stringify({code:error.code,message,exitCode:error.exitCode});
 }
 const dev=command(['dev','--non-interactive','--json']);let ready;
 for(let attempt=0;attempt<480;attempt++){
  assert.equal(dev.child.exitCode,null,dev.child.exitCode===null?'rer dev remains running until stopped':`rer dev remains running until stopped; ${startupDiagnostic(dev)}`);
  ready=dev.output().split('\n').flatMap(line=>{try{return [JSON.parse(line)];}catch{return [];}}).find(event=>event.event==='ready');
  if(ready)break;await new Promise(resolve=>setTimeout(resolve,250));
 }
 assert.ok(ready,'rer dev reports readiness');const origin=ready.url;assert.equal(new URL(origin).hostname,'localhost');
 const request=(path,headers={})=>fetch(origin+path,{headers,redirect:'manual'});
 browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});const context=await browser.newContext(),page=await context.newPage();
 try {await page.goto(ready.openUrl);}catch{throw new Error('The dev credential exchange did not open Auth');}
 await expect(page.getByRole('heading',{name:'Finish setup'})).toBeVisible();
 assert.equal((await context.request.get(origin+'/api/auth/me')).status(),200,'RER_OPEN fragment establishes Auth session');
 await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Finish setup'}).click();await expect(page).toHaveURL(origin+'/app');
 await page.goto(origin+'/app/methods');await expect(page.getByRole('button',{name:'Register a passkey'})).toHaveCount(0);await expect(page.getByRole('link',{name:'Confirm your email',exact:true})).toBeVisible();
 const proof=await context.request.post(origin+'/auth/identity/email/request',{data:{email:'owner@example.com',returnTo:'/setup'},headers:{origin}});assert.equal(proof.status(),202);
 const listing=await(await request('/__dev/outbox',{'x-rer-dev-key':key})).text();const message=listing.match(/href="(\/__dev\/outbox\?message=[^"]+)"/)?.[1];assert.ok(message);
 const detail=await(await request(message.replaceAll('&amp;','&'),{'x-rer-dev-key':key})).text();const link=detail.match(/href="([^"]*\/auth\/identity\/email\/confirm\?token=[^"]+)"/)?.[1];assert.ok(link);
 await page.goto(link.replaceAll('&amp;','&'));await page.getByRole('button',{name:'Continue to Auth'}).click();await expect(page).toHaveURL(origin+'/app');
 const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 await page.goto(origin+'/app/methods');const registration=page.waitForResponse(response=>response.url().endsWith('/passkeys/register/verify'));
 await page.getByRole('button',{name:'Register a passkey'}).click();assert.equal((await registration).status(),200,'fresh rer localhost supports native Chromium passkey enrollment');
 await browser.close();
 assert.equal((await request('/auth/dev/enter?as=owner')).status,404);
 const entered=await request('/auth/dev/enter?as=owner',{'x-rer-dev-key':key});assert.equal(entered.status,303);
 const cookies=entered.headers.getSetCookie().map(value=>value.split(';')[0]);const authCookie=cookies.find(value=>value.startsWith('auth_session='));assert.ok(authCookie,'dev entry issues genuine Auth session');
 const authenticated=await request('/api/auth/me',{cookie:cookies.join('; ')});assert.equal(authenticated.status,200);const model=await authenticated.json();assert.equal(model.user.email,'owner@example.com');assert.ok(model.user.amr.includes('dev'));assert.equal(model.isAdmin,false);
 assert.equal((await request('/api/auth/me',{cookie:authCookie})).status,401,'removing the checkout gate removes dev authority');
 const privatePaths=['/cdn-cgi/local/explorer/api/config','/cdn-cgi/handler/scheduled','/.rer/local/dev-key.env','/.seed/installer/state.json','/exports/private.rer','/private.rer','/@fs'+join(directory,'private.rer')];
 for(const path of privatePaths)assert.equal((await request(path)).status,404,path);
 const signedOut=await request('/auth/dev/enter?as=signed-out',{cookie:cookies.join('; ')});assert.equal(signedOut.status,303);
 assert.equal((await request('/api/auth/me',{cookie:cookies.join('; ')})).status,401,'persona signout revokes the Auth session');
 const stopped=new Promise(resolve=>dev.child.once('exit',resolve));dev.child.kill('SIGTERM');
 assert.equal(await stopped,143,'the owned foreground dev process reports its SIGTERM shutdown');
 const preview=command(['preview','--non-interactive','--json']);let previewReady;
 for(let attempt=0;attempt<480;attempt++){
  assert.equal(preview.child.exitCode,null,preview.child.exitCode===null?'rer preview stays running':`rer preview stays running; ${startupDiagnostic(preview)}`);
  previewReady=preview.output().split('\n').flatMap(line=>{try{return [JSON.parse(line)];}catch{return [];}}).find(event=>event.event==='ready');
  if(previewReady)break;await new Promise(resolve=>setTimeout(resolve,250));
 }
 assert.ok(previewReady,'rer preview ready');
 for(const path of privatePaths)assert.equal((await fetch(previewReady.url+path,{redirect:'manual'})).status,404,`preview ${path}`);
 const previewStopped=new Promise(resolve=>preview.child.once('exit',resolve));preview.child.kill('SIGTERM');
 assert.equal(await previewStopped,143,'the owned foreground preview process reports its SIGTERM shutdown');
 const recovery=command([],['scripts/auth-recovery.mjs','--local']);assert.equal(await new Promise(resolve=>recovery.child.once('exit',resolve)),0);const tokenFile=join(directory,'.rer/local/recovery-token');assert.equal((await stat(tokenFile)).mode&0o777,0o600);const token=(await readFile(tokenFile,'utf8')).trim();assert.ok(!recovery.output().includes(token),'recovery wrapper never prints the token');
 // Export carries people and the signed grant map, never sessions, signing keys or the pairwise key.
 const transfer=command(['export','--output','exports/auth.rer','--non-interactive','--json']);assert.equal(await new Promise(resolve=>transfer.child.once('exit',resolve)),0,transfer.output());
 const archived=(await readFile(join(directory,'exports/auth.rer'),'utf8')).split('\n').filter(Boolean).map(line=>JSON.parse(line)),tables=archived[0].tables.map(table=>table.name);
 for(const kept of ['oa_operators','auth_emails','auth_passkeys','auth_clients','auth_grants','auth_subjects','auth_activity','auth_grant_maps'])assert.ok(tables.includes(kept),kept);
 for(const left of ['auth_sessions','oa_sessions','auth_signing_keys','auth_settings','auth_recovery_tokens','auth_agent_keys','auth_link_tokens'])assert.ok(!tables.includes(left),left);
 console.log('Real rer setup/dev: localhost owner claim, key-gated Auth session bridge, no passkey admin privilege, key removal, persona signout, private path refusals and a policy export');
});
