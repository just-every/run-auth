import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {cp,writeFile,readFile,stat,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {openApp,cookieOf} from './runtime.mjs';
import {register,authenticate} from '../auth/webauthn.mjs';

const execute=promisify(execFile),root=fileURLToPath(new URL('../../',import.meta.url));
const ownerEmail='synthetic-auth-10@emergency.example.com',workerEmail='synthetic-auth-11@company.example.com';
const varsText=vars=>Object.entries(vars).map(([key,value])=>`${key}=${value}`).join('\n')+'\n';
const checkoutFiles=['package.json','edition.json','rer-project.json','rer-setup.json','wrangler.jsonc','scripts','src','public','migrations','deploy.json','composition.lock.json','.node-version','OPERATIONS.json','OPERATIONS.md','ACCEPTANCE.md','RUN-LOCALLY.md','SEED-COMMAND-CONTRACT.md','AUTH-COMMANDS.md','pnpm-lock.yaml'];

// A root-installation loss rehearsal using the emitted Worker, its real D1
// outbox, rer's archive engine and the supported local recovery command.
export async function continuityDrill(t) {
 const app=await openApp();t.after(()=>app.close());
 await app.pause();app.vars.OWNER_EMAIL=ownerEmail;
 await writeFile(join(app.directory,'.dev.vars'),varsText(app.vars),{mode:0o600});
 for(const name of checkoutFiles)await cp(join(root,name),join(app.directory,name),{recursive:true,errorOnExist:true,force:false});
 await app.resume();await app.claim();
 const runtime={origin:app.origin,call:(path,{method='GET',data,cookie}={})=>method==='POST'?app.post(path,data,cookie):app.get(path,cookie?{cookie}:{})};
 const owner=await register(runtime,await app.signIn()),spare=await register(runtime,owner.cookie);
 const invited=await app.post('/api/auth/people/invite',{email:workerEmail,name:'Synthetic continuity worker'},owner.cookie);assert.equal(invited.status,201);
 const worker=await register(runtime,await app.signIn('/app/account',workerEmail));
 const run=async(entry,args,label)=>{
  let result;
  try {result={...(await execute(process.execPath,[entry,...args],{cwd:app.directory,env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',RER_SERVER_JOURNEY:'1'},maxBuffer:8*1024*1024})),code:0};}
  catch(error){result={code:error.code,stdout:error.stdout||'',stderr:error.stderr||''};}
  // Never attach CLI logs, URLs, cookies or private configuration to failures.
  assert.equal(result.code,0,label+' must succeed');return result.stdout+'\n'+result.stderr;
 };
 const cli=(...args)=>run(join(root,'node_modules/@runeditrun/rer/global/rer.mjs'),args,'rer '+args[0]);
 const installRecovery=async()=>{
  const output=await run(join(app.directory,'scripts/auth-recovery.mjs'),['--local'],'local recovery installation');
  const path=join(app.directory,'.rer/local/recovery-token'),token=(await readFile(path,'utf8')).trim();
  assert.equal((await stat(path)).mode&0o777,0o600,'recovery file is private');
  assert.ok(token.length>=43,'local recovery has a random token');
  assert.ok(!output.includes(token),'recovery command never prints its token');return token;
 };

 await app.pause();const preLossToken=await installRecovery();
 await cli('export','--output','exports/synthetic-auth-12.rer');
 const {fileRecords}=await import('@runeditrun/rer/modules/portability/files');
 let manifest;let rows=0;
 for await(const record of fileRecords(join(app.directory,'exports/synthetic-auth-12.rer'))) {
  if(record.kind==='manifest')manifest=record;
  if(record.kind==='part'){
   assert.ok(!JSON.stringify(record.items).includes(preLossToken),'archive carries no emergency token');
   rows+=record.items.filter(item=>item.kind==='row'&&item.table==='oa_operators').length;
  }
 }
 assert.ok(manifest&&rows>=2,'the real archive contains the scoped test accounts');
 assert.ok(!manifest.tables.some(table=>['auth_sessions','auth_recovery_tokens','auth_signing_keys','auth_saml_keys','auth_settings'].includes(table.name)),'archive is not live session or private-key authority');
 await app.resume();
 assert.equal((await app.post('/api/auth/recovery/token',{token:preLossToken},worker.cookie)).status,403,'ordinary worker cannot redeem installation recovery');
 assert.equal((await app.get('/exports/synthetic-auth-12.rer')).status,404,'offline archive is never a public download');

 // Rehearse installation loss through the public CLI. Private configuration is
 // restored from separate operator custody, as required by the import engine.
 await app.pause();await cli('reset','--yes');
 assert.equal(await lstat(join(app.directory,'.dev.vars')).catch(()=>null),null);
 await writeFile(join(app.directory,'.dev.vars'),varsText(app.vars),{mode:0o600});
 await cli('import','--input','exports/synthetic-auth-12.rer','--yes');await app.resume();
 assert.equal((await app.get('/api/auth/me',{cookie:owner.cookie})).status,401,'archived directory never restores a live owner session');
 const restored=await app.signIn();
 assert.equal((await app.post('/api/auth/recovery/token',{token:preLossToken},restored)).status,400,'archive cannot reactivate the pre-loss emergency token');
 assert.equal((await app.post('/auth/passkeys/register/options',{},restored)).status,403,'restored email alone cannot replace the lost factors');

 await app.pause();const recovery=await installRecovery();await app.resume();
 const workerEmailSession=await app.signIn('/app/account',workerEmail);
 assert.equal((await app.post('/api/auth/recovery/token',{token:recovery},workerEmailSession)).status,403);
 // Capture an unfinished public email proof before recovery. Its later replay
 // must fail just like the consumed emergency token and the two lost factors.
 const pending=await app.post('/auth/identity/email/request',{email:ownerEmail}),pendingLink=await app.link();
 const completed=await app.post('/api/auth/recovery/token',{token:recovery},restored);assert.equal(completed.status,200);
 assert.equal((await app.post('/api/auth/recovery/token',{token:recovery},restored)).status,400);
 assert.equal((await app.post('/auth/identity/email/confirm',{token:pendingLink.searchParams.get('token')},cookieOf(pending))).status,400);
 for(const key of [owner.key,spare.key])assert.equal((await authenticate(runtime,key)).response.status,400,'restored lost hardware cannot sign in after owner recovery');
 assert.equal((await app.get('/api/auth/people',{cookie:restored})).status,403,'emergency redemption still needs replacement hardware enrollment');
 const replacement=await register(runtime,restored);
 const peopleResponse=await app.get('/api/auth/people',{cookie:replacement.cookie});assert.equal(peopleResponse.status,200);
 const people=await peopleResponse.json();assert.ok(people.some(p=>p.email===ownerEmail)&&people.some(p=>p.email===workerEmail),'owner can administer the restored root directory');
 assert.equal((await authenticate(runtime,replacement.key)).response.status,200);
 t.diagnostic('MEASURED root-only CLI archive/reset/restore, separate private configuration custody, real outbox email proof, owner-only local recovery, replacement hardware, dead archived sessions, old-token and lost-factor replay refusal');
 t.diagnostic('UNMEASURED isolated employer-owner archive/restore (AUTH-TRANSFER-002), independent approval of local owner recovery, and remotely hosted issuer disaster recovery; this rehearsal grants no new recovery authority');
}
