import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {symlink,writeFile,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {openApp,cookieOf} from './runtime.mjs';
import {register,authenticate} from '../auth/webauthn.mjs';
const execute=promisify(execFile),root=fileURLToPath(new URL('../../',import.meta.url));
const varsText=vars=>Object.entries(vars).map(([key,value])=>`${key}=${value}`).join('\n')+'\n';

export async function erasurePortability(t) {
 const app=await openApp();t.after(()=>app.close());await app.claim();
 for(const name of ['package.json','edition.json','rer-project.json','rer-setup.json','wrangler.jsonc','scripts','src','public','migrations','deploy.json','composition.lock.json','.node-version','OPERATIONS.json','RUN-LOCALLY.md','SEED-COMMAND-CONTRACT.md','AUTH-COMMANDS.md','pnpm-lock.yaml'])await symlink(join(root,name),join(app.directory,name));
 const runtime={origin:app.origin,call:(path,{method='GET',data,cookie}={})=>method==='POST'?app.post(path,data,cookie):app.get(path,cookie?{cookie}:{})};
 const owner=await register(runtime,await app.signIn());
 const command=async(path,data,status=200)=>{const response=await app.post('/api/auth/'+path,data,owner.cookie);assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 await command('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const worker=await command('directory/onboard',{email:'worker@northwind.example.com',name:'Morgan Ellis',kind:'contractor',set:{department:'Engineering'}},201);
 const factor=await register(runtime,await app.signIn('/app/account','worker@northwind.example.com'));await register(runtime,factor.cookie);
 const cli=async(args,expected=0)=>{
  let result;
  try {result={...(await execute(process.execPath,[join(root,'node_modules/@runeditrun/rer/global/rer.mjs'),...args],{cwd:app.directory,env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',RER_SERVER_JOURNEY:'1'},maxBuffer:8*1024*1024})),code:0};}
  catch(error){result={code:error.code,stdout:error.stdout||'',stderr:error.stderr||''};}
  // Commands must never print generated private configuration. Keep only the
  // contract diagnostic in assertion output, without its arbitrary log body.
  assert.equal(result.code,expected,'rer '+args[0]+' exit '+result.code+' expected '+expected+'; '+String(result.stdout+'\n'+result.stderr).replace(/[A-Za-z0-9_+\/-]{35,}/g,'[value]').slice(-1400));
  return result.stdout+'\n'+result.stderr;
 };
 await app.pause();await cli(['export','--output','exports/before-erasure.rer']);await app.resume();
 const preview=await command('erasure/preview',{kind:'person',target:worker.id});await command('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',confirmRemoteDeletion:true});
 await app.pause();await cli(['export','--output','exports/after-erasure.rer']);
 const {fileRecords}=await import('@runeditrun/rer/modules/portability/files');
 let before,after;
 for await(const record of fileRecords(join(app.directory,'exports/before-erasure.rer')))if(record.kind==='manifest')before=record;
 const archived=[];
 for await(const record of fileRecords(join(app.directory,'exports/after-erasure.rer'))){if(record.kind==='manifest')after=record;if(record.kind==='part')archived.push(...record.items);}
 assert.equal(before.sourceIdentity,after.sourceIdentity);assert.ok(after.epoch>before.epoch);assert.ok(after.journal.length);
 assert.ok(!JSON.stringify(archived).includes('worker@northwind.example.com'),'every exported store omits erased email');
 assert.ok(archived.some(item=>item.table==='auth_activity'&&item.row.event==='erasure_completed'),'anonymous accountability is portable');
 await cli(['reset','--yes']);assert.equal(await lstat(join(app.directory,'.dev.vars')).catch(()=>null),null,'local reset removes private configuration');
 await writeFile(join(app.directory,'.dev.vars'),varsText(app.vars),{mode:0o600});
 const refused=await cli(['import','--input','exports/before-erasure.rer','--journal','exports/after-erasure.rer','--yes'],4);assert.match(refused,/erasure_epoch/);
 await cli(['import','--input','exports/after-erasure.rer','--yes']);await app.resume();
 const authenticated=await authenticate(runtime,owner.key);assert.equal(authenticated.response.status,200);
 const proof=await app.post('/auth/identity/email/request',{email:app.vars.OWNER_EMAIL},cookieOf(authenticated.response)),link=await app.link();
 const confirmed=await app.post('/auth/identity/email/confirm',{token:link.searchParams.get('token')},cookieOf(proof));assert.equal(confirmed.status,200);
 const people=await (await app.get('/api/auth/people',{cookie:cookieOf(confirmed)})).json();assert.ok(people.some(p=>p.email==='owner@example.com'));assert.ok(!people.some(p=>p.email==='worker@northwind.example.com'));
 return {beforeEpoch:before.epoch,afterEpoch:after.epoch};
}
