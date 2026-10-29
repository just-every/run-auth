import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {cp,writeFile,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {openApp,cookieOf} from './runtime.mjs';
import {register,authenticate} from '../auth/webauthn.mjs';
const execute=promisify(execFile),root=fileURLToPath(new URL('../../',import.meta.url));
// A copied checkout owns its operation lease, independently of rer verify.
const commandEnv={...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',RER_SERVER_JOURNEY:'1'};
delete commandEnv.RER_LOCAL_OPERATION;
const varsText=vars=>Object.entries(vars).map(([key,value])=>`${key}=${value}`).join('\n')+'\n';

export async function erasurePortability(t) {
 const app=await openApp();t.after(()=>app.close());await app.claim();
 for(const name of ['package.json','edition.json','rer-project.json','rer-setup.json','wrangler.jsonc','scripts','src','public','migrations','deploy.json','composition.lock.json','.node-version','OPERATIONS.json','OPERATIONS.md','ACCEPTANCE.md','RUN-LOCALLY.md','SEED-COMMAND-CONTRACT.md','AUTH-COMMANDS.md','pnpm-lock.yaml'])await cp(join(root,name),join(app.directory,name),{recursive:true,errorOnExist:true,force:false});
 const runtime={origin:app.origin,call:(path,{method='GET',data,cookie}={})=>method==='POST'?app.post(path,data,cookie):app.get(path,cookie?{cookie}:{})};
 const owner=await register(runtime,await app.signIn());
 let commandCookie=owner.cookie;
 const command=async(path,data,status=200)=>{const response=await app.post('/api/auth/'+path,data,commandCookie);assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 await command('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const worker=await command('directory/onboard',{email:'worker@northwind.example.com',name:'Morgan Ellis',kind:'contractor',set:{department:'Engineering'}},201);
 const factor=await register(runtime,await app.signIn('/app/account','worker@northwind.example.com'));await register(runtime,factor.cookie);
 const cli=async(args,expected=0)=>{
  let result;
  try {result={...(await execute(process.execPath,[join(root,'node_modules/@runeditrun/rer/global/rer.mjs'),...args],{cwd:app.directory,env:commandEnv,maxBuffer:8*1024*1024})),code:0};}
  catch(error){result={code:error.code,stdout:error.stdout||'',stderr:error.stderr||''};}
  // Commands must never print generated private configuration. Keep only the
  // contract diagnostic in assertion output, without its arbitrary log body.
  assert.equal(result.code,expected,'rer '+args[0]+' exit '+result.code+' expected '+expected+'; '+String(result.stdout+'\n'+result.stderr).replace(/[A-Za-z0-9_+\/-]{35,}/g,'[value]').slice(-1400));
  return result.stdout+'\n'+result.stderr;
 };
 // Rotation and archive custody use real public doors; only the remote SCIM
 // service is a test edge. Neither the old nor replacement secret is portable.
 const {scimServer}=await import('../auth/scim-server.mjs'),edge=await scimServer(t,'synthetic-auth-20');
 const company=await command('company-apps/create',{name:'Archive credential custody',entityId:'https://archive.example.com',acsUrl:'https://archive.example.com/acs'},201);
 await command('provisioning/connect',{appId:company.id,baseUrl:edge.url+'/scim/v2',token:'synthetic-auth-20'},201);
 await command('provisioning/rotate',{appId:company.id,token:'synthetic-auth-21'});edge.token='synthetic-auth-21';
 const stagedKey=await command('keys/stage',{},201);assert.ok(stagedKey.kid);
 const now=Date.now(),ownerId=(await (await app.get('/api/auth/me',{cookie:commandCookie})).json()).user.id;await command('reviews/create',{name:'Portable quarterly snapshot',reviewerId:ownerId,periodStart:now-86400000,periodEnd:now-1000,dueAt:now+86400000,intervalMonths:3},201);
 for(const path of ['/api/auth/activity','/auth-assets/auth-ui.js','/auth-assets/decisions-ui.js','/auth-assets/retention-ui.js']) {
  const response=await app.get(path,{cookie:commandCookie});assert.equal(response.status,200);const body=await response.text();
  for(const secret of ['synthetic-auth-20','synthetic-auth-21'])assert.ok(!body.includes(secret),'rotation credentials absent from logs and assets');
 }
 await app.pause();await cli(['export','--output','exports/before-erasure.rer']);await app.resume();
 const preview=await command('erasure/preview',{kind:'person',target:worker.id});await command('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',confirmRemoteDeletion:true});
 const revocations=(await (await app.get('/api/auth/activity',{cookie:commandCookie})).json()).find(row=>row.event==='erasure_credentials_revoked');
 assert.ok(revocations);const revocationAudit=JSON.parse(revocations.detail);assert.equal(revocationAudit.counts.passkeys,2);assert.ok(!JSON.stringify(revocations).includes('worker@northwind.example.com'));assert.ok(!JSON.stringify(revocations).includes('Morgan Ellis'));
 await app.pause();await cli(['export','--output','exports/after-erasure.rer']);
 const {fileRecords}=await import('@runeditrun/rer/modules/portability/files');
 let before,after;
 for await(const record of fileRecords(join(app.directory,'exports/before-erasure.rer')))if(record.kind==='manifest')before=record;
 const archived=[];
 for await(const record of fileRecords(join(app.directory,'exports/after-erasure.rer'))){if(record.kind==='manifest')after=record;if(record.kind==='part')archived.push(...record.items);}
 for(const secret of ['synthetic-auth-20','synthetic-auth-21'])assert.ok(!JSON.stringify(archived).includes(secret),'rotated credentials absent from the real archive');
 const credentialColumns=new Set(['private_key','encrypted_private','sealed_work','sealed_token','sealed_secret','sealed_secrets','secret_hash','token_hash']);
 for(const table of after.tables)assert.ok(table.columns.every(column=>!credentialColumns.has(column.name)),'private custody columns excluded from every portable store');
 assert.ok(after.tables.some(table=>table.name==='auth_review_schedules'),'review parents travel with their snapshots');
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
 const restoredAudit=(await (await app.get('/api/auth/activity',{cookie:cookieOf(confirmed)})).json()).find(row=>row.event==='erasure_credentials_revoked'&&row.subject_id===revocationAudit.id);assert.deepEqual(JSON.parse(restoredAudit.detail),revocationAudit,'the product archive restore preserves the same opaque id and kind counts');
 assert.notEqual((await authenticate(runtime,factor.key)).response.status,200,'the erased passkey stays refused after the product archive restore');
 // Hosting an isolated employer grants no authority to export its directory or
 // to restore over it. Keep the original identity/journal restore proof above.
 commandCookie=cookieOf(confirmed);
 const organization=await command('organizations/create',{name:'Isolated employer archive boundary'},201),prefix='/org/'+organization.id;
 assert.equal((await app.get(prefix+'/.well-known/openid-configuration')).status,200);
 await app.pause();
 const exportRefusal=await cli(['export','--output','exports/isolated-employer.rer'],4);assert.match(exportRefusal,/isolated_organization_export_forbidden/);
 await assert.rejects(lstat(join(app.directory,'exports/isolated-employer.rer')),{code:'ENOENT'});
 const importRefusal=await cli(['import','--input','exports/after-erasure.rer','--yes'],4);assert.match(importRefusal,/isolated_organization_import_forbidden/);
 await app.resume();assert.equal((await app.get(prefix+'/.well-known/openid-configuration')).status,200,'refused root import preserves the isolated employer');
 await command('erasure/policy',{organizationId:organization.id,confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const resetPreview=await command('erasure/preview',{kind:'organization',target:organization.id});
 const reset=await command('erasure/confirm',{organizationId:organization.id,previewId:resetPreview.id,confirmation:'RESET '+app.origin+prefix});assert.equal(reset.local,'complete');
 assert.equal((await app.get(prefix+'/.well-known/openid-configuration')).status,404);
 await app.pause();await cli(['export','--output','exports/erased-employer.rer']);
 let erasedManifest;const erasedRows=[];
 for await(const record of fileRecords(join(app.directory,'exports/erased-employer.rer'))){if(record.kind==='manifest')erasedManifest=record;if(record.kind==='part')erasedRows.push(...record.items.filter(item=>item.kind==='row'&&item.table.startsWith('org_'+organization.id+'_')));}
 assert.ok(erasedRows.some(item=>item.table==='org_'+organization.id+'_auth_erasure_receipts'),'anonymous employer accountability remains portable');
 assert.ok(!erasedRows.some(item=>item.table==='org_'+organization.id+'_oa_operators'),'no erased employer directory is restored into an archive');
 assert.ok(!JSON.stringify(erasedRows).includes(app.vars.OWNER_EMAIL),'anonymous employer namespace holds no person email');
 const namespace='org_'+organization.id+'_',secretColumns=new Set(['private_key','encrypted_private','sealed_work','sealed_token','sealed_secret','sealed_secrets','secret_hash','token_hash']);
 for(const table of erasedManifest.tables.filter(table=>table.name.startsWith(namespace))) {
  assert.ok(!['auth_settings','oa_dev_credentials'].includes(table.name.slice(namespace.length)),'installation-local credential store excluded');
  assert.ok(table.columns.every(column=>!secretColumns.has(column.name)),'private credential and sealed-work columns excluded from '+table.name);
 }
 return {beforeEpoch:before.epoch,afterEpoch:after.epoch};
}
