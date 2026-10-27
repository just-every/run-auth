import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {mkdtemp,writeFile,readFile,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {generateKeyPair,exportJWK,exportPKCS8} from 'jose';
import {spCredentials} from './saml-helpers.mjs';
import {openRuntime} from './runtime.mjs';
import {passkeyPerson,post,activity,everyRow} from './agents-helpers.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
async function run(command,args,options={}) {
 const child=spawn(command,args,{...options,stdio:['ignore','pipe','pipe']});let output='';
 child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);
 const timer=setTimeout(()=>child.kill('SIGTERM'),180000);
 try{return await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>resolve({code,output}));});}finally{clearTimeout(timer);}
}

// Actual CLI installations share a filesystem mirror, never a mock provider.
for(const cli of ['terraform','tofu'])test(`${cli} installs the Auth provider and reconciles native resources with drift, import and audited scope and stale-plan refusals`,{timeout:240000},async t=>{
 const dir=await mkdtemp(join(tmpdir(),'auth-terraform-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const home=join(dir,'home'),mirror=join(dir,'mirror');await mkdir(home);
 const host=cli==='terraform'?'registry.terraform.io':'registry.opentofu.org';
 const platform=process.platform==='darwin'?'darwin':process.platform,arch=process.arch==='arm64'?'arm64':'amd64';
 const binaryDir=join(mirror,host,'runeditrun','auth','0.1.0',`${platform}_${arch}`);await mkdir(binaryDir,{recursive:true});
 const built=await run('go',['build','-o',join(binaryDir,'terraform-provider-auth_v0.1.0'),'.'],{cwd:join(root,'packages/terraform-provider')});assert.equal(built.code,0,built.output);
 const configFile=join(dir,'cli.tfrc');await writeFile(configFile,`provider_installation { filesystem_mirror { path = ${JSON.stringify(mirror)} } }`);
 const r=await openRuntime();t.after(()=>r.close());const requests=[],tokens=[];
 const server=createServer(async(req,res)=>{
  try{
   const chunks=[];for await(const b of req)chunks.push(b);const body=Buffer.concat(chunks).toString();
   const response=await r.call(req.url,{method:req.method,headers:req.headers,...(body?req.headers['content-type']?.startsWith('application/json')?{data:JSON.parse(body)}:{form:Object.fromEntries(new URLSearchParams(body))}:{})});
   requests.push({method:req.method,path:req.url,status:response.status,etag:req.headers['if-match']});
   const text=await response.text();if(req.url==='/oidc/token'&&response.ok)tokens.push(JSON.parse(text).access_token);
   res.writeHead(response.status,Object.fromEntries(response.headers));res.end(text);
  }catch{res.writeHead(500);res.end('{}');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 r.origin='http://127.0.0.1:'+server.address().port;r.local=true;r.now=Date.now();
 const owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 const algorithm=cli==='tofu'?'RS256':'ES256';
 const key=await generateKeyPair(algorithm,{extractable:true}),jwk={...await exportJWK(key.publicKey),kid:'synthetic-auth-201',alg:algorithm};
 const create=async(scopes,resources)=>{
  const response=await r.call('/api/auth/admin-service-apps/create',post({name:'Terraform reconciler',purpose:'Manage native scoped resources',ownerId:'owner',jwks:{keys:[jwk]},scopes,resources,expiresAt:r.now+3600000},owner.cookie));assert.equal(response.status,201,await response.clone().text());return response.json();
 };
 const full=await create(['groups.manage','apps.manage','assignments.manage'],{people:['*'],groups:['*'],apps:['*']});
 const privateKey=await exportPKCS8(key.privateKey),privateFile=join(dir,'signing.pem');await writeFile(privateFile,privateKey,{mode:0o600});
 // External key file is deliberately absent from every HCL and provider schema.
 const env={...process.env,HOME:home,TF_CLI_CONFIG_FILE:configFile,TF_IN_AUTOMATION:'1',CHECKPOINT_DISABLE:'1',AUTH_ISSUER:r.origin,AUTH_CLIENT_ID:full.clientId,AUTH_PRIVATE_KEY_FILE:privateFile,AUTH_KEY_ID:jwk.kid};
 delete env.TF_LOG;delete env.TF_LOG_PATH;delete env.AUTH_SCOPES;
 let diagnostics='';const command=async(args,expected=0,extra={})=>{
  const result=await run(cli,args,{cwd:dir,env:{...env,...extra}});diagnostics+=result.output;
  assert.equal(result.code,expected,result.output);return result.output;
 };
 const header=`terraform {\n required_providers {\n  auth = { source = "${host}/runeditrun/auth", version = "0.1.0" }\n }\n}\nprovider "auth" {}\n`;
 const resources=name=>`resource "auth_group" "team" { name = "Engineering" }\nresource "auth_saml_app" "payroll" {\n name = "${name}"\n entity_id = "https://payroll.example.com/saml"\n acs_url = "https://payroll.example.com/acs"\n}\nresource "auth_assignment" "payroll" {\n app_id = auth_saml_app.payroll.id\n principal_type = "group"\n principal_id = auth_group.team.id\n role = "employee"\n}\n`;
 await writeFile(join(dir,'main.tf'),header+resources('Payroll'));
 await command(['init','-input=false','-no-color']);await command(['plan','-input=false','-no-color','-out=initial.plan']);await command(['apply','-input=false','-no-color','initial.plan']);
 const state=JSON.parse(await command(['show','-json']));
 const values=Object.fromEntries(state.values.root_module.resources.map(row=>[row.address,row.values]));
 assert.equal(values['auth_group.team'].name,'Engineering');assert.equal(values['auth_saml_app.payroll'].name,'Payroll');
 assert.equal(values['auth_assignment.payroll'].app_id,values['auth_saml_app.payroll'].id);assert.equal(values['auth_assignment.payroll'].principal_id,values['auth_group.team'].id);assert.equal(values['auth_assignment.payroll'].role,'employee');
 await command(['plan','-input=false','-no-color','-detailed-exitcode']);
 // The same authenticated command used by the Apps UI changes live settings.
 const appID=values['auth_saml_app.payroll'].id;
 const ui=await r.call('/api/auth/company-apps/update',post({id:appID,name:'Payroll UI change',entityId:'https://payroll.example.com/saml',acsUrl:'https://payroll.example.com/acs'},owner.cookie));assert.equal(ui.status,200,await ui.clone().text());
 await command(['plan','-input=false','-no-color','-detailed-exitcode','-out=drift.plan'],2);
 const drift=JSON.parse(await command(['show','-json','drift.plan']));
 const changed=drift.resource_changes.find(row=>row.address==='auth_saml_app.payroll');assert.equal(changed.change.before.name,'Payroll UI change');assert.equal(changed.change.after.name,'Payroll');assert.deepEqual(changed.change.actions,['update']);
 await command(['apply','-input=false','-no-color','drift.plan']);await command(['plan','-input=false','-no-color','-detailed-exitcode']);
 const sp=await spCredentials('benefits.example.com');
 const existing=await r.call('/api/auth/company-apps/create',post({name:'Benefits',entityId:'https://benefits.example.com/saml',acsUrl:'https://benefits.example.com/acs',signingCertificate:sp.cert},owner.cookie));assert.equal(existing.status,201);const existingID=(await existing.json()).id;
 const imported=`resource "auth_saml_app" "benefits" {\n name = "Benefits"\n entity_id = "https://benefits.example.com/saml"\n acs_url = "https://benefits.example.com/acs"\n}\n`;
 await writeFile(join(dir,'main.tf'),header+resources('Payroll')+imported);await command(['import','-input=false','-no-color','auth_saml_app.benefits',existingID]);await command(['plan','-input=false','-no-color','-detailed-exitcode']);
 // Independent updates in one apply advance only this process's own revision.
 const renamedImport=imported.replace('Benefits','Benefits renamed');
 await writeFile(join(dir,'main.tf'),header+resources('Payroll renamed')+renamedImport);
 await command(['plan','-input=false','-no-color','-out=renamed.plan']);await command(['apply','-input=false','-no-color','renamed.plan']);await command(['plan','-input=false','-no-color','-detailed-exitcode']);
 assert.equal((await r.db.prepare('SELECT name FROM auth_apps WHERE id=?').bind(existingID).first()).name,'Benefits renamed');
 assert.deepEqual(JSON.parse((await r.db.prepare('SELECT sp_certificates FROM auth_apps WHERE id=?').bind(existingID).first()).sp_certificates),[sp.certBase64],'a machine rename preserves the existing service-provider certificate');
 // A saved plan must not silently approve a subsequent UI revision.
 await writeFile(join(dir,'main.tf'),header+resources('Reviewed rename')+renamedImport);
 await command(['plan','-input=false','-no-color','-out=stale.plan']);
 assert.equal((await r.call('/api/auth/company-apps/update',post({id:appID,name:'Concurrent UI edit',entityId:'https://payroll.example.com/saml',acsUrl:'https://payroll.example.com/acs'},owner.cookie))).status,200);
 const at=requests.length;await command(['apply','-input=false','-no-color','stale.plan'],1);
 assert.equal(requests.slice(at).filter(row=>row.method==='PATCH'&&row.path===`/api/auth/admin/v1/apps/${appID}`).length,1,'stale mutations never retry');
 assert.ok(requests.slice(at).some(row=>row.status===412));
 assert.equal((await r.db.prepare('SELECT name FROM auth_apps WHERE id=?').bind(appID).first()).name,'Concurrent UI edit');
 const afterStale=JSON.parse(await command(['show','-json']));assert.notEqual(afterStale.values.root_module.resources.find(row=>row.address==='auth_saml_app.payroll').values.name,'Reviewed rename','refused state is never recorded as applied');
 // A narrower credential can read the reviewed app but cannot change it.
 const limited=await create(['apps.read'],{people:[],groups:[],apps:[appID]});
 const restricted=join(dir,'restricted');await mkdir(restricted);await writeFile(join(restricted,'main.tf'),header+`resource "auth_saml_app" "denied" {\n name = "Forbidden rename"\n entity_id = "https://payroll.example.com/saml"\n acs_url = "https://payroll.example.com/acs"\n}\n`);
 const limitedEnv={...env,AUTH_CLIENT_ID:limited.clientId};
 for(const args of [['init','-input=false','-no-color'],['import','-input=false','-no-color','auth_saml_app.denied',appID],['plan','-input=false','-no-color','-out=denied.plan']]){const result=await run(cli,args,{cwd:restricted,env:limitedEnv});diagnostics+=result.output;assert.equal(result.code,0,result.output);}
 const denied=await run(cli,['apply','-input=false','-no-color','denied.plan'],{cwd:restricted,env:limitedEnv});diagnostics+=denied.output;assert.equal(denied.code,1,denied.output);
 assert.equal((await r.db.prepare('SELECT name FROM auth_apps WHERE id=?').bind(appID).first()).name,'Concurrent UI edit');
 const audit=await activity(r,'admin_api_call');assert.ok(audit.some(row=>row.detail.serviceApp===limited.id&&row.detail.result==='admin_service_scope_required'));assert.ok(audit.some(row=>row.detail.serviceApp===full.id&&row.detail.result==='precondition_failed'));
 // A management scope alone cannot create outside its live resource grant.
 const bounded=await create(['groups.manage'],{people:[],groups:[],apps:[]});
 const boundedDir=join(dir,'bounded');await mkdir(boundedDir);await writeFile(join(boundedDir,'main.tf'),header+'resource "auth_group" "denied" { name = "Forbidden group" }\n');
 const boundedEnv={...env,AUTH_CLIENT_ID:bounded.clientId};
 for(const args of [['init','-input=false','-no-color'],['plan','-input=false','-no-color','-out=bounded.plan']]){const result=await run(cli,args,{cwd:boundedDir,env:boundedEnv});diagnostics+=result.output;assert.equal(result.code,0,result.output);}
 const boundedApply=await run(cli,['apply','-input=false','-no-color','bounded.plan'],{cwd:boundedDir,env:boundedEnv});diagnostics+=boundedApply.output;assert.equal(boundedApply.code,1,boundedApply.output);
 assert.equal(await r.db.prepare('SELECT id FROM auth_groups WHERE name=?').bind('Forbidden group').first(),null,'a refused creation leaves no partial group');
 assert.ok((await activity(r,'admin_api_call')).some(row=>row.detail.serviceApp===bounded.id&&row.detail.result==='admin_service_resource_refused'));
 const exposed=diagnostics+await readFile(join(dir,'terraform.tfstate'),'utf8')+await readFile(join(restricted,'terraform.tfstate'),'utf8')+await everyRow(r);
 for(const secret of [privateKey,(await exportJWK(key.privateKey)).d,...tokens])assert.ok(!exposed.includes(secret),'private keys and tokens stay out of state and diagnostics');
 assert.ok(tokens.length>0,'real private-key OAuth was exercised');
 // Update an assignment and destroy through the same reviewed public doors.
 await writeFile(join(dir,'main.tf'),header+resources('Payroll final').replace('role = "employee"','role = "viewer"')+renamedImport);
 await command(['plan','-input=false','-no-color','-out=final.plan']);await command(['apply','-input=false','-no-color','final.plan']);await command(['plan','-input=false','-no-color','-detailed-exitcode']);
 assert.equal((await r.db.prepare('SELECT role FROM auth_app_assignments WHERE app_id=?').bind(appID).first()).role,'viewer');
 await command(['destroy','-input=false','-no-color','-auto-approve']);
 assert.equal(await r.db.prepare('SELECT id FROM auth_groups WHERE id=?').bind(values['auth_group.team'].id).first(),null);
 assert.equal(await r.db.prepare('SELECT app_id FROM auth_app_assignments WHERE app_id=?').bind(appID).first(),null);
 assert.ok((await r.db.prepare('SELECT disabled_at FROM auth_apps WHERE id=?').bind(appID).first()).disabled_at!==null);

});
