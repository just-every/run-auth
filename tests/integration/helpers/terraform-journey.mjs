import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {generateKeyPair,exportJWK,exportPKCS8} from 'jose';
import {expect} from '@playwright/test';

export async function terraformJourney({app,context,page,t,shoot}) {
 const directory=await mkdtemp(join(tmpdir(),'auth-terraform-ui-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const home=join(directory,'home');await mkdir(home);
 const root=fileURLToPath(new URL('../../../',import.meta.url));
 const platform=process.platform==='darwin'?'darwin':process.platform,arch=process.arch==='arm64'?'arm64':'amd64';
 const mirror=join(directory,'mirror'),destination=join(mirror,'registry.terraform.io','runeditrun','auth','0.1.0',`${platform}_${arch}`);await mkdir(destination,{recursive:true});
 async function run(command,args,env=process.env) {
  const child=spawn(command,args,{cwd:directory,env,stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);
  const timer=setTimeout(()=>child.kill('SIGTERM'),180000);
  try{return await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>resolve({code,output}));});}finally{clearTimeout(timer);}
 }
 const build=await run('go',['-C',join(root,'packages/terraform-provider'),'build','-buildvcs=false','-o',join(destination,'terraform-provider-auth_v0.1.0'),'.']);assert.equal(build.code,0,build.output);
 const key=await generateKeyPair('ES256',{extractable:true});
 const me=await(await context.request.get(app.origin+'/api/auth/me')).json();
 const serviceResponse=await context.request.post(app.origin+'/api/auth/admin-service-apps/create',{headers:{origin:app.origin},data:{name:'Terraform browser journey',purpose:'Reconcile a scoped app and detect UI drift',ownerId:me.user.id,expiresAt:Date.now()+3600000,scopes:['groups.manage','apps.manage','assignments.manage'],resources:{people:['*'],groups:['*'],apps:['*']},jwks:{keys:[{...await exportJWK(key.publicKey),kid:'synthetic-auth-202',alg:'ES256'}]}}});assert.equal(serviceResponse.status(),201,await serviceResponse.text());const service=await serviceResponse.json();
 const privateFile=join(directory,'key.pem');await writeFile(privateFile,await exportPKCS8(key.privateKey),{mode:0o600});
 const cliFile=join(directory,'cli.tfrc');await writeFile(cliFile,`provider_installation { filesystem_mirror { path = ${JSON.stringify(mirror)} } }`);
 const env={...process.env,HOME:home,TF_CLI_CONFIG_FILE:cliFile,TF_IN_AUTOMATION:'1',CHECKPOINT_DISABLE:'1',AUTH_ISSUER:app.origin,AUTH_CLIENT_ID:service.clientId,AUTH_PRIVATE_KEY_FILE:privateFile,AUTH_KEY_ID:'synthetic-auth-202'};delete env.TF_LOG;delete env.TF_LOG_PATH;delete env.AUTH_SCOPES;
 const command=async(args,expected=0)=>{const result=await run('terraform',args,env);assert.equal(result.code,expected,result.output);return result.output;};
 await writeFile(join(directory,'main.tf'),`terraform {\n required_providers {\n  auth = { source = "registry.terraform.io/runeditrun/auth", version = "0.1.0" }\n }\n}\nprovider "auth" {}\nresource "auth_group" "training" { name = "Terraform training" }\nresource "auth_saml_app" "training" {\n name = "Terraform training"\n entity_id = "https://training.example.com/saml"\n acs_url = "https://training.example.com/acs"\n}\nresource "auth_assignment" "training" {\n app_id = auth_saml_app.training.id\n principal_type = "group"\n principal_id = auth_group.training.id\n}\n`);
 await command(['init','-input=false','-no-color']);await command(['plan','-input=false','-no-color','-out=initial.plan']);await command(['apply','-input=false','-no-color','initial.plan']);await command(['plan','-input=false','-no-color','-detailed-exitcode']);
 await page.goto(app.origin+'/app/apps');
 const panel=page.locator('section',{has:page.getByRole('heading',{name:'Terraform training',exact:true})});await expect(panel).toBeVisible();await expect(panel.getByText('Terraform training',{exact:true})).toHaveCount(2);
 await shoot(page,'terraform-managed');
 await page.setViewportSize({width:1440,height:1000});
 const removed=page.waitForResponse(response=>response.url().endsWith('/api/auth/company-apps/remove'));
 await panel.getByRole('button',{name:'Remove app',exact:true}).click();assert.equal((await removed).status(),200);
 await expect(panel).toHaveCount(0);
 await command(['plan','-input=false','-no-color','-detailed-exitcode','-out=ui-drift.plan'],2);
 const drift=JSON.parse(await command(['show','-json','ui-drift.plan']));assert.deepEqual(drift.resource_changes.find(row=>row.address==='auth_saml_app.training').change.actions,['create'],'a removal through the actual UI is detected by the provider');
 const state=await readFile(join(directory,'terraform.tfstate'),'utf8');assert.ok(!state.includes(await exportPKCS8(key.privateKey)));
 assert.equal((await context.request.post(app.origin+'/api/auth/admin-service-apps/revoke',{headers:{origin:app.origin},data:{id:service.id}})).status(),200);
}
