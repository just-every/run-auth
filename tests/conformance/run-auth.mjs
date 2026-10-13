import {createServer,get} from 'node:https';
import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {fixture} from './auth-fixture.mjs';

const here=dirname(fileURLToPath(import.meta.url));
const out=resolve(process.argv[2]||'conformance-current-results');
await mkdir(out,{recursive:true,mode:0o700});
const scratch=await mkdtemp(join(tmpdir(),'auth-conformance-'));
const origin='https://auth.localhost:19443',suiteOrigin='https://localhost:8443';
let provider,server,child,result=1;
const interrupted=()=>{child?.kill('SIGTERM');};
process.on('SIGINT',interrupted);process.on('SIGTERM',interrupted);
try {
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(scratch,'key.pem'),'-out',join(scratch,'cert.pem'),'-days','1','-subj','/CN=auth.localhost','-addext','subjectAltName=DNS:auth.localhost'],{stdio:'ignore'});
 provider=await fixture(scratch,origin,suiteOrigin);
 await writeFile(join(out,'preflight.json'),await readFile(join(scratch,'preflight.json')),{mode:0o600});
 server=createServer({key:await readFile(join(scratch,'key.pem')),cert:await readFile(join(scratch,'cert.pem'))},async(req,res)=>{
  try {
   const chunks=[];for await(const chunk of req)chunks.push(chunk);
   const response=await provider.runtime.call(req.url,{method:req.method,headers:req.headers,data:undefined,...(chunks.length?{form:Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()))}:{})});
   res.statusCode=response.status;
   for(const [name,value]of response.headers)if(name!=='set-cookie')res.setHeader(name,value);
   const cookies=response.headers.getSetCookie();if(cookies.length)res.setHeader('set-cookie',cookies);
   res.end(Buffer.from(await response.arrayBuffer()));
  }catch {res.writeHead(500);res.end();}
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(19443,'0.0.0.0',resolve);});
 const discovery=await new Promise((resolve,reject)=>get('https://localhost:19443/.well-known/openid-configuration',{rejectUnauthorized:false},response=>{let body='';response.on('data',data=>body+=data);response.on('end',()=>resolve({status:response.statusCode,metadata:JSON.parse(body)}));}).on('error',reject));
 assert.equal(discovery.status,200);assert.equal(discovery.metadata.issuer,origin);
 await writeFile(join(out,'https-preflight.json'),JSON.stringify({status:discovery.status,issuer:discovery.metadata.issuer,listener:'19443',tls:'local self-signed development certificate'})+'\n',{mode:0o600});
 const planSpecs=[
  'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client][client_auth_type=private_key_jwt]',
  'oidcc-config-certification-test-plan',
  'oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client][client_auth_type=private_key_jwt]'
 ];
 child=spawn('bash',[join(here,'run.sh'),'--target','external','--plans',planSpecs.join(','),'--config',join(scratch,'config.json'),'--extra-host','auth.localhost=host-gateway','--out',join(out,'suite')],{stdio:'inherit',env:{...process.env,BASE_URL:suiteOrigin,BASE_MTLS_URL:'https://localhost:8444'}});
 result=await new Promise(resolve=>child.once('exit',code=>resolve(code??1)));child=null;
}catch(error) {
 await writeFile(join(out,'adapter-error.json'),JSON.stringify({name:error.name,message:error.message})+'\n',{mode:0o600});
}finally {
 if(child){child.kill('SIGTERM');await new Promise(resolve=>child.once('exit',resolve));}
 if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 if(provider){await writeFile(join(out,'http-requests.json'),JSON.stringify(provider.records,null,2)+'\n',{mode:0o600});await provider.runtime.close();}
 await rm(scratch,{recursive:true,force:true});
 await writeFile(join(out,'auth-cleanup.json'),JSON.stringify({provider_stopped:true,private_fixture_removed:true,adapter_result:result})+'\n',{mode:0o600});
 execFileSync('python3',['-c',"import sys;sys.path.insert(0,sys.argv[1]);from artifacts import preserve_runner_artifact;from pathlib import Path;preserve_runner_artifact(Path(sys.argv[2]))",join(here,'lib'),out],{stdio:'inherit'});
}
process.exitCode=result;
