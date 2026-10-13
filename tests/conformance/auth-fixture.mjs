import assert from 'node:assert/strict';
import {randomBytes,createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {join} from 'node:path';
import {generateKeyPair,exportJWK,SignJWT,jwtVerify,createLocalJWKSet} from 'jose';

export async function fixture(directory,origin,suiteOrigin) {
 const {openRuntime,emailSession}=await import(pathToFileURL(join(process.cwd(),'tests/auth/runtime.mjs')));
 const runtime=await openRuntime();
 runtime.origin=origin;runtime.local=true;runtime.now=Date.now();
 const records=[];
 const call=runtime.call;
 runtime.call=async(path,options={})=>{
  runtime.now=Date.now();
  const response=await call(path,options);
  records.push({phase:runtime.phase||'preflight',method:options.method||'GET',path:new URL(path,origin).pathname,status:response.status});
  return response;
 };
 try {
  await runtime.person('conformance-owner','owner@conformance.example.com','owner');
  // The native suite schema predates RER's required interface negotiation field.
  // Declare that known extension using upstream's supported configuration;
  // structural metadata validation and all protocol conditions still run.
  const base=suiteOrigin+'/test/a/auth-current';
  // Browser automation for the logout plan: authorization ends at Auth's own page
  // (the person cannot sign in by email inside the suite's browser), and
  // end-session either returns to the suite or shows Auth's signed-out page.
  const browser=[
   {match:origin+'/oidc/authorize*',tasks:[{task:'Auth answers the authorization request',match:origin+'/*',commands:[['wait','xpath','//h1',10]]}]},
   {match:origin+'/oidc/logout*',tasks:[
    {task:'Confirm sign-out when Auth asks',optional:true,match:origin+'/oidc/logout*',commands:[['click','xpath','//button[@type="submit"]','optional']]},
    {task:'Return to the suite',optional:true,match:'*/test/*/post*'},
   ]},
  ];
  const config={alias:'auth-current',description:'Actual Auth disposable D1 profile',server:{discoveryUrl:origin+'/.well-known/openid-configuration',allow_unexpected_metadata_fields:['rer_interfaces']},browser};
  const keys=[];
  for(const name of ['client','client2']) {
   const pair=await generateKeyPair('ES256',{extractable:true});
   const publicKey={...await exportJWK(pair.publicKey),kid:name,alg:'ES256',use:'sig'};
   const privateKey={...await exportJWK(pair.privateKey),kid:name,alg:'ES256',use:'sig'};
   const id='auth-current-'+name,redirect=base+'/callback';
   config[name]={client_id:id,scope:'openid email profile',token_endpoint_auth_method:'private_key_jwt',token_endpoint_auth_signing_alg:'ES256',id_token_signed_response_alg:'RS256',jwks:{keys:[privateKey]}};
   await runtime.db.prepare('INSERT INTO auth_clients(id,name,origin,sector_id,redirect_uris,jwks,owner_person_id,source,created_at,id_token_signed_response_alg,logout_uri,post_logout_redirect_uris) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,name,suiteOrigin,'conformance-'+name,JSON.stringify([redirect]),JSON.stringify({keys:[publicKey]}),'conformance-owner','owner',Date.now(),'RS256',base+'/backchannel_logout',JSON.stringify([base+'/post_logout_redirect'])).run();
   keys.push(pair);
  }
  await writeFile(join(directory,'config.json'),JSON.stringify(config),{mode:0o600});
  const discovered=await runtime.call('/.well-known/openid-configuration');
  assert.equal(discovered.status,200);
  const metadata=await discovered.json();
  assert.deepEqual(metadata.token_endpoint_auth_methods_supported,['private_key_jwt']);
  assert.deepEqual(metadata.response_types_supported,['code']);
  const stage=await runtime.db.prepare('SELECT MAX(use_after) AS ready FROM auth_signing_keys').first();
  const wait=Math.max(0,stage.ready-Date.now()+50);
  if(wait)await new Promise(resolve=>setTimeout(resolve,wait));
  const cookie=await emailSession(runtime,'owner@conformance.example.com');
  const verifier=randomBytes(32).toString('base64url');
  const query=new URLSearchParams({client_id:config.client.client_id,redirect_uri:suiteOrigin+'/test/a/auth-current/callback',response_type:'code',scope:'openid email profile',state:'conformance-state',nonce:'conformance-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
  const authorization=await runtime.call('/oidc/authorize?'+query,{cookie});
  assert.equal(authorization.status,302);
  const code=new URL(authorization.headers.get('location')).searchParams.get('code');
  const assertion=await new SignJWT({jti:randomBytes(16).toString('hex')}).setProtectedHeader({alg:'ES256',kid:'client'}).setIssuer(config.client.client_id).setSubject(config.client.client_id).setAudience(origin+'/oidc/token').setIssuedAt().setExpirationTime('2m').sign(keys[0].privateKey);
  const token=await runtime.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',client_id:config.client.client_id,redirect_uri:suiteOrigin+'/test/a/auth-current/callback',code,code_verifier:verifier,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion}});
  assert.equal(token.status,200);
  const body=await token.json();
  assert.ok(body.id_token);assert.ok(body.access_token);assert.equal(body.refresh_token,undefined);
  const jwks=await(await runtime.call('/oidc/jwks')).json();
  const verified=await jwtVerify(body.id_token,createLocalJWKSet(jwks),{issuer:origin,audience:config.client.client_id});
  assert.equal(verified.protectedHeader.alg,'RS256');assert.deepEqual(verified.payload.amr,['dev']);
  const userinfo=await runtime.call('/oidc/userinfo',{headers:{authorization:'Bearer '+body.access_token}});assert.equal(userinfo.status,200);assert.equal((await userinfo.json()).sub,verified.payload.sub);
  await writeFile(join(directory,'preflight.json'),JSON.stringify({passed:true,issuer:origin,profile:{response_types:metadata.response_types_supported,client_auth_methods:metadata.token_endpoint_auth_methods_supported,id_token_alg:verified.protectedHeader.alg,access_token_present:true,refresh_token_present:false,amr:verified.payload.amr},userinfo_status:userinfo.status,static_clients:2,key_maturation_wait_ms:wait,identity:'real bound email request/confirmation through fake mail edge',client_provisioning:'disposable D1 fixture; owner linking remains unavailable'},null,2)+'\n',{mode:0o600});
  runtime.phase='suite';
  return {runtime,records};
 }catch(error){await runtime.close();throw error;}
}
