import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {generateKeyPair,exportJWK,SignJWT,createLocalJWKSet,jwtVerify} from 'jose';
import {createResourceAuthorizer} from '../../packages/delegated-resource/index.mjs';
import {ownerInstall,passkeyPerson,signInAgain,post} from './agents-helpers.mjs';

export async function externalDelegationFlow(t) {
 const {r,owner:initialOwner}=await ownerInstall(t);r.now=Date.now();
 const owner=await signInAgain(r,initialOwner,'owner@example.com');
 const worker=await passkeyPerson(r,'worker','worker@example.com','member'),other=await passkeyPerson(r,'other','other@example.com','member');
 const reviewer=await passkeyPerson(r,'reviewer','reviewer@example.com','member');
 const json=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
 const command=(path,data,cookie=owner.cookie)=>r.call('/api/auth/'+path,post(data,cookie));
 await json(await command('people/role',{personId:'reviewer',role:'admin'}));
 const approver=await signInAgain(r,reviewer,'reviewer@example.com');
 const keys=await generateKeyPair('ES256'),resourceKeys=await generateKeyPair('ES256'),foreign=await generateKeyPair('ES256');
 const jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-61',alg:'ES256',use:'sig'},resourceJwk={...await exportJWK(resourceKeys.publicKey),kid:'synthetic-auth-62',alg:'ES256',use:'sig'};
 const hash=value=>createHash('sha256').update(value).digest('base64url');
 const assertion=(clientId,audience,claims)=>new SignJWT(claims).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(clientId).setSubject(clientId).setAudience(audience).setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).setJti(randomUUID()).sign(keys.privateKey);
 const refuse=async(response,label)=>{assert.ok([400,401,403,409].includes(response.status),label+': '+response.status+' '+await response.clone().text());assert.equal(typeof (await response.json()).error,'string');};
 const nonces=new Map();
 const proof=(url,token,{privateKey=keys.privateKey,publicKey=jwk,...claims}={})=>new SignJWT({htm:'POST',htu:url,iat:Math.floor(r.now/1000),...(nonces.has(url)?{nonce:nonces.get(url)}:{}),...(token?{ath:hash(token)}:{}),...claims}).setProtectedHeader({typ:'dpop+jwt',alg:'ES256',jwk:publicKey}).setJti(randomUUID()).sign(privateKey);
 const consent=async(grant,who=worker)=>{
  const response=await command('delegations/consent/options',{grantId:grant.grantId,effectDigest:grant.effectDigest},who.cookie);
  if(response.status!==200)return response;
  const options=await json(response);
  return command('delegations/consent',{grantId:grant.grantId,effectDigest:grant.effectDigest,decision:'consent',transaction:options.transaction,response:who.key.authenticate(options.options)},who.cookie+'; '+response.headers.get('set-cookie').split(';')[0]);
 };
 const approve=async(grant,who=approver)=>{
  const response=await command('delegations/approval/options',{grantId:grant.grantId,effectDigest:grant.effectDigest},who.cookie);
  if(response.status!==200)return response;
  const options=await json(response);
  return command('delegations/approve',{grantId:grant.grantId,effectDigest:grant.effectDigest,transaction:options.transaction,response:who.key.authenticate(options.options)},who.cookie+'; '+response.headers.get('set-cookie').split(';')[0]);
 };
 for(const kind of ['mcp','api']) {
  const resource=await json(await command('delegations/resources/register',{name:kind==='mcp'?'Expense MCP server':'Expenses API',kind,audience:`https://${kind}.example.com/tasks`,scopes:['expenses.update'],detailType:kind==='mcp'?'mcp_tool_task':'expense_task',operations:kind==='mcp'?['update_expense','delete_expense']:['expense.update','expense.delete'],jwks:{keys:[resourceJwk]}}),201);
  const agent=await json(await command('delegations/agents/register',{name:'Expense assistant',purpose:'One reviewed expense update',jwks:{keys:[jwk]},appIds:[],resourceIds:[resource.id],personIds:['worker'],expiresAt:r.now+86400000}),201);
  const operation=resource.operations[0];
  const task=(change={})=>({organizationId:'root',accountablePersonId:'worker',personId:'worker',purpose:'Update the category of my expense',apiId:resource.id,resourceId:resource.id,detailType:resource.detailType,audience:resource.audience,resource:'expense:synthetic-auth-1',operation,scopes:['expenses.update'],expiresAt:r.now+3600000,arguments:{category:'Travel'},...change});
  const request=async effect=>r.call('/api/auth/delegations/request',post({clientId:agent.clientId,clientAssertion:await assertion(agent.clientId,r.origin+'/api/auth/delegations/request',{delegation_use:'request',request_hash:hash(JSON.stringify(effect))}),task:effect}));
  const oauth=async(grant,effect,{scope=effect.scopes.join(' '),audience=effect.audience}={})=>{
   const url=r.origin+'/oidc/token',signed=await assertion(agent.clientId,url,{delegation_use:'token',grant_id:grant.grantId,effect_digest:grant.effectDigest});
   const send=async()=>r.call('/oidc/token',{method:'POST',headers:{DPoP:await proof(url)},form:{grant_type:'client_credentials',client_id:agent.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:signed,grant_id:grant.grantId,scope,resource:audience}});
   let response=await send();if(response.headers.has('dpop-nonce')){nonces.set(url,response.headers.get('dpop-nonce'));response=await send();}return response;
  };
  const approved=async(effect=task())=>{const grant=await json(await request(effect),201);await json(await consent(grant));await json(await approve(grant));return {...grant,task:effect};};
  await refuse(await request(task({audience:'https://unregistered.example.com/tasks'})),'unregistered audience');
  await refuse(await request(task({operation:'administer_all'})),'unpublished operation');
  await refuse(await request(task({scopes:['expenses.admin']})),'unpublished scope');
  await refuse(await request(task({detailType:'auth_assignment_task'})),'native detail profile');
  await refuse(await request(task({personId:'other',accountablePersonId:'other'})),'another accountable person');
  const grant=await json(await request(task()),201);grant.task=task();
  await refuse(await oauth(grant,grant.task),'unconsented request');
  await refuse(await consent(grant,other),'another person consent');
  await json(await consent(grant));
  await refuse(await oauth(grant,grant.task),'unapproved task');
  await refuse(await approve(grant,owner),'custodian approval');
  await json(await approve(grant));
  await refuse(await oauth(grant,grant.task,{audience:'https://unregistered.example.com/tasks'}),'unregistered token audience');
  await refuse(await oauth(grant,grant.task,{scope:'expenses.admin'}),'excess token scope');
  const token=(await json(await oauth(grant,grant.task))).access_token;
  const {payload:claims}=await jwtVerify(token,createLocalJWKSet(await json(await r.call('/oidc/jwks'))),{issuer:r.origin,audience:resource.audience,currentDate:new Date(r.now)});
  assert.equal(claims.delegation_profile,'auth-external-task-v1');assert.equal(claims.sub,'worker');assert.equal(claims.act.sub,'agent:'+agent.id);assert.equal(claims.authorization_details[0].type,resource.detailType);assert.ok(claims.cnf.jkt);assert.equal(claims.scope,'expenses.update');
  const actual=[];
  const authorize=createResourceAuthorizer({issuer:r.origin,resourceId:resource.id,clientId:resource.clientId,audience:resource.audience,privateKey:resourceKeys.privateKey,kid:resourceJwk.kid,fetch:async(url,init)=>r.call(new URL(url).pathname,{method:init.method,headers:init.headers,data:JSON.parse(init.body)})});
  // An independent HTTP resource parses the concrete MCP tools/call or API
  // operation, then calls the real Auth HTTP door through the resource SDK.
  const server=createServer(async(req,res)=>{try{
   let raw='';for await(const chunk of req)raw+=chunk;
   const incoming=JSON.parse(raw),body=incoming.body;
   const expected=kind==='mcp'?{personId:body.personId,resource:body.resource,operation:body.params.name,arguments:body.params.arguments}:{personId:body.personId,resource:body.resource,operation:body.operation,arguments:body.arguments};
   if(kind==='mcp')assert.equal(body.method,'tools/call');
   const result=await authorize(new Request(resource.audience,{method:'POST',headers:req.headers}),{...incoming.envelope,expected});
   let response;if(result.ok){actual.push(expected);response=Response.json({executed:true,personId:expected.personId,operation:expected.operation});}else response=result.response;
   res.writeHead(response.status,Object.fromEntries(response.headers));res.end(await response.text());
  }catch(error){res.writeHead(500);res.end(String(error));}});
  server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(done=>server.close(done)));
  const endpoint=`http://127.0.0.1:${server.address().port}`;
  const invoke=async(g,bearer,{change={},signed,scheme='DPoP',envelope=g}={})=>{
   const expected={personId:g.task.personId,resource:g.task.resource,operation:g.task.operation,arguments:g.task.arguments,...change};
   const body=kind==='mcp'?{method:'tools/call',personId:expected.personId,resource:expected.resource,params:{name:expected.operation,arguments:expected.arguments}}:expected;
   const send=async header=>fetch(endpoint,{method:'POST',headers:{authorization:scheme+' '+bearer,DPoP:header,'content-type':'application/json'},body:JSON.stringify({envelope,body})});
   let response=await send(signed??await proof(resource.audience,bearer));
   if(signed===undefined&&response.headers.has('dpop-nonce')){nonces.set(resource.audience,response.headers.get('dpop-nonce'));await response.body.cancel();response=await send(await proof(resource.audience,bearer));}return response;
  };
  for(const [label,change] of [['another tool or operation',{operation:resource.operations[1]}],['another person',{personId:'other'}],['another resource',{resource:'expense:synthetic-auth-2'}],['changed arguments',{arguments:{category:'Payroll'}}]])await refuse(await invoke(grant,token,{change}),label);
  await refuse(await invoke(grant,token,{scheme:'Bearer'}),'bearer token');
  await refuse(await invoke(grant,token,{signed:await proof(resource.audience,token,{privateKey:foreign.privateKey,publicKey:await exportJWK(foreign.publicKey)})}),'wrong sender');
  assert.equal(actual.length,0,'all denied requests execute nothing');
  const nonceChallenge=await invoke(grant,token,{signed:await proof(resource.audience,token)});
  assert.equal(nonceChallenge.status,401);assert.equal((await nonceChallenge.json()).error,'use_dpop_nonce');nonces.set(resource.audience,nonceChallenge.headers.get('dpop-nonce'));
  const replayProof=await proof(resource.audience,token);
  const concurrent=await Promise.all([invoke(grant,token,{signed:replayProof}),invoke(grant,token,{signed:await proof(resource.audience,token)})]);
  assert.equal(concurrent.filter(response=>response.status===200).length,1,'one operation across concurrent resource requests: '+JSON.stringify(await Promise.all(concurrent.map(async response=>({status:response.status,body:await response.clone().text()})))));
  assert.equal(actual.length,1);assert.deepEqual(actual[0],{personId:'worker',resource:grant.task.resource,operation,arguments:grant.task.arguments});
  await refuse(await invoke(grant,token,{signed:replayProof}),'proof replay');
  await refuse(await invoke(grant,token),'consumed task with fresh proof');
  await refuse(await oauth(grant,grant.task),'consumed task cannot issue another token');
  const revocable=await approved(),revocableToken=(await json(await oauth(revocable,revocable.task))).access_token;
  const inventory=await json(await r.call('/api/auth/delegations',{cookie:worker.cookie}));
  const shown=inventory.grants.find(row=>row.grantId===revocable.grantId);assert.equal(shown.appName,resource.name);assert.equal(shown.authorityCurrent,true);
  assert.equal((await json(await r.call('/api/auth/delegations',{cookie:other.cookie}))).grants.length,0);
  await refuse(await command('delegations/revoke',{grantId:revocable.grantId},other.cookie),'foreign revoke');
  await json(await command('delegations/revoke',{grantId:revocable.grantId},worker.cookie));
  await refuse(await invoke(revocable,revocableToken),'My account next call refusal');
  const expiring=await approved(task({expiresAt:r.now+10000})),expiringToken=(await json(await oauth(expiring,expiring.task))).access_token;
  r.now+=10001;await refuse(await invoke(expiring,expiringToken),'expired grant');
  const disabled=await approved(),disabledToken=(await json(await oauth(disabled,disabled.task))).access_token;
  await json(await command('delegations/resources/disable',{resourceId:resource.id}));
  await refuse(await invoke(disabled,disabledToken),'disabled resource');await refuse(await oauth(disabled,disabled.task),'disabled resource token');
  assert.equal(actual.length,1,'revocation, expiry and disabling cause no remote operation');
  const audit=await json(await r.call('/api/auth/activity',{cookie:owner.cookie}));
  const receipt=audit.find(row=>row.event==='delegation_resource_released'&&row.subject_id===grant.grantId);assert.ok(receipt);assert.equal(JSON.parse(receipt.detail).remoteOutcome,'unknown');
  for(const secret of [token,revocableToken,expiringToken,disabledToken])assert.ok(!JSON.stringify(audit).includes(secret),'no access token in audit');
  await new Promise(done=>server.close(done));
 }
 await json(await command('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true}));
 const preview=await json(await command('erasure/preview',{kind:'person',target:'worker'}));
 assert.ok(preview.stores.find(row=>row.store==='auth_external_tasks').deleted>0);
 const erased=await json(await command('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',destinations:[]}));assert.equal(erased.local,'complete');
 assert.equal((await r.call('/api/auth/me',{cookie:worker.cookie})).status,401);
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM auth_external_tasks WHERE accountable_id='worker'").first()).n,0,'immutable external effects are erased');
 assert.ok(!JSON.stringify(await json(await r.call('/api/auth/activity',{cookie:owner.cookie}))).includes('worker@example.com'),'audit is anonymized');
}
