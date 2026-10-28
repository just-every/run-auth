import {randomBytes,createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {samlCredential,samlSigner,samlRequest} from './federation-saml-peer.mjs';
import {ownerInstall,passkeyPerson,signInAgain,activity} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {verifyDomains} from './domain-helpers.mjs';

const address=(name,domain='company.example')=>[name,domain].join('@');
const parked=response=>response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
const read=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
export async function federationFlow(t) {
 const {r,owner}=await ownerInstall(t);
 await r.person('synthetic-auth-federation-1',address('employee','company.example'));
 await r.person('synthetic-auth-federation-2',address('second','company.example'));
 const memberCookie=await emailSession(r,address('employee','company.example'));
 const admin=await passkeyPerson(r,'synthetic-auth-federation-3',address('admin','company.example'),'admin');
 const post=(action,data={},cookie=owner.cookie)=>r.call('/api/auth/federation/'+action,{method:'POST',data,cookie});
 const issuer='https://idp.company.example',keys=await generateKeyPair('RS256'),jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-federation-4',alg:'RS256',use:'sig'};
 const provider={id:'synthetic-company',preset:'oidc',issuer,clientId:'synthetic-auth-federation-5',tokenAuthMethod:'client_secret_basic',clientSecret:'synthetic-auth-federation-6',endpointPins:{authorization:issuer+'/authorize',token:issuer+'/token',jwks:issuer+'/keys'},subjectEmails:{'synthetic-auth-federation-7':address('employee','company.example'),'synthetic-auth-federation-8':address('second','company.example')}};
 r.upstream={discovery:{issuer,authorization_endpoint:provider.endpointPins.authorization,token_endpoint:provider.endpointPins.token,jwks_uri:provider.endpointPins.jwks,response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[jwk]}};
 assert.equal((await post('create',{domain:'company.example',provider,confirm:true},memberCookie)).status,403);
 assert.equal((await post('create',{domain:'company.example',provider,confirm:true},admin.cookie)).status,403);
 assert.equal((await post('create',{domain:'company.example',provider,confirm:true})).status,409,'exact domain ownership is required');
 await verifyDomains(t,r,owner.cookie,['company.example']);
 assert.equal((await post('create',{domain:'company.example',provider,confirm:false})).status,403);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,subjectEmails:{'synthetic-subject':address('absent','company.example')}},confirm:true})).status,409);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,subjectEmails:{'synthetic-subject':address('admin','company.example')}},confirm:true})).status,409);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,subjectEmails:{'synthetic-subject':address('employee','sub.company.example')}},confirm:true})).status,403);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,issuer:r.origin},confirm:true})).status,400);
 const created=await read(await post('create',{domain:'company.example',provider,confirm:true}),201),id=created.id;
 const stored=await r.db.prepare('SELECT sealed_config FROM auth_federation_setups WHERE id=?').bind(id).first();
 assert.ok(!stored.sealed_config.includes(provider.clientSecret));
 assert.ok(!JSON.stringify(created).includes(provider.clientSecret));
 assert.equal((await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{}})).status,404,'draft trust cannot sign in');
 assert.equal((await post('activate',{id,digest:created.digest,revision:created.revision,confirm:true})).status,409);
 const before=async()=>Promise.all(['oa_operators','oa_external_identities','auth_sessions','auth_upstream_proofs','auth_emails','oa_identity_providers'].map(async table=>(await r.db.prepare('SELECT * FROM '+table+' ORDER BY 1').all()).results));
 const snapshot=await before();
 const start=async()=>{const response=await r.call('/api/auth/federation/test',{method:'POST',cookie:owner.cookie,headers:{accept:'application/json'},data:{id,subject:'synthetic-auth-federation-7'}});const started=await read(response);return {response,url:new URL(started.redirect),cookie:parked(response)};};
 const callback=async(started,subject='synthetic-auth-federation-7',cookie=owner.cookie+'; '+started.cookie)=>{
  r.upstream.tokens={id_token:await new SignJWT({sub:subject,nonce:started.url.searchParams.get('nonce'),email:address('admin','company.example'),email_verified:true}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(issuer).setAudience(provider.clientId).setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
  return r.call('/auth/oidc/'+provider.id+'/callback?'+new URLSearchParams({state:started.url.searchParams.get('state'),code:'synthetic-auth-federation-9',iss:issuer}),{cookie});
 };
 const initial=await start();
 assert.equal((await callback(initial,'synthetic-auth-federation-7',initial.cookie)).status,401,'the setup cookie supplies no owner session');
 assert.equal((await callback(initial,'synthetic-auth-federation-7',owner.cookie)).status,404,'the owner session supplies no setup binding');
 const completed=await callback(initial);assert.equal(completed.status,303,await completed.clone().text());
 assert.ok(!completed.headers.getSetCookie().some(value=>/^__Host-auth_session(?:_|=)/.test(value)));
 assert.equal((await callback(initial)).status,403,'a completed setup test cannot replay');
 assert.deepEqual(await before(),snapshot,'the representative test never mutates account/proof/session/active pin state');
 let preview=await read(await post('preview',{id}));assert.equal(preview.state,'tested');assert.equal(preview.testedSubject,'synthetic-auth-federation-7');
 assert.equal((await post('activate',{id,digest:preview.digest,revision:preview.revision,confirm:false})).status,403);
 assert.equal((await post('activate',{id,digest:created.digest,revision:created.revision,confirm:true})).status,409);
 const wrong=await start();assert.equal((await callback(wrong,'synthetic-auth-federation-8')).status,403,'a different reviewed subject cannot substitute for the requested representative');
 const valid=await start();assert.equal((await callback(valid)).status,303);
 preview=await read(await post('preview',{id}));
 const oldCookie=owner.cookie,renewed=await signInAgain(r,owner,address('owner','example.com'));
 const tied=await start();
 assert.equal((await callback(tied,'synthetic-auth-federation-7',renewed.cookie+'; '+tied.cookie)).status,403,'another live session of the same owner cannot complete this test');
 assert.equal((await callback(tied,'synthetic-auth-federation-7',oldCookie+'; '+tied.cookie)).status,303);
 preview=await read(await post('preview',{id}));
 const activated=await read(await post('activate',{id,digest:preview.digest,revision:preview.revision,confirm:true}));assert.equal(activated.state,'active');
 assert.equal((await activity(r,'federation_activated')).length,1);
 const active=await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{returnTo:'/app/account'}});assert.equal(active.status,303,await active.clone().text());
 const activeState={url:new URL(active.headers.get('location')),cookie:parked(active)};
 assert.equal((await callback(activeState,'synthetic-unreviewed-subject',activeState.cookie)).status,403,'a verified email claim cannot admit an unreviewed subject');
 const allowed=await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{returnTo:'/app/account'}});assert.equal(allowed.status,303);
 const admitted=await callback({url:new URL(allowed.headers.get('location')),cookie:parked(allowed)},'synthetic-auth-federation-7',parked(allowed));assert.equal(admitted.status,303,await admitted.clone().text());
 const employee=admitted.headers.getSetCookie().find(value=>value.startsWith('__Host-auth_session='))?.split(';')[0];assert.ok(employee);
 assert.equal((await read(await r.call('/api/auth/me',{cookie:employee}))).user.id,'synthetic-auth-federation-1');
 const app=await read(await r.call('/api/auth/oidc-apps/create',{method:'POST',cookie:owner.cookie,data:{name:'Assigned expenses',authMethod:'client_secret_basic',redirectUris:'https://rp.example.com/callback',requirePkce:true}}),201);
 assert.equal((await r.call('/api/auth/company-apps/assign',{method:'POST',cookie:owner.cookie,data:{appId:app.id,principalType:'person',principalId:'synthetic-auth-federation-1',role:'employee'}})).status,200);
 await r.call('/.well-known/openid-configuration');r.now=Math.max(r.now,(await r.db.prepare('SELECT MAX(use_after) AS at FROM auth_signing_keys').first()).at+1);
 const verifier=randomBytes(32).toString('base64url'),query=new URLSearchParams({client_id:app.clientId,redirect_uri:'https://rp.example.com/callback',response_type:'code',scope:'openid email',state:'synthetic-auth-app-state',nonce:'synthetic-auth-app-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',prompt:'none'});
 const authorized=await r.call('/oidc/authorize?'+query,{cookie:employee});assert.equal(authorized.status,302);
 const code=new URL(authorized.headers.get('location')).searchParams.get('code');assert.ok(code,'the upstream-authenticated worker reaches the assigned downstream app');
 const tokens=await read(await r.call('/oidc/token',{method:'POST',headers:{authorization:'Basic '+Buffer.from(app.clientId+':'+app.clientSecret).toString('base64')},form:{grant_type:'authorization_code',code,code_verifier:verifier,redirect_uri:'https://rp.example.com/callback'}}));
 const info=await read(await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}}));assert.equal(info.email,address('employee','company.example'));

 const rotated=await generateKeyPair('RS256'),nextJwk={...await exportJWK(rotated.publicKey),kid:'synthetic-auth-federation-rotated',alg:'RS256',use:'sig'};
 keys.privateKey=rotated.privateKey;Object.assign(jwk,nextJwk);r.upstream.jwks={keys:[nextJwk]};
 const rotation=await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{returnTo:'/app/account'}});assert.equal(rotation.status,303);
 assert.equal((await callback({url:new URL(rotation.headers.get('location')),cookie:parked(rotation)},'synthetic-auth-federation-7',parked(rotation))).status,303,'an unknown upstream signing key is refreshed and verified without rebinding the employee');
 assert.equal((await post('create',{domain:'company.example',provider:{id:'synthetic-hostile-metadata',preset:'saml',metadataUrl:'https://127.0.0.1/metadata',subjectEmails:{'synthetic-auth-other':address('second','company.example')}},confirm:true})).status,400,'metadata cannot read a private network destination');
 assert.equal((await post('disable',{id,revision:preview.revision,confirm:true})).status,409);
 assert.equal((await post('disable',{id,revision:activated.revision,confirm:true})).status,200);
 assert.equal((await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{}})).status,404);
 assert.equal((await activity(r,'federation_disabled')).length,1);
 await samlSetupFlow(r,owner,post);
 // Creation and activation both require Auth's recent local email proof.
 r.now+=10*60000+1;
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,id:'synthetic-stale'},confirm:true})).status,403);
}


// Keep rotation inside the existing delegated setup sanity journey.
async function samlSetupFlow(r,owner,post) {
 const subject='synthetic-auth-federation-11',personId='synthetic-auth-federation-2';
 await emailSession(r,address('second'));
 const old=await samlCredential(r.now,'synthetic-auth-310'),next=await samlCredential(r.now,'synthetic-auth-311'),expired=await samlCredential(r.now,'synthetic-auth-312',{expired:true}),unapproved=await samlCredential(r.now,'synthetic-auth-313');
 const provider={id:'synthetic-saml',preset:'saml',issuer:'https://saml.company.example/entity',ssoUrl:'https://saml.company.example/sso',certificates:[old.certificate,next.certificate,expired.certificate],subjectEmails:{[subject]:address('second')}};
 let setup=await read(await post('create',{domain:'company.example',provider,confirm:true}),201);
 assert.equal(setup.trust.entityId,r.origin+'/federation/saml/'+provider.id);
 const counts=async()=>Promise.all(['oa_operators','auth_sessions','auth_upstream_proofs','oa_external_identities','auth_emails','auth_grants','auth_oidc_codes','auth_oidc_sessions'].map(async table=>(await r.db.prepare('SELECT * FROM '+table+' ORDER BY 1').all()).results));
 const begin=async(representative=false)=>{
  const response=representative?await post('test',{id:setup.id,subject}):await r.call('/auth/saml/'+provider.id+'/start',{method:'POST',data:{returnTo:'/app/account'}});
  assert.equal(response.status,302,await response.clone().text());
  const url=new URL(response.headers.get('location'));return {response,url,cookie:parked(response),...samlRequest(url)};
 };
 const signed=(started,credential=old,options={})=>samlSigner({issuer:provider.issuer,entityId:setup.trust.entityId,callback:setup.callback,credential,now:()=>r.now})(started,{subject,...options});
 const send=(started,body)=>r.call('/auth/saml/'+provider.id+'/callback',{method:'POST',form:{RelayState:started.relay,SAMLResponse:body},cookie:started.response.headers.getSetCookie().find(value=>value.startsWith('__Host-auth_federation_'+started.relay+'='))?.split(';')[0],headers:{origin:'https://saml.company.example'}});
 const resume=(response,started,representative=false)=>r.call(response.headers.get('location'),{cookie:(representative?owner.cookie+'; ':'')+started.cookie});
 const unchanged=async(action,status,label)=>{const before=await counts(),response=await action();assert.equal(response.status,status,await response.clone().text());assert.deepEqual(await counts(),before,label);assert.ok(!response.headers.getSetCookie().some(value=>value.startsWith('__Host-auth_session=')));return response;};
 const metadata=await r.call('/auth/saml/'+provider.id+'/metadata?setup='+setup.id,{cookie:owner.cookie});assert.equal(metadata.status,200);assert.ok((await metadata.text()).includes(setup.callback));
 for(const options of [{audience:'https://wrong.example/entity'},{requestId:'_synthetic_wrong_request'},{subject:'synthetic-unreviewed-subject'},{expiry:r.now-120000}]) {
  const transaction=await begin(true);await unchanged(async()=>send(transaction,await signed(transaction,old,options)),options.expiry?400:403,'invalid representative proof grants nothing');
 }
 const representative=async credential=>{
  const transaction=await begin(true),snapshot=await counts(),body=await signed(transaction,credential),posted=await send(transaction,body);
  assert.equal(posted.status,303,await posted.clone().text());
  await unchanged(()=>r.call(posted.headers.get('location'),{cookie:transaction.cookie}),401,'the owner session is still required');
  const done=await resume(posted,transaction,true);assert.equal(done.status,303,await done.clone().text());
  assert.deepEqual(await counts(),snapshot,'representative testing creates no employee session, binding or downstream grant');
  await unchanged(()=>resume(posted,transaction,true),403,'representative resume cannot replay');
  const replay=await send(transaction,body);assert.equal(replay.status,404);
  return read(await post('preview',{id:setup.id}));
 };
 const stale=await representative(old),preview=await representative(next);
 assert.deepEqual(preview.people,stale.people,'both certificates retain the same exact reviewed map');
 await unchanged(()=>post('activate',{id:setup.id,digest:stale.digest,revision:stale.revision,confirm:true}),409,'stale review cannot activate');
 // The existing D1 fault edge withdraws only the initiating owner's email proof
 // after preflight and before the guarded activation statement.
 const setupBefore=await r.db.prepare('SELECT * FROM auth_federation_setups WHERE id=?').bind(setup.id).first();
 for(const sql of ["UPDATE auth_sessions SET local_email_verified_at=0 WHERE person_id='owner'", "UPDATE auth_sessions SET amr=json_array('email') WHERE person_id='owner'", "UPDATE auth_sessions SET revoked_at=1 WHERE person_id='owner'"]) {
  const beforeLoss=await counts();
  const lost=await r.call('/api/auth/federation/activate',{method:'POST',cookie:owner.cookie,data:{id:setup.id,digest:preview.digest,revision:preview.revision,confirm:true},factorRace:sql});
  assert.equal(lost.status,403,await lost.clone().text());
  assert.deepEqual((await counts()).map((rows,i)=>i===1?rows.filter(row=>row.person_id!=='owner'):rows),beforeLoss.map((rows,i)=>i===1?rows.filter(row=>row.person_id!=='owner'):rows),'lost authority cannot admit an employee');
  assert.deepEqual(await r.db.prepare('SELECT * FROM auth_federation_setups WHERE id=?').bind(setup.id).first(),setupBefore,'lost authority leaves trust unchanged');
  Object.assign(owner,await signInAgain(r,owner,address('owner','example.com')));
 }

 const active=await read(await post('activate',{id:setup.id,digest:preview.digest,revision:preview.revision,confirm:true}));assert.equal(active.state,'active');
 await r.restart();
 const app=await read(await r.call('/api/auth/oidc-apps/create',{method:'POST',cookie:owner.cookie,data:{name:'Rotating upstream app',authMethod:'client_secret_basic',redirectUris:'https://rotation.example.test/callback',requirePkce:true}}),201);
 assert.equal((await r.call('/api/auth/company-apps/assign',{method:'POST',cookie:owner.cookie,data:{appId:app.id,principalType:'person',principalId:personId,role:'employee'}})).status,200);
 const launch=async credential=>{
  const transaction=await begin(),body=await signed(transaction,credential),posted=await send(transaction,body);assert.equal(posted.status,303,await posted.clone().text());
  const admitted=await resume(posted,transaction);assert.equal(admitted.status,303,await admitted.clone().text());
  const employee=admitted.headers.getSetCookie().find(value=>value.startsWith('__Host-auth_session='))?.split(';')[0];assert.ok(employee);
  const who=await read(await r.call('/api/auth/me',{cookie:employee}));assert.equal(who.user.id,personId);assert.equal(who.user.role,'member');
  const verifier=randomBytes(32).toString('base64url'),query=new URLSearchParams({client_id:app.clientId,redirect_uri:'https://rotation.example.test/callback',response_type:'code',scope:'openid email',state:'synthetic-auth-314',nonce:'synthetic-auth-315',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',prompt:'none'});
  const authorized=await r.call('/oidc/authorize?'+query,{cookie:employee});assert.equal(authorized.status,302);
  const code=new URL(authorized.headers.get('location')).searchParams.get('code');assert.ok(code);
  const tokens=await read(await r.call('/oidc/token',{method:'POST',headers:{authorization:'Basic '+Buffer.from(app.clientId+':'+app.clientSecret).toString('base64')},form:{grant_type:'authorization_code',code,code_verifier:verifier,redirect_uri:'https://rotation.example.test/callback'}}));
  const info=await read(await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}}));assert.equal(info.email,address('second'));
  await unchanged(()=>send(transaction,body),403,'replayed response cannot create another session or grant');
  await unchanged(()=>resume(posted,transaction),403,'replayed resume cannot create another session or grant');
 };
 await launch(old);await launch(next);
 for(const credential of [expired,unapproved]){
  const transaction=await begin();await unchanged(async()=>send(transaction,await signed(transaction,credential)),403,'expired or unapproved signing certificate cannot admit an employee');
 }
 const pending=await begin(),pendingBody=await signed(pending,old),verified=await begin(),verifiedPost=await send(verified,await signed(verified,next));assert.equal(verifiedPost.status,303);
 assert.equal((await post('disable',{id:setup.id,revision:active.revision,confirm:true})).status,200);
 await unchanged(()=>send(pending,pendingBody),404,'disabled setup refuses its unfinished callback');
 await unchanged(()=>resume(verifiedPost,verified),404,'disabled setup refuses a previously verified response');
 assert.equal((await r.call('/auth/saml/'+provider.id+'/start',{method:'POST',data:{}})).status,404);
 // Replacement is a new explicitly tested and approved setup, never an edit of
 // the active trust. Keep the exact subject map and retire the old certificate.
 setup=await read(await post('create',{domain:'company.example',provider:{...provider,certificates:[next.certificate]},confirm:true}),201);
 const replacement=await representative(next);assert.deepEqual(replacement.people,preview.people);
 assert.deepEqual(replacement.trust.certificates,[next.certificate]);
 const renewed=await read(await post('activate',{id:setup.id,digest:replacement.digest,revision:replacement.revision,confirm:true}));
 await r.restart();
 await unchanged(()=>send(pending,pendingBody),403,'replacement refuses callbacks correlated under the old configuration');
 await unchanged(()=>resume(verifiedPost,verified),403,'replacement refuses a verified principal parked under the old trust');
 const retired=await begin();await unchanged(async()=>send(retired,await signed(retired,old)),403,'fresh messages signed by the retired certificate cannot admit an employee');
 await launch(next);
 assert.equal((await post('disable',{id:setup.id,revision:renewed.revision,confirm:true})).status,200);
}
