import {randomBytes,createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,exportPKCS8,SignJWT} from 'jose';
import {createRequire} from 'node:module';
import {inflateRawSync} from 'node:zlib';
import {selfSignedCertificate,toBase64} from '../../src/auth/saml/der.mjs';
import {ownerInstall,passkeyPerson,signInAgain,activity} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {verifyDomains} from './domain-helpers.mjs';

const parked=response=>response.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
const read=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
export async function federationFlow(t) {
 const {r,owner}=await ownerInstall(t);
 await r.person('synthetic-auth-federation-1','employee@company.example');
 await r.person('synthetic-auth-federation-2','second@company.example');
 const memberCookie=await emailSession(r,'employee@company.example');
 const admin=await passkeyPerson(r,'synthetic-auth-federation-3','admin@company.example','admin');
 const post=(action,data={},cookie=owner.cookie)=>r.call('/api/auth/federation/'+action,{method:'POST',data,cookie});
 const issuer='https://idp.company.example',keys=await generateKeyPair('RS256'),jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-federation-4',alg:'RS256',use:'sig'};
 const provider={id:'synthetic-company',preset:'oidc',issuer,clientId:'synthetic-auth-federation-5',tokenAuthMethod:'client_secret_basic',clientSecret:'synthetic-auth-federation-6',endpointPins:{authorization:issuer+'/authorize',token:issuer+'/token',jwks:issuer+'/keys'},subjectEmails:{'synthetic-auth-federation-7':'employee@company.example','synthetic-auth-federation-8':'second@company.example'}};
 r.upstream={discovery:{issuer,authorization_endpoint:provider.endpointPins.authorization,token_endpoint:provider.endpointPins.token,jwks_uri:provider.endpointPins.jwks,response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[jwk]}};
 assert.equal((await post('create',{domain:'company.example',provider,confirm:true},memberCookie)).status,403);
 assert.equal((await post('create',{domain:'company.example',provider,confirm:true},admin.cookie)).status,403);
 assert.equal((await post('create',{domain:'company.example',provider,confirm:true})).status,409,'exact domain ownership is required');
 await verifyDomains(t,r,owner.cookie,['company.example']);
 assert.equal((await post('create',{domain:'company.example',provider,confirm:false})).status,403);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,subjectEmails:{'synthetic-subject':'absent@company.example'}},confirm:true})).status,409);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,subjectEmails:{'synthetic-subject':'admin@company.example'}},confirm:true})).status,409);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,subjectEmails:{'synthetic-subject':'employee@sub.company.example'}},confirm:true})).status,403);
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,issuer:r.origin},confirm:true})).status,400);
 const created=await read(await post('create',{domain:'company.example',provider,confirm:true}),201),id=created.id;
 const stored=await r.db.prepare('SELECT sealed_config FROM auth_federation_setups WHERE id=?').bind(id).first();
 assert.ok(!stored.sealed_config.includes(provider.clientSecret));
 assert.ok(!JSON.stringify(created).includes(provider.clientSecret));
 assert.equal((await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{}})).status,404,'draft trust cannot sign in');
 assert.equal((await post('activate',{id,digest:created.digest,revision:created.revision,confirm:true})).status,409);
 const before=async()=>Promise.all(['oa_operators','oa_external_identities','auth_sessions','auth_upstream_proofs','auth_emails','oa_identity_providers'].map(async table=>(await r.db.prepare('SELECT * FROM '+table+' ORDER BY 1').all()).results));
 const snapshot=await before();
 const start=async()=>{const response=await post('test',{id,subject:'synthetic-auth-federation-7'});assert.equal(response.status,303,await response.clone().text());return {response,url:new URL(response.headers.get('location')),cookie:parked(response)};};
 const callback=async(started,subject='synthetic-auth-federation-7',cookie=owner.cookie+'; '+started.cookie)=>{
  r.upstream.tokens={id_token:await new SignJWT({sub:subject,nonce:started.url.searchParams.get('nonce'),email:'admin@company.example',email_verified:true}).setProtectedHeader({alg:'RS256',kid:jwk.kid}).setIssuer(issuer).setAudience(provider.clientId).setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
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
 const oldCookie=owner.cookie,renewed=await signInAgain(r,owner,'owner@example.com');
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
 const info=await read(await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}}));assert.equal(info.email,'employee@company.example');

 const rotated=await generateKeyPair('RS256'),nextJwk={...await exportJWK(rotated.publicKey),kid:'synthetic-auth-federation-rotated',alg:'RS256',use:'sig'};
 keys.privateKey=rotated.privateKey;Object.assign(jwk,nextJwk);r.upstream.jwks={keys:[nextJwk]};
 const rotation=await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{returnTo:'/app/account'}});assert.equal(rotation.status,303);
 assert.equal((await callback({url:new URL(rotation.headers.get('location')),cookie:parked(rotation)},'synthetic-auth-federation-7',parked(rotation))).status,303,'an unknown upstream signing key is refreshed and verified without rebinding the employee');
 assert.equal((await post('create',{domain:'company.example',provider:{id:'synthetic-hostile-metadata',preset:'saml',metadataUrl:'https://127.0.0.1/metadata',subjectEmails:{'synthetic-auth-other':'second@company.example'}},confirm:true})).status,400,'metadata cannot read a private network destination');
 assert.equal((await post('disable',{id,revision:preview.revision,confirm:true})).status,409);
 assert.equal((await post('disable',{id,revision:activated.revision,confirm:true})).status,200);
 assert.equal((await r.call('/auth/oidc/'+provider.id+'/start',{method:'POST',data:{}})).status,404);
 assert.equal((await activity(r,'federation_disabled')).length,1);
 await samlSetupFlow(r,owner,post);
 // Creation and activation both require Auth's recent local email proof.
 r.now+=10*60000+1;
 assert.equal((await post('create',{domain:'company.example',provider:{...provider,id:'synthetic-stale'},confirm:true})).status,403);
}


// The IdP is the network edge: sign its real XML response with an independent
// XML signature library, and carry only protocol fields through Auth's routes.
async function samlSetupFlow(r,owner,post) {
 const require=createRequire(import.meta.url),{SignedXml}=createRequire(require.resolve('@node-saml/node-saml'))('xml-crypto');
 const keys=await generateKeyPair('RS256',{extractable:true}),spki=new Uint8Array(await crypto.subtle.exportKey('spki',keys.publicKey));
 const certificate=toBase64(await selfSignedCertificate(keys.privateKey,spki,'synthetic-auth-federation-10',r.now-60000,r.now+86400000));
 const pem='-----BEGIN CERTIFICATE-----\n'+certificate.match(/.{1,64}/g).join('\n')+'\n-----END CERTIFICATE-----\n';
 const provider={id:'synthetic-saml',preset:'saml',issuer:'https://saml.company.example/entity',ssoUrl:'https://saml.company.example/sso',certificates:[certificate],subjectEmails:{'synthetic-auth-federation-11':'second@company.example'}};
 const setup=await read(await post('create',{domain:'company.example',provider,confirm:true}),201),id=setup.id;
 assert.equal(setup.trust.entityId,r.origin+'/federation/saml/'+provider.id);
 const start=async()=>{const response=await post('test',{id,subject:'synthetic-auth-federation-11'});assert.equal(response.status,302,await response.clone().text());const url=new URL(response.headers.get('location'));return {response,url,cookie:parked(response),request:inflateRawSync(Buffer.from(url.searchParams.get('SAMLRequest'),'base64')).toString('utf8'),relay:url.searchParams.get('RelayState')};};
 const signed=async(started,{audience=setup.trust.entityId,subject='synthetic-auth-federation-11',requestId=started.request.match(/ ID="([^"]+)"/)[1],destination=setup.callback,expiry=r.now+120000}={})=>{
  const now=new Date(r.now).toISOString(),until=new Date(expiry).toISOString(),tag='_'+crypto.randomUUID().replaceAll('-','');
  const xml=`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${tag}" Version="2.0" IssueInstant="${now}" Destination="${destination}" InResponseTo="${requestId}"><saml:Issuer>${provider.issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="${tag}_assertion" Version="2.0" IssueInstant="${now}"><saml:Issuer>${provider.issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${subject}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="${setup.callback}" InResponseTo="${requestId}" NotOnOrAfter="${until}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="${until}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${now}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;
  const signer=new SignedXml({privateKey:await exportPKCS8(keys.privateKey),publicCert:pem,signatureAlgorithm:'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',canonicalizationAlgorithm:'http://www.w3.org/2001/10/xml-exc-c14n#'});
  signer.addReference({xpath:"/*[local-name()='Response']",transforms:['http://www.w3.org/2000/09/xmldsig#enveloped-signature','http://www.w3.org/2001/10/xml-exc-c14n#'],digestAlgorithm:'http://www.w3.org/2001/04/xmlenc#sha256'});
  signer.computeSignature(xml,{prefix:'ds',location:{reference:"/*[local-name()='Response']/*[local-name()='Issuer']",action:'after'}});
  return Buffer.from(signer.getSignedXml()).toString('base64');
 };
 const send=async(started,options)=>r.call('/auth/saml/'+provider.id+'/callback',{method:'POST',form:{RelayState:started.relay,SAMLResponse:await signed(started,options)},cookie:started.response.headers.getSetCookie().find(value=>value.startsWith('__Host-auth_federation_'+started.relay+'='))?.split(';')[0],headers:{origin:'https://saml.company.example'}});
 const metadata=await r.call('/auth/saml/'+provider.id+'/metadata?setup='+id,{cookie:owner.cookie});assert.equal(metadata.status,200);assert.ok((await metadata.text()).includes(setup.callback));
 for(const options of [{audience:'https://wrong.example/entity'},{requestId:'_synthetic_wrong_request'},{subject:'synthetic-unreviewed-subject'},{expiry:r.now-120000}]) {
  const transaction=await start();assert.equal((await send(transaction,options)).status,options.expiry?400:403);
 }
 const transaction=await start(),counts=async()=>Promise.all(['auth_sessions','auth_upstream_proofs','oa_external_identities','auth_emails'].map(async table=>(await r.db.prepare('SELECT * FROM '+table+' ORDER BY 1').all()).results)),snapshot=await counts();
 const posted=await send(transaction);assert.equal(posted.status,303,await posted.clone().text());
 const resume=posted.headers.get('location');
 assert.equal((await r.call(resume,{cookie:transaction.cookie})).status,401,'cross-site SAML POST cannot admit without the initiating owner on GET');
 const done=await r.call(resume,{cookie:owner.cookie+'; '+transaction.cookie});assert.equal(done.status,303,await done.clone().text());
 assert.deepEqual(await counts(),snapshot,'SAML representative test creates no account, proof or session');
 assert.equal((await r.call(resume,{cookie:owner.cookie+'; '+transaction.cookie})).status,403);
 assert.equal((await send(transaction)).status,404);
 const preview=await read(await post('preview',{id})),active=await read(await post('activate',{id,digest:preview.digest,revision:preview.revision,confirm:true}));
 assert.equal(active.state,'active');
 assert.equal((await post('disable',{id,revision:active.revision,confirm:true})).status,200);
}
