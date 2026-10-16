import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createVerify} from 'node:crypto';
import {signXml} from '@node-saml/node-saml/lib/xml.js';
import {emailSession} from './runtime.mjs';
import {samlInstall,spCredentials,idpCertificates,serviceProvider,metadataOf,addApp,signIn,posted,browse,field,inflate,xmlOf} from './saml-helpers.mjs';

const FORMAT={persistent:'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',emailAddress:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',unspecified:'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',transient:'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'};

test('an assigned employee signs in to a SAML app over both request bindings, with each NameID format, signature placement and algorithm',async t=>{
 const r=await samlInstall(t),idpCerts=await idpCertificates(r),sp=await spCredentials('sp.example.com');
 const cases=[['persistent','response','sha256','HTTP-Redirect'],['emailAddress','assertion','sha512','HTTP-POST'],['unspecified','both','sha256','HTTP-POST'],['transient','both','sha512','HTTP-Redirect'],['persistent','response','sha512','HTTP-POST'],['emailAddress','assertion','sha256','HTTP-Redirect']];
 const seen={};
 for(const [i,[format,sign,digest,binding]] of cases.entries()) {
  const entity=`https://sp-${i}-${format.toLowerCase()}.example.com`,options={entity,idpCerts,sp,binding,format:FORMAT[format],response:sign!=='assertion',assertion:sign!=='response',algorithm:digest};
  const saml=serviceProvider(r,options);
  const app=await addApp(r,{metadata:metadataOf(saml,sp),nameIdFormat:format,sign,digest,attributes:'email=email\nrole=role\ndisplayName=name',wantRequestsSigned:true});
  await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:'ada',role:'editor'});
  const exported=await (await r.call(`/api/auth/company-apps/metadata?id=${app.id}`,{cookie:r.owner.cookie})).text();assert.match(exported,new RegExp(`entityID="${entity}"`));assert.match(exported,new RegExp(FORMAT[format]));
  const out=await posted(await signIn(r,saml,r.ada,binding));
  assert.equal(out.action,`${entity}/acs`);assert.equal(out.RelayState,'relay-1');
  const xml=xmlOf(out.SAMLResponse);
  assert.equal((xml.match(/<ds:Signature[ >]/g)||[]).length,sign==='both'?2:1);assert.match(xml,new RegExp(digest==='sha512'?'rsa-sha512':'rsa-sha256'));
  const {profile}=await saml.validatePostResponseAsync({SAMLResponse:out.SAMLResponse}).catch(error=>{throw new Error(`${format}: ${error.message}`);});
  assert.equal(profile.nameIDFormat,FORMAT[format]);assert.equal(profile.email,'ada@example.com');assert.equal(profile.role,'editor');assert.equal(profile.displayName,'ada');assert.equal(profile.issuer,`${r.origin}/saml/metadata`);assert.ok(profile.sessionIndex);
  seen[format]??=profile.nameID;
  // The same person again: persistent stays, transient changes.
  const again=(await saml.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,saml,r.ada,binding))).SAMLResponse})).profile.nameID;
  if(format==='transient')assert.notEqual(again,profile.nameID);else assert.equal(again,profile.nameID);
  // Bob is not assigned: no assertion leaves Auth.
  const refused=await signIn(r,serviceProvider(r,options),r.bob,binding);assert.equal(refused.status,403);assert.equal(field(await refused.text(),'SAMLResponse'),null);
 }
 assert.equal(seen.emailAddress,'ada@example.com');assert.equal(seen.unspecified,'ada@example.com');assert.doesNotMatch(seen.persistent,/@/);
 // A signed-out browser is sent to sign in first; the request waits for it.
 const saml=serviceProvider(r,{entity:'https://sp-0-persistent.example.com',idpCerts,sp,format:FORMAT.persistent,assertion:false});
 const waiting=await signIn(r,saml,undefined);assert.equal(waiting.status,404);
 const issued=(await r.db.prepare("SELECT COUNT(*) AS n FROM auth_activity WHERE event='saml_assertion_issued'").first()).n;assert.equal(issued,12);
});

test('encrypted assertions open at the app with AES-256-GCM and AES-128-CBC; a Redirect-bound response is signed in its query; IdP-initiated launch only where the app permits it',async t=>{
 const r=await samlInstall(t),idpCerts=await idpCertificates(r),sp=await spCredentials('sp.example.com'),decryption=await spCredentials('sp.example.com encryption');
 for(const encryption of ['aes256-gcm','aes128-cbc']) {
  const entity=`https://sp-${encryption}.example.com`,options={entity,idpCerts,sp,decryption,format:FORMAT.persistent,response:true,assertion:true};
  const saml=serviceProvider(r,options);
  await addApp(r,{metadata:metadataOf(saml,sp,decryption),sign:'both',encryption});
  const out=await posted(await signIn(r,saml,r.ada));
  const xml=xmlOf(out.SAMLResponse);assert.match(xml,/<saml:EncryptedAssertion /);assert.doesNotMatch(xml,/ada@example\.com/);
  assert.match(xml,encryption==='aes256-gcm'?/xmlenc11#aes256-gcm/:/xmlenc#aes128-cbc/);
  const {profile}=await saml.validatePostResponseAsync({SAMLResponse:out.SAMLResponse});
  assert.equal(profile.email,'ada@example.com');
 }
 // An app whose consumer takes the Redirect binding gets a deflated response and a query signature.
 const entity='https://sp-redirect.example.com';
 const app=await addApp(r,{entityId:entity,acsUrl:`${entity}/acs`,acsBinding:'redirect',sign:'both',attributes:'email=email',idpInitiated:true,relayState:'/start'});
 const saml=serviceProvider(r,{entity,idpCerts,format:null,response:false,assertion:true});saml.options.validateInResponseTo='ifPresent';
 const location=new URL((await browse(r,`/saml/launch/${app.id}`,{cookie:r.ada})).headers.get('location'));
 assert.equal(location.origin+location.pathname,`${entity}/acs`);assert.equal(location.searchParams.get('RelayState'),'/start');
 const raw=location.search.slice(1),signed=raw.slice(0,raw.indexOf('&Signature='));
 assert.ok(createVerify('RSA-SHA256').update(signed).verify(idpCerts[0],location.searchParams.get('Signature'),'base64'));
 const responseXml=inflate(location.searchParams.get('SAMLResponse'));assert.equal((responseXml.match(/<ds:Signature[ >]/g)||[]).length,1);assert.doesNotMatch(responseXml,/InResponseTo/);
 assert.equal((await saml.validatePostResponseAsync({SAMLResponse:Buffer.from(responseXml).toString('base64')})).profile.email,'ada@example.com');
 // IdP-initiated launch is refused for an app that does not permit it, and for a person not assigned.
 const closed=await r.db.prepare("SELECT id FROM auth_apps WHERE entity_id='https://sp-aes256-gcm.example.com'").first();
 assert.equal((await browse(r,`/saml/launch/${closed.id}`,{cookie:r.ada})).status,404);
 const permitted=await addApp(r,{entityId:'https://sp-idp.example.com',acsUrl:'https://sp-idp.example.com/acs',idpInitiated:true,relayState:'/home',sign:'response',attributes:'email=email'});
 const launcher=await (await r.call('/api/auth/launcher',{cookie:r.ada})).json();
 assert.deepEqual(launcher.apps.map(a=>a.launch).filter(Boolean).sort(),[`/saml/launch/${app.id}`,`/saml/launch/${permitted.id}`].sort());
 const launched=await posted(await browse(r,`/saml/launch/${permitted.id}`,{cookie:r.ada}));
 assert.equal(launched.RelayState,'/home');assert.doesNotMatch(xmlOf(launched.SAMLResponse),/InResponseTo/);
 const idp=serviceProvider(r,{entity:'https://sp-idp.example.com',idpCerts,response:true,assertion:false});idp.options.validateInResponseTo='ifPresent';
 assert.equal((await idp.validatePostResponseAsync({SAMLResponse:launched.SAMLResponse})).profile.email,'ada@example.com');
 assert.equal((await browse(r,`/saml/launch/${permitted.id}`,{cookie:r.bob})).status,403);
});

test('forged, SHA-1, replayed, stale and misaddressed requests are refused before any assertion; an app cannot use another app\'s assertion',async t=>{
 const r=await samlInstall(t),idpCerts=await idpCertificates(r),sp=await spCredentials('sp.example.com'),other=await spCredentials('attacker.example.com');
 const entity='https://sp-checks.example.com',saml=serviceProvider(r,{entity,idpCerts,sp,format:FORMAT.persistent});
 await addApp(r,{metadata:metadataOf(saml,sp),wantRequestsSigned:true});
 const refusedPage=async response=>{assert.equal(response.status,400);const html=await response.text();assert.equal(field(html,'SAMLResponse'),null);assert.equal(response.headers.get('location'),null);return html;};
 // Forged: signed by a key the app's metadata does not hold; unsigned when signing is required.
 await refusedPage(await signIn(r,serviceProvider(r,{entity,idpCerts,sp:other,format:FORMAT.persistent}),r.ada));
 await refusedPage(await signIn(r,serviceProvider(r,{entity,idpCerts,format:FORMAT.persistent}),r.ada));
 await refusedPage(await signIn(r,serviceProvider(r,{entity,idpCerts,sp:other,format:FORMAT.persistent,binding:'HTTP-POST'}),r.ada,'HTTP-POST'));
 // SHA-1: refused without the app's named exception, and the exception itself needs saying.
 await refusedPage(await signIn(r,serviceProvider(r,{entity,idpCerts,sp,format:FORMAT.persistent,algorithm:'sha1'}),r.ada));
 assert.equal((await r.admin('company-apps/create',{entityId:'https://sha1.example.com',acsUrl:'https://sha1.example.com/acs',digest:'sha1'})).status,400);
 // Altered consumer address: not in the app's allow-list.
 const altered=serviceProvider(r,{entity,idpCerts,sp,format:FORMAT.persistent});altered.options.callbackUrl='https://evil.example.com/acs';
 assert.match(await refusedPage(await signIn(r,altered,r.ada)),/acs_not_allowed/);
 // Replay: the same signed request answers once.
 const url=new URL(await saml.getAuthorizeUrlAsync('relay-1',undefined,{}));
 assert.equal((await browse(r,url.pathname+url.search,{cookie:r.ada})).status,200);
 assert.match(await refusedPage(await browse(r,url.pathname+url.search,{cookie:r.ada})),/saml_request_replayed/);
 // Stale: issued more than five minutes away from Auth's clock.
 const stale=new URL(await saml.getAuthorizeUrlAsync('relay-1',undefined,{}));
 r.tick=()=>{r.now=Date.now()+6*60000;};
 assert.match(await refusedPage(await browse(r,stale.pathname+stale.search,{cookie:r.ada})),/stale_saml_message/);
 r.tick=()=>{r.now=Date.now();};
 // Wrong audience: an assertion for this app does not satisfy another.
 const out=await posted(await signIn(r,saml,r.ada));
 const elsewhere=serviceProvider(r,{entity:'https://sp-elsewhere.example.com',idpCerts,sp,format:FORMAT.persistent});elsewhere.options.validateInResponseTo='never';
 await assert.rejects(elsewhere.validatePostResponseAsync({SAMLResponse:out.SAMLResponse}),/audience|Audience|InResponseTo/);
 // A signature-wrapped response (assertion moved, content changed) fails at the app.
 const tampered=Buffer.from(xmlOf(out.SAMLResponse).replace('ada@example.com','eve@example.com')).toString('base64');
 await assert.rejects(serviceProvider(r,{entity,idpCerts,sp,format:FORMAT.persistent}).validatePostResponseAsync({SAMLResponse:tampered}));
});

test('single logout from the app and from Auth over both bindings ends the Auth session and every app; signing certificates roll over with overlap',async t=>{
 const r=await samlInstall(t),sp=await spCredentials('sp.example.com');let idpCerts=await idpCertificates(r);
 const apps={};
 for(const [name,sloBinding] of [['one','redirect'],['two','post']]) {
  const entity=`https://sp-${name}.example.com`,saml=serviceProvider(r,{entity,idpCerts,sp,format:FORMAT.persistent,response:true,assertion:false});
  // node-saml publishes its logout endpoint with the POST binding; app one takes Redirect.
  const meta=metadataOf(saml,sp).replace(/bindings:HTTP-POST" Location="([^"]+)\/slo"/,sloBinding==='redirect'?'bindings:HTTP-Redirect" Location="$1/slo"':'$&');
  apps[name]={saml,entity,app:await addApp(r,{metadata:meta,sign:'response'})};
 }
 const signInBoth=async cookie=>{const profiles={};for(const [name,{saml}] of Object.entries(apps))profiles[name]=(await saml.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,saml,cookie))).SAMLResponse})).profile;return profiles;};
 // SP-initiated over Redirect: Auth ends its session, visits app two over POST, then answers app one.
 let profiles=await signInBoth(r.ada);
 const request=new URL(await apps.one.saml.getLogoutUrlAsync(profiles.one,'bye',{}));
 const toTwo=await posted(await browse(r,request.pathname+request.search));
 assert.equal(toTwo.action,`${apps.two.entity}/slo`);
 const logoutTwo=await apps.two.saml.validatePostRequestAsync({SAMLRequest:toTwo.SAMLRequest});assert.equal(logoutTwo.profile.nameID,profiles.two.nameID);assert.equal(logoutTwo.profile.sessionIndex,profiles.two.sessionIndex);
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);
 const answerTwo=new URL(await apps.two.saml.getLogoutResponseUrlAsync(logoutTwo.profile,'',{},true));
 const backToOne=await browse(r,answerTwo.pathname+answerTwo.search);assert.equal(backToOne.status,302,await backToOne.clone().text());
 const final=new URL(backToOne.headers.get('location'));assert.equal(final.origin+final.pathname,`${apps.one.entity}/slo`);assert.equal(final.searchParams.get('RelayState'),'bye');
 assert.equal((await apps.one.saml.validateRedirectAsync(Object.fromEntries(final.searchParams),final.search.slice(1))).loggedOut,true);
 // A replayed logout request is refused.
 assert.equal((await browse(r,request.pathname+request.search)).status,400);
 // IdP-initiated from Auth: Redirect to app one, then POST to app two, then a signed-out page.
 r.ada=await emailSession(r,'ada@example.com');profiles=await signInBoth(r.ada);
 assert.equal((await r.call('/saml/logout',{method:'POST',cookie:r.ada,form:{},headers:{origin:'https://evil.example.com'}})).status,400);
 const first=await r.call('/saml/logout',{method:'POST',cookie:r.ada,form:{}});assert.equal(first.status,302);
 const toOne=new URL(first.headers.get('location'));
 const logoutOne=await apps.one.saml.validateRedirectAsync(Object.fromEntries(toOne.searchParams),toOne.search.slice(1));assert.equal(logoutOne.profile.nameID,profiles.one.nameID);
 const reply=new URL(await apps.one.saml.getLogoutResponseUrlAsync(logoutOne.profile,'',{},true));
 const second=await posted(await browse(r,reply.pathname+reply.search));
 const logoutTwoAgain=await apps.two.saml.validatePostRequestAsync({SAMLRequest:second.SAMLRequest});
 const doneUrl=new URL(await apps.two.saml.getLogoutResponseUrlAsync(logoutTwoAgain.profile,'',{},true));
 const done=await browse(r,doneUrl.pathname+doneUrl.search);assert.equal(done.status,200);assert.match(await done.text(),/signed out of Auth and of your apps/);
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);
 // SP-initiated over POST (an enveloped XML signature): app two asks, app one is visited, app two is answered by POST.
 r.ada=await emailSession(r,'ada@example.com');profiles=await signInBoth(r.ada);
 const viaRedirect=new URL(await apps.two.saml.getLogoutUrlAsync(profiles.two,'',{}));
 const signedPost=signXml(inflate(viaRedirect.searchParams.get('SAMLRequest')),"//*[local-name(.)='LogoutRequest']",{reference:"//*[local-name(.)='Issuer']",action:'after'},{privateKey:sp.key,signatureAlgorithm:'sha256',digestAlgorithm:'sha256'});
 const toOneAgain=await browse(r,'/saml/slo',{method:'POST',form:{SAMLRequest:Buffer.from(signedPost).toString('base64')}});assert.equal(toOneAgain.status,302);
 const askOne=new URL(toOneAgain.headers.get('location'));
 const oneRequest=await apps.one.saml.validateRedirectAsync(Object.fromEntries(askOne.searchParams),askOne.search.slice(1));
 const oneReply=new URL(await apps.one.saml.getLogoutResponseUrlAsync(oneRequest.profile,'',{},true));
 const answerPost=await posted(await browse(r,oneReply.pathname+oneReply.search));assert.equal(answerPost.action,`${apps.two.entity}/slo`);
 // node-saml reads InResponseTo only on a Response element, so the logout response's is checked here.
 assert.equal(xmlOf(answerPost.SAMLResponse).match(/InResponseTo="([^"]+)"/)[1],signedPost.match(/ID="([^"]+)"/)[1]);
 apps.two.saml.options.validateInResponseTo='ifPresent';
 assert.equal((await apps.two.saml.validatePostResponseAsync({SAMLResponse:answerPost.SAMLResponse})).loggedOut,true);
 apps.two.saml.options.validateInResponseTo='always';
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);
 // Rollover: the next certificate is published before it signs; the previous stays published until retired.
 const staged=await (await r.admin('saml-keys/stage',{})).json();
 assert.equal((await idpCertificates(r)).length,2);
 r.ada=await emailSession(r,'ada@example.com');
 const oldOnly=serviceProvider(r,{entity:apps.one.entity,idpCerts:[idpCerts[0]],sp,format:FORMAT.persistent,assertion:false});
 assert.ok((await oldOnly.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,oldOnly,r.ada))).SAMLResponse})).profile);
 assert.equal((await r.admin('saml-keys/activate',{kid:staged.kid})).status,200);
 const both=await idpCertificates(r);assert.equal(both.length,2);
 await assert.rejects(oldOnly.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,oldOnly,r.ada))).SAMLResponse}));
 const rolled=serviceProvider(r,{entity:apps.one.entity,idpCerts:both,sp,format:FORMAT.persistent,assertion:false});
 assert.ok((await rolled.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,rolled,r.ada))).SAMLResponse})).profile);
 const previous=await r.db.prepare("SELECT kid FROM auth_saml_keys WHERE state='previous'").first();
 assert.equal((await r.admin('saml-keys/retire',{kid:staged.kid})).status,409);
 assert.equal((await r.admin('saml-keys/retire',{kid:previous.kid})).status,200);
 const remaining=await idpCertificates(r);assert.equal(remaining.length,1);assert.notEqual(remaining[0],idpCerts[0]);
});
