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

test('app setup previews typed mappings for three people, launches computed collision-safe NameID and group role, provisions formatted dates, refuses unsafe programs and rolls back an audited version',async t=>{
 const r=await samlInstall(t),{scimServer}=await import('./scim-server.mjs'),scim=await scimServer(t,'synthetic-auth-1');r.scimServer=scim.url;
 const admin=async(path,data,status=200)=>{const response=await r.admin(path,data);assert.equal(response.status,status,await response.clone().text());return response.json();};
 await admin('directory/edit',{personId:'ada',set:{name:'Ada Lovelace',start_date:'2026-10-01'}});
 await admin('directory/edit',{personId:'bob',set:{name:'Ada Lovelace',start_date:'2026-10-02',manager:'ada'}});
 const group=await admin('groups/create',{name:'Finance'},201);await admin('groups/add',{groupId:group.id,personId:'ada'});
 const idpCerts=await idpCertificates(r),sp=await spCredentials('mapping.example.com'),entity='https://mapping.example.com',saml=serviceProvider(r,{entity,idpCerts,sp});
 const app=await addApp(r,{metadata:metadataOf(saml,sp),sign:'both',attributes:'email=email',assign:['ada','bob']});
 const op=(op,...args)=>({op,args}),field=field=>({field});
 const username={expression:op('lower',op('concat',field('first_name'),'.',field('last_name'))),unique:true};
 const program={language:1,nameId:username,username,saml:{role:op('if',op('inGroup','Finance'),'finance','reader')},scim:{title:op('date',field('start_date'),'YYYYMMDD')}};
 const data={appId:app.id,personIds:['ada','bob','owner'],program};
 let preview=await admin('mapping/preview',data);
 assert.deepEqual(preview.rows.map(x=>[x.personId,x.values.nameId]),[['ada','ada.lovelace-1'],['bob','ada.lovelace-2'],['owner',null]]);
 assert.ok(preview.rows.find(x=>x.personId==='owner').warnings.includes('nameId:empty'));
 assert.ok(preview.rows.find(x=>x.personId==='ada').warnings.includes('nameId:duplicate'));
 assert.deepEqual(preview.rows.filter(x=>x.personId!=='owner').map(x=>x.values.scim.title),['20261001','20261002']);
 assert.equal((await r.admin('mapping/save',{...data,version:0,digest:'stale'})).status,409);
 await admin('mapping/save',{...data,version:0,digest:preview.digest});
 const read=async()=> (await saml.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,saml,r.ada))).SAMLResponse})).profile;
 assert.equal((await read()).nameID,'ada.lovelace-1');assert.equal((await read()).role,'finance');
 await admin('provisioning/connect',{appId:app.id,baseUrl:'https://scim.example.com/scim/v2',token:scim.token},201);
 assert.deepEqual([...scim.users.values()].map(x=>[x.userName,x.title]).sort(),[['ada.lovelace-1','20261001'],['ada.lovelace-2','20261002']]);
 const verified=(await r.db.prepare("SELECT state FROM auth_provisioning WHERE app_id=? AND state!='superseded'").bind(app.id).all()).results;assert.ok(verified.length>=2&&verified.every(x=>x.state==='verified'));
 // All functions are exercised through the same preview door, with manager and source lookups.
 await admin('directory/source',{source:'hr',records:[{personId:'bob',sourceId:'synthetic-auth-2',fields:{department:'Sales'}}]});
 const functions={lower:op('lower','ABC'),upper:op('upper','abc'),substring:op('substring','abcdef',1,3),replace:op('replace','a-b','-','.'),regex:op('regexReplace','A  B',' +','-'),trim:op('trim',' x '),pad:op('pad','7',3,'0','start'),coalesce:op('coalesce',null,'yes'),manager:{manager:'email'},source:{source:'hr',field:'department'},filter:op('filter',{groups:true},'startsWith','Fin')};
 const values=(await admin('mapping/preview',{...data,program:{language:1,saml:functions}})).rows.find(x=>x.personId==='bob').values.saml;
 assert.deepEqual(values,{lower:'abc',upper:'ABC',substring:'bcd',replace:'a.b',regex:'A-B',trim:'x',pad:'007',coalesce:'yes',manager:'ada@example.com',source:'Sales',filter:[]});
 const longText=op('concat',...Array(4).fill('a'.repeat(1024))),pattern='.'.repeat(128),replacement='a'.repeat(128);
 const expensive=op('regexReplace',op('regexReplace',longText,pattern,replacement),pattern,replacement);
 const bounded=await r.admin('mapping/preview',{...data,program:{language:1,nameId:{expression:expensive}}});
 assert.equal(bounded.status,400);assert.equal((await bounded.json()).error,'mapping_budget');
 let tooDeep='x';for(let n=0;n<18;n++)tooDeep=op('lower',tooDeep);
 assert.equal((await r.admin('mapping/preview',{...data,program:{language:1,nameId:{expression:tooDeep}}})).status,400);
 for(const expr of [{field:'AUTH_ENCRYPTION_KEY'},op('fetch','https://example.com'),op('pad','x',100000000),op('regexReplace','aaaa','(a+)+','x'),op('lower',42)]){
  assert.equal((await r.admin('mapping/preview',{...data,program:{language:1,nameId:{expression:expr}}})).status,400);
 }
 const next={...program,saml:{role:'reader'}};preview=await admin('mapping/preview',{...data,program:next});
 await admin('mapping/save',{...data,program:next,version:1,digest:preview.digest});assert.equal((await read()).role,'reader');
 await admin('mapping/rollback',{appId:app.id,personIds:['ada'],version:2,targetVersion:1});assert.equal((await read()).role,'finance');
 assert.equal((await r.admin('mapping/save',{...data,version:1,digest:preview.digest})).status,409);
 for(const cookie of [undefined,r.ada])assert.equal((await r.call('/api/auth/mapping/preview',{method:'POST',cookie,data})).status,cookie?403:401);
 r.tick=()=>{r.now=Date.now()+660000;};assert.equal((await r.admin('mapping/rollback',{appId:app.id,personIds:['ada'],version:3,targetVersion:1})).status,403);
 const history=(await r.db.prepare("SELECT event FROM auth_activity WHERE event LIKE 'mapping_%'").all()).results;
 assert.deepEqual(history.map(x=>x.event),['mapping_saved','mapping_saved','mapping_rolled_back']);
});

import {temporaryLauncherGrant} from './launcher-flow.mjs';
import {scimServer} from './scim-server.mjs';
test('launcher preferences never grant access: current groups control credential-free bookmarks and expired temporary SAML grants refuse direct launch',async t=>{
 const r=await samlInstall(t);r.tick=()=>{};
 const app=await addApp(r,{name:'Temporary expenses',entityId:'https://temporary.example.com',acsUrl:'https://temporary.example.com/acs',idpInitiated:true,assign:[]});
 const employee=await temporaryLauncherGrant(r,app);
 const read=async(cookie=employee.cookie)=>(await (await r.call('/api/auth/launcher',{cookie})).json()).apps;
 const action=(path,data,cookie=employee.cookie)=>r.call(path,{method:'POST',data,cookie});
 assert.equal((await r.call(`/saml/launch/${app.id}`,{cookie:employee.cookie})).status,200);
 assert.equal((await action('/api/auth/launcher/favorite',{id:app.id,favorite:true})).status,200);
 assert.equal((await r.call(`/api/auth/launcher/open?id=${app.id}`,{cookie:employee.cookie})).headers.get('location'),`/saml/launch/${app.id}`);
 await r.restart();assert.equal((await read()).find(a=>a.id===app.id).favorite,true);assert.equal((await read()).find(a=>a.id===app.id).lastUsedAt,r.now);
 assert.equal((await read(r.bob)).find(a=>a.id===app.id).favorite,false);
 r.now+=60001;
 const expired=(await read()).find(a=>a.id===app.id);assert.equal(expired.state,'expired');assert.equal(expired.launch,null);
 assert.equal((await r.call(`/saml/launch/${app.id}`,{cookie:employee.cookie})).status,403);
 assert.equal((await r.call(`/api/auth/launcher/open?id=${app.id}`,{cookie:employee.cookie})).status,403);
 assert.equal((await action('/api/auth/launcher/favorite',{id:app.id,favorite:true})).status,403);
 // A connector account still being created is explained, then an edge refusal
 // becomes a blocked connector without exposing its credential or error text.
 const edge=await scimServer(t,'synthetic-auth-71');r.scimServer=edge.url;
 const provisioned=await addApp(r,{name:'Provisioned app',entityId:'https://provisioned.example.com',acsUrl:'https://provisioned.example.com/acs',idpInitiated:true});
 let release,started;const ready=new Promise(resolve=>{started=resolve}),paused=new Promise(resolve=>{release=resolve});t.after(()=>release());
 edge.beforeRequest=async()=>{started();await paused;};edge.fail(1,403);
 assert.equal((await r.call('/api/auth/provisioning/connect',{method:'POST',cookie:r.owner.cookie,data:{appId:provisioned.id,baseUrl:'https://scim.example.com/scim/v2',token:'synthetic-auth-71'},detached:true})).status,201);
 await ready;
 assert.equal((await read(r.ada)).find(a=>a.id===provisioned.id).state,'unprovisioned');
 release();edge.beforeRequest=null;
 // Await the pending delivery through the native runtime's scheduled door.
 for(let attempt=0;attempt<30;attempt++) {const tile=(await read(r.ada)).find(a=>a.id===provisioned.id);if(tile.state==='connector-blocked')break;await new Promise(resolve=>setTimeout(resolve,10));}
 const blocked=(await read(r.ada)).find(a=>a.id===provisioned.id);assert.equal(blocked.state,'connector-blocked');assert.equal(blocked.launch,null);
 assert.equal((await r.call(`/api/auth/launcher/open?id=${provisioned.id}`,{cookie:r.ada})).status,403);
 const group=await (await r.admin('/api/auth/groups/create',{name:'Bookmark readers'})).json();
 const bookmark=await (await r.admin('/api/auth/bookmarks/create',{name:'Handbook',url:'https://handbook.example.com/start',icon:'Book',groupId:group.id})).json();
 assert.equal((await action('/api/auth/bookmarks/create',{name:'Forbidden',url:'https://handbook.example.com',groupId:group.id})).status,403);
 assert.equal((await r.admin('/api/auth/bookmarks/create',{name:'Unsafe',url:'https://user:synthetic-auth-1@handbook.example.com',groupId:group.id})).status,400);
 assert.equal((await read()).some(a=>a.id===bookmark.id),false);
 await r.admin('/api/auth/groups/add',{groupId:group.id,personId:'temporary-worker'});
 const tile=(await read()).find(a=>a.id===bookmark.id);assert.equal(tile.kind,'bookmark');assert.equal(tile.launch,'https://handbook.example.com/start');
 assert.equal((await read(r.bob)).some(a=>a.id===bookmark.id),false);
 await action('/api/auth/launcher/favorite',{id:bookmark.id,favorite:true});
 const opened=await r.call(`/api/auth/launcher/open?id=${bookmark.id}`,{cookie:employee.cookie});assert.equal(opened.status,303);assert.equal(opened.headers.get('location'),tile.launch);assert.equal(opened.headers.get('set-cookie'),null);
 await r.admin('/api/auth/groups/remove',{groupId:group.id,personId:'temporary-worker'});
 assert.equal((await read()).some(a=>a.id===bookmark.id),false);
 assert.equal((await r.call(`/api/auth/launcher/open?id=${bookmark.id}`,{cookie:employee.cookie})).status,403);
 await r.admin('/api/auth/company-apps/assign',{appId:app.id,principalType:'person',principalId:'temporary-worker'});
 assert.equal((await r.call(`/saml/launch/${app.id}`,{cookie:employee.cookie})).status,200,'an independent current grant works');
 await r.admin('/api/auth/company-apps/unassign',{appId:app.id,principalType:'person',principalId:'temporary-worker'});
 assert.equal((await r.call(`/saml/launch/${app.id}`,{cookie:employee.cookie})).status,403,'a saved favorite cannot replace a removed assignment');
});
