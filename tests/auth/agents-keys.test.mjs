import {verifyDomains} from './domain-helpers.mjs';
import {sdkAdminFlow,pythonAdminFlow,honoPermissionFlow} from './sdk-admin-flow.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {emailSession,cookieOf} from './runtime.mjs';
import {requestProof,finishProof,issueClient,sessionCookie} from './policy-helpers.mjs';
import {ownerInstall,passkeyPerson,mint,preparer,file,approve,post,table,person,proposal,captureOutput,everyRow,signInAgain} from './agents-helpers.mjs';

const DAY=86400000;

test('preparer keys: only a passkey administrator with fresh email proof mints, renews and revokes; expired, revoked and orphaned keys are refused; the key is shown once and stored, listed, audited and logged nowhere',async t=>{
 const output=captureOutput(t);
 const {r,owner}=await ownerInstall(t);
 const member=await passkeyPerson(r,'member','member@example.com','member');
 const ownerEmailOnly=await emailSession(r,'owner@example.com');
 for(const [label,cookie,status,error] of [['no session',undefined,401,'sign_in_required'],['member passkey session',member.cookie,403,'passkey_admin_required'],['owner email-link-only session',ownerEmailOnly,403,'passkey_admin_required']]) {
  const refused=await r.call('/api/auth/agents/mint',post({label:'Agent'},cookie));assert.equal(refused.status,status,label);assert.equal((await refused.json()).error,error,label);
 }
 assert.deepEqual(await table(r,'auth_agent_keys'),[],'refused mints store nothing');

 const minted=await r.call('/api/auth/agents/mint',post({label:'Directory agent'},owner.cookie));assert.equal(minted.status,201);
 const {id,key,expiresAt}=await minted.json();
 assert.match(key,/^authprep_[A-Za-z0-9_-]{43}$/);assert.equal(expiresAt,r.now+30*DAY);
 const listed=await r.call('/api/auth/agents',{cookie:owner.cookie});assert.equal(listed.status,200);
 const [row]=(await listed.json()).keys;
 assert.deepEqual({id:row.id,label:row.label,owner:row.owner_email,created:row.created_at,expires:row.expires_at,used:row.last_used_at},{id,label:'Directory agent',owner:'owner@example.com',created:r.now,expires:r.now+30*DAY,used:null});
 assert.equal((await preparer(r,key)).status,200,'the key reads the inventory');
 r.now+=1000;await preparer(r,key);
 assert.equal((await r.db.prepare('SELECT last_used_at FROM auth_agent_keys WHERE id=?').bind(id).first()).last_used_at,r.now,'last use is recorded');

 // Renewal gives another full lifetime; afterwards the key ends at its new expiry.
 r.now+=60000;assert.equal((await r.call('/api/auth/agents/renew',post({keyId:id},member.cookie))).status,403);
 assert.equal((await r.call('/api/auth/agents/renew',post({keyId:id},owner.cookie))).status,200);
 const renewed=r.now+30*DAY;assert.equal((await r.db.prepare('SELECT expires_at FROM auth_agent_keys WHERE id=?').bind(id).first()).expires_at,renewed);
 const later=r.now;r.now=renewed;
 const expired=await preparer(r,key);assert.equal(expired.status,401);assert.equal((await expired.json()).error,'preparer_key_refused');
 r.now=later;

 // Revocation takes effect on the very next request.
 const second=await mint(r,owner.cookie,'Second agent'),secondId=(await r.db.prepare("SELECT id FROM auth_agent_keys WHERE label='Second agent'").first()).id;
 assert.equal((await preparer(r,second)).status,200);
 assert.equal((await r.call('/api/auth/agents/revoke',post({keyId:secondId},member.cookie))).status,403);
 assert.equal((await r.call('/api/auth/agents/revoke',post({keyId:secondId},owner.cookie))).status,200);
 const revoked=await preparer(r,second);assert.equal(revoked.status,401);
 assert.equal((await r.call('/api/auth/agents/renew',post({keyId:secondId},owner.cookie))).status,409,'a revoked key cannot be renewed');

 // A key ends for good when its accountable owner stops being an active administrator:
 // restoring or promoting the owner again never brings it back, however that happens.
 const refused=async(key,why)=>{const response=await preparer(r,key);assert.equal(response.status,401,why);assert.equal((await response.json()).error,'preparer_key_refused',why);};
 const keyRow=async label=>(await (await r.call('/api/auth/agents',{cookie:owner.cookie})).json()).keys.find(k=>k.label===label);
 const keyId=async label=>(await r.db.prepare('SELECT id FROM auth_agent_keys WHERE label=?').bind(label).first()).id;
 const ann=await passkeyPerson(r,'ann','ann@example.com','admin'),annKey=await mint(r,ann.cookie,'Ann agent');
 assert.equal((await preparer(r,annKey)).status,200);
 const annFiled=await file(r,annKey,{kind:'suspend_person',target:'member@example.com',reason:'Left on 10 October'});
 assert.equal((await r.call('/api/auth/people/role',post({id:'ann',role:'member'},owner.cookie))).status,200);
 await refused(annKey,'a demoted owner leaves the key without authority');
 assert.equal((await r.call('/api/auth/people/role',post({id:'ann',role:'admin'},owner.cookie))).status,200);
 await refused(annKey,'promoting the owner back does not revive the key');
 assert.equal((await r.call('/api/auth/agents/renew',post({keyId:await keyId('Ann agent')},owner.cookie))).status,409,'an ended key cannot be renewed');
 await refused(annKey,'renewal does not revive it either');
 const ended=await keyRow('Ann agent');assert.equal(ended.ended_reason,'owner_changed','the Agents list says the key has ended and why');assert.equal(ended.revoked_at,null);
 const page=await (await r.call('/api/auth/agents?proposal='+annFiled,{cookie:owner.cookie})).json();
 assert.equal(page.proposal.key_ended_reason,'owner_changed','its proposal stays readable, with the key shown as ended');
 assert.equal((await approve(r,owner,annFiled)).status,200,'a person can still approve what an ended key filed');assert.equal((await person(r,'member@example.com')).status,'inactive');
 const annAgain=await signInAgain(r,ann,'ann@example.com'),annNew=await mint(r,annAgain.cookie,'Ann second agent');assert.equal((await preparer(r,annNew)).status,200,'a new key minted after promotion works');

 const bea=await passkeyPerson(r,'bea','bea@example.com','admin'),beaKey=await mint(r,bea.cookie,'Bea agent'),ownerKey=await mint(r,owner.cookie,'Owner agent');
 assert.equal((await preparer(r,beaKey)).status,200);
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'bea'},owner.cookie))).status,200);
 await refused(beaKey,'a suspended owner leaves the key without authority');
 assert.equal((await keyRow('Bea agent')).ended_reason,'owner_suspended');
 const restore=await file(r,ownerKey,{kind:'restore_person',target:'bea@example.com',reason:'Back from leave'});
 assert.equal((await approve(r,owner,restore)).status,200);assert.equal((await person(r,'bea@example.com')).status,'active');
 await refused(beaKey,'restoring the owner through an approved proposal does not revive the key');
 assert.equal((await keyRow('Bea agent')).ended_reason,'owner_changed');

 const cy=await passkeyPerson(r,'cy','cy@example.com','admin'),cyKey=await mint(r,cy.cookie,'Cy agent');
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'cy'},owner.cookie))).status,200);
 await refused(cyKey,'a suspended owner leaves the key without authority');
 await r.db.prepare("UPDATE oa_operators SET status='active' WHERE id='cy'").run();
 await refused(cyKey,'restoring the owner directly does not revive the key');
 assert.equal((await preparer(r,ownerKey)).status,200,'keys of administrators who stayed are untouched');
 assert.equal((await keyRow('Owner agent')).ended_reason,null);

 // A lapsed local email proof refuses minting until the person confirms again.
 r.now+=11*60000;
 const stale=await r.call('/api/auth/agents/mint',post({label:'Late'},owner.cookie));assert.equal(stale.status,403);assert.equal((await stale.json()).error,'local_email_step_up_required');
 const fresh=cookieOf(await finishProof(r,await requestProof(r,'owner@example.com',owner.cookie)));
 const third=await mint(r,fresh,'After confirmation');

 // Shown once: no listing, Activity entry, stored row or log line carries any key.
 const activity=await r.call('/api/auth/activity',{cookie:fresh});
 const seen=JSON.stringify([await (await r.call('/api/auth/agents',{cookie:fresh})).json(),await activity.json(),await (await preparer(r,third)).json()])+await everyRow(r)+output();
 for(const secret of [key,second,annKey,beaKey,third])assert.ok(!seen.includes(secret)&&!seen.includes(secret.slice('authprep_'.length)),'a key appears nowhere after minting');
 const events=(await table(r,'auth_activity')).map(e=>e.event);
 for(const event of ['agent_key_minted','agent_key_renewed','agent_key_revoked'])assert.ok(events.includes(event),event);
});

test('a preparer key opens only the preparer API: it cannot approve, mint, revoke, read administration, sign in or use the protocol, and a session cookie is not a key',async t=>{
 const {r,owner}=await ownerInstall(t);await issueClient(r);
 await passkeyPerson(r,'ada','ada@example.com','member');
 const key=await mint(r,owner.cookie),keyId=(await r.db.prepare('SELECT id FROM auth_agent_keys').first()).id;
 const proposalId=await file(r,key,{kind:'suspend_person',target:'ada@example.com',reason:'Left on 10 October'});
 const asKey={authorization:'Preparer '+key};
 const limitsBefore=new Map((await table(r,'auth_limits')).filter(row=>row.bucket.startsWith('abuse:')).map(row=>[row.bucket,row.count]));
 const authorityRows=text=>JSON.stringify(JSON.parse(text).map(rows=>rows.filter(row=>!row.bucket?.startsWith('abuse:')))).replace(/"last_used_at":\d+/g,'');
 const before=authorityRows(await everyRow(r)),sessions=(await table(r,'auth_sessions')).length;
 const status=async(path,options={})=>{const response=await r.call(path,{...options,headers:{...asKey,...options.headers}});assert.equal(sessionCookie(response),undefined,`${path} sets no session`);return response.status;};

 for(const path of ['/api/auth/me','/api/auth/people','/api/auth/agents','/api/auth/activity','/api/auth/apps','/api/auth/move-in','/api/auth/methods','/api/auth/notices','/api/auth/move-in/subjects.csv?batch=x'])assert.equal(await status(path),401,path);
 for(const [path,data] of [['/api/auth/agents/approve/options',{proposalId}],['/api/auth/agents/approve',{proposalId}],['/api/auth/agents/reject',{proposalId}],['/api/auth/agents/mint',{label:'Self-minted'}],['/api/auth/agents/revoke',{keyId}],['/api/auth/agents/renew',{keyId}],['/api/auth/people/suspend',{personId:'ada'}],['/api/auth/people/invite',{email:'new@example.com'}],['/api/auth/people/domain',{domain:'example.org'}],['/api/auth/keys/stage',{}],['/api/auth/recovery/approve',{}],['/api/auth/move-in/stage',{text:'x'}],['/api/auth/signout',{}],['/auth/passkeys/register/options',{}]])
  assert.equal(await status(path,post(data)),401,path);
 // Sign-in and protocol endpoints answer a key exactly as they answer nobody.
 assert.equal(await status('/auth/identity/email/confirm',post({token:key})),400);
 assert.equal(await status('/auth/passkeys/authenticate/verify',post({transaction:key,response:{id:'x'}})),400);
 const authorize=await r.call('/oidc/authorize?'+new URLSearchParams({client_id:'policy-app',redirect_uri:'https://app.example.com/callback',response_type:'code',scope:'openid email',state:'s',nonce:'n',code_challenge:'a'.repeat(43),code_challenge_method:'S256',prompt:'none'}),{headers:asKey});
 assert.equal(new URL(authorize.headers.get('location')).searchParams.get('error'),'login_required','no code for a key');
 assert.equal(await status('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',client_id:'policy-app',code:key,code_verifier:'v'.repeat(43),redirect_uri:'https://app.example.com/callback'}}),401);
 for(const authorization of ['Bearer '+key,'Preparer '+key])assert.equal((await r.call('/oidc/userinfo',{headers:{authorization}})).status,401,`UserInfo refuses ${authorization.split(' ')[0]}`);
 assert.equal((await r.call('/api/auth/me',{cookie:`__Host-auth_session=${key}`})).status,401,'a key presented as a session cookie is no session');
 assert.equal((await r.call('/api/auth/agents',{cookie:`__Host-auth_session=${key}`})).status,401);
 // A person's session cookie is not a preparer key, by cookie or by header.
 const raw=owner.cookie.split('=')[1];
 for(const headers of [{cookie:owner.cookie},{authorization:'Preparer '+raw},{authorization:'Preparer authprep_'+raw},{authorization:'Bearer '+raw}]) {
  const refused=await r.call('/api/auth/preparer',{headers});assert.equal(refused.status,401,JSON.stringify(Object.keys(headers)));
  assert.equal((await r.call('/api/auth/preparer',{method:'POST',data:{kind:'suspend_person',target:'ada',reason:'x'},headers})).status,401);
 }
 const {hash}=await import('../../src/auth/core.mjs');
 const expected=[];
 for(const [kind,identity,count] of [['recovery','anonymous',1],['webauthn','public',2],['email-confirm','public',1],['token','policy-app',1]]) {
  const scope=await hash(JSON.stringify([kind,identity]));
  for(const bucket of [`abuse:aggregate:${scope}`,`abuse:source:${scope}:${await hash('unavailable')}`])expected.push([bucket,count]);
 }
 const spent=(await table(r,'auth_limits')).filter(row=>row.bucket.startsWith('abuse:')).map(row=>[row.bucket,row.count-(limitsBefore.get(row.bucket)||0)]).filter(([,count])=>count);
 assert.deepEqual(spent.sort(),expected.sort(),'refused authentication attempts spend only their exact attack budgets');
 assert.equal(authorityRows(await everyRow(r)),before,'all authority and other rows are unchanged except the key last use and the asserted attack budgets');
 assert.equal((await table(r,'auth_sessions')).length,sessions);
 assert.equal((await proposal(r,proposalId)).status,'pending');
 // The administrator still can, which shows the refusals were the key's.
 assert.equal((await approve(r,owner,proposalId)).status,200);
});

test('admin service apps use private-key OAuth for scoped group and assignment writes; resource, IP, expiry, owner and ETag fences refuse automation while every scope excludes identity and credential custody',async t=>{
 const {generateKeyPair,exportJWK,SignJWT,decodeJwt}=await import('jose');
 const {r,owner}=await ownerInstall(t),admin=await passkeyPerson(r,'service-owner','sara@example.com','admin');
 const {publicKey,privateKey}=await generateKeyPair('ES256',{extractable:true}),jwk={...await exportJWK(publicKey),kid:'automation',alg:'ES256',use:'sig'};
 const settings={name:'Access reconciler',purpose:'Reconcile company groups and approved app assignments',ownerId:'service-owner',jwks:{keys:[jwk]},scopes:['groups.manage','assignments.manage'],allowedIps:['192.0.2.0/24'],expiresAt:r.now+86400000};
 const create=async(extra={},cookie=owner.cookie)=>r.call('/api/auth/admin-service-apps/create',post({...settings,...extra},cookie));
 assert.equal((await create({},null)).status,401);
 assert.equal((await create({},await emailSession(r,'owner@example.com'))).status,403,'email-only sign-in cannot create an admin credential');
 assert.equal((await create({jwks:{keys:[{...jwk,...await exportJWK(privateKey)}]}})).status,400,'private keys never enter credential custody');
 assert.equal((await create({expiresAt:r.now+366*86400000})).status,400);
 const created=await create();assert.equal(created.status,201,await created.clone().text());const service=await created.json();assert.equal(service.clientSecret,undefined);
 const assertion=async(app=service)=>new SignJWT({}).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(app.clientId).setSubject(app.clientId).setAudience(r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+60).setJti(crypto.randomUUID()).sign(privateKey);
 const grant=async(app=service,extra={},headers={})=>r.call('/oidc/token',{method:'POST',form:{grant_type:'client_credentials',client_id:app.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:await assertion(app),...extra},headers});
 assert.equal((await grant(service,{client_secret:'synthetic-auth-1'})).status,401,'no secret option');
 assert.equal((await grant(service,{}, {'cf-connecting-ip':'198.51.100.20'})).status,401,'token IP is bounded');
 const signed=await assertion(),once=await grant(service,{client_assertion:signed});assert.equal(once.status,200,await once.clone().text());
 assert.equal((await grant(service,{client_assertion:signed})).status,401,'assertions cannot replay');
 const access=await once.json(),claims=decodeJwt(access.access_token);assert.ok(claims.exp-claims.iat<=900);for(const key of ['role','amr','sid'])assert.equal(claims[key],undefined);
 const call=(path,{token=access.access_token,headers={},method='GET',data}={})=>r.call('/api/auth/admin/v1'+path,{method,data,headers:{authorization:'Bearer '+token,...(data!==undefined?{'content-type':'application/json'}:{}),...headers}});
 assert.equal((await call('/groups',{headers:{'cf-connecting-ip':'198.51.100.20'}})).status,403,'bearer IP is rechecked');
 const made=await call('/groups',{method:'POST',data:{name:'App operators'}});assert.equal(made.status,201,await made.clone().text());const group=await made.json(),oldTag=made.headers.get('etag');
 const appResponse=await r.call('/api/auth/company-apps/create',post({name:'Service Desk',entityId:'https://desk.example.com/saml',acsUrl:'https://desk.example.com/acs',idpInitiated:true},owner.cookie));assert.equal(appResponse.status,201);const app=await appResponse.json();
 const groups=await call('/groups?limit=1');assert.equal(groups.status,200);assert.equal((await groups.json()).items[0].id,group.id);assert.ok(groups.headers.has('ratelimit-remaining'));
 assert.equal((await call(`/assignments/${app.id}/group/${group.id}`,{method:'PUT',data:{},headers:{'if-match':oldTag}})).status,412,'UI edits invalidate a machine ETag');
 let tag=groups.headers.get('etag');
 assert.equal((await call(`/assignments/${app.id}/group/${group.id}`,{method:'PUT',data:{},headers:{'if-match':tag}})).status,200,'an assignment uses its granted scope');
 assert.equal((await call(`/assignments/${app.id}/group/${group.id}`,{method:'DELETE',headers:{'if-match':tag}})).status,412,'a replayed stale ETag cannot overwrite the new state');
 assert.equal((await call('/policies/example.com',{method:'PUT',data:{providerId:'other'},headers:{'if-match':(await call('/groups')).headers.get('etag')}})).status,403,'wrong scope never reaches policy validation');
 assert.equal((await call(`/groups/${group.id}`,{method:'DELETE'})).status,428,'existing mutations require a precondition');
 assert.equal((await call('/groups',{headers:{authorization:'Preparer synthetic-auth-2'}})).status,401);
 assert.equal((await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+access.access_token}})).status,401,'machine tokens carry no interactive sign-in proof');

 // A business event about an allowed app or group must not disclose a
 // related person or group outside the machine credential's resource set.
 await r.person('log-inside','synthetic-auth-21@example.com');await r.person('log-outside','synthetic-auth-22@example.com');
 for(const id of ['log-inside','log-outside']) {
  assert.equal((await r.call('/api/auth/groups/add',post({groupId:group.id,personId:id},owner.cookie))).status,200);
  assert.equal((await r.call('/api/auth/company-apps/assign',post({appId:app.id,principalType:'person',principalId:id},owner.cookie))).status,200);
 }
 const logService=await(await create({name:'Scoped event reader',scopes:['logs.read'],resources:{people:['log-inside'],groups:[group.id],apps:[app.id]}})).json();
 const logToken=(await(await grant(logService)).json()).access_token;
 const business=(await(await call('/logs?limit=100',{token:logToken})).json()).items;
 const membership=(await r.db.prepare("SELECT a.id,d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event IN ('app_assigned','group_member_added') ORDER BY a.id").all()).results;
 const insideIds=membership.filter(row=>JSON.parse(row.detail).person==='synthetic-auth-21@example.com').map(row=>row.id);
 const outsideIds=membership.filter(row=>JSON.parse(row.detail).person==='synthetic-auth-22@example.com').map(row=>row.id);
 assert.equal(insideIds.length,2);assert.equal(outsideIds.length,2);
 for(const id of insideIds)assert.ok(business.some(row=>row.id===id),'supported related person event remains visible');
 for(const id of outsideIds)assert.ok(!business.some(row=>row.id===id),'restricted related person event is excluded');
 assert.ok(!business.some(row=>/role|factor|recovery|key|credential|service_app/.test(row.event)),'identity and credential events remain excluded');
 assert.equal((await r.call('/api/auth/audit',{headers:{authorization:'Bearer '+logToken}})).status,401,'machine logs never confer interactive audit custody');

 const narrowed=(await (await create({name:'Narrow reconciler',resources:{groups:[group.id],apps:[],people:[]}})).json()),narrowToken=(await(await grant(narrowed)).json()).access_token;
 assert.equal((await call('/groups',{token:narrowToken,method:'POST',data:{name:'Outside its grant'}})).status,403);
 assert.equal((await call(`/assignments/${app.id}/group/${group.id}`,{token:narrowToken,method:'DELETE',headers:{'if-match':(await call('/groups',{token:narrowToken})).headers.get('etag')}})).status,403);

 // The exclusion is checked separately under every issued scope, without a
 // wildcard credential or a rate-limit refusal obscuring the result.
 const excluded=['/people/service-owner/roles','/resource-sets','/people/service-owner/factors','/people/service-owner/recovery','/recovery/approve','/signing-keys','/admin-service-apps','/emergency-accounts','/admin-service-apps/self/policy'];
 for(const scope of Object.keys((await(await call('/openapi.json')).json())['x-scopes'])) {
  const scoped=await(await create({name:'Scope '+scope,scopes:[scope]})).json(),tokenResponse=await grant(scoped);assert.equal(tokenResponse.status,200);const token=(await tokenResponse.json()).access_token;
  const description=await call('/openapi.json',{token});assert.equal(description.status,200);const etag=description.headers.get('etag');
  for(const path of excluded)assert.equal((await call(path,{token,method:'PUT',data:{},headers:{'if-match':etag}})).status,403,`${scope} excludes ${path}`);
  for(const path of ['/api/auth/people/role','/api/auth/recovery/approve','/api/auth/keys/stage','/api/auth/admin-service-apps/create'])assert.equal((await r.call(path,{method:'POST',data:{},headers:{authorization:'Bearer '+token}})).status,401,`${scope} has no human door`);
 }
 // Demotion and departure persist even if the human's role/state is restored.
 const delegate=await passkeyPerson(r,'delegate','delegate@example.com','admin');
 const delegated=await(await create({name:'Delegated task',ownerId:'delegate'})).json();assert.equal((await grant(delegated)).status,200);
 assert.equal((await r.call('/api/auth/people/role',post({id:'delegate',role:'member'},owner.cookie))).status,200);assert.equal((await grant(delegated)).status,401);
 assert.equal((await r.call('/api/auth/people/role',post({id:'delegate',role:'admin'},owner.cookie))).status,200);assert.equal((await grant(delegated)).status,401,'re-promotion cannot silently revive a service app');
 assert.equal((await r.call('/api/auth/admin-service-apps/reassign',post({id:delegated.id,ownerId:'delegate'},owner.cookie))).status,200);assert.equal((await grant(delegated)).status,200);
 assert.equal((await r.call('/api/auth/directory/edit',post({personId:'delegate',state:'terminated'},owner.cookie))).status,200);assert.equal((await grant(delegated)).status,401,'departure suspends the app');
 assert.equal((await r.call('/api/auth/directory/edit',post({personId:'delegate',state:'active'},owner.cookie))).status,200);assert.equal((await grant(delegated)).status,401,'rehire needs an explicit accountable owner decision');

 // Provider management changes availability only. A callback begun before
 // disable cannot admit a person afterwards, even with a valid network-edge JWT.
 r.upstreamProviders=[{id:'company',preset:'google',clientId:'synthetic-auth-3',clientSecret:'synthetic-auth-4',tokenAuthMethod:'client_secret_basic'}];
 const providerKeys=await generateKeyPair('RS256'),providerJwk={...await exportJWK(providerKeys.publicKey),kid:'employer',alg:'RS256',use:'sig'};
 const issuer='https://accounts.google.com';r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[providerJwk]}};
 await r.person('reader','reader@example.com');
 const providerService=await(await create({name:'Provider availability',ownerId:'owner',scopes:['idps.manage']})).json(),providerAccess=(await(await grant(providerService)).json()).access_token;
 const providerRead=await call('/idps',{token:providerAccess});assert.equal(providerRead.status,200);assert.equal((await providerRead.json()).items[0].available,true);
 r.upstreamProviders[0].label='Northwind Google Workspace';
 assert.equal((await call('/idps/company',{token:providerAccess,method:'PUT',data:{enabled:false},headers:{'if-match':providerRead.headers.get('etag')}})).status,412,'owner configuration changes invalidate old API preconditions');
 const providerTag=(await call('/idps',{token:providerAccess})).headers.get('etag');
 const begun=await r.call('/auth/oidc/company/start',{method:'POST',data:{returnTo:'/app/account'}});assert.equal(begun.status,303,await begun.clone().text());const upstreamStart=new URL(begun.headers.get('location'));
 r.upstream.tokens={id_token:await new SignJWT({sub:'reader-subject',email:'reader@example.com',email_verified:true,hd:'example.com',nonce:upstreamStart.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:'employer'}).setIssuer(issuer).setAudience('synthetic-auth-3').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+60).sign(providerKeys.privateKey)};
 const disabled=await call('/idps/company',{token:providerAccess,method:'PUT',data:{enabled:false},headers:{'if-match':providerTag}});assert.equal(disabled.status,200,await disabled.clone().text());
 const callback=await r.call('/auth/oidc/company/callback?'+new URLSearchParams({code:'synthetic-auth-5',state:upstreamStart.searchParams.get('state'),iss:issuer}),{cookie:cookieOf(begun)});assert.equal(callback.status,404,'disabled provider refuses an in-flight callback');
 assert.equal(await r.db.prepare("SELECT operator_id FROM oa_external_identities WHERE subject='reader-subject'").first(),null);
 const disabledView=await call('/idps',{token:providerAccess});assert.equal((await disabledView.json()).items[0].available,false);
 assert.equal((await call('/idps/company',{token:providerAccess,method:'PUT',data:{enabled:true,issuer:'https://foreign.example.com'},headers:{'if-match':disabledView.headers.get('etag')}})).status,403,'provider identity remains immutable');
 assert.equal((await call('/idps/company',{token:providerAccess,method:'PUT',data:{enabled:true},headers:{'if-match':disabledView.headers.get('etag')}})).status,200);
 assert.equal((await r.call('/auth/oidc/company/start',{method:'POST',data:{returnTo:'/app/account'}})).status,303,'reenabling offers only the original configuration');

 const beforeOwnerChange=await grant();assert.equal(beforeOwnerChange.status,200);
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'service-owner'},owner.cookie))).status,200);
 assert.equal((await call('/groups')).status,401,'already-issued tokens stop on owner suspension');assert.equal((await grant()).status,401);
 assert.equal((await r.call('/api/auth/admin-service-apps/reassign',post({id:service.id,ownerId:'owner'},owner.cookie))).status,200);
 const reassigned=await grant();assert.equal(reassigned.status,200);assert.equal((await call('/groups')).status,401,'reassignment fences old revisions');
 const short=await(await create({name:'Short task',ownerId:'owner',expiresAt:r.now+1000})).json(),shortGrant=await grant(short);assert.equal(shortGrant.status,200);const shortToken=(await shortGrant.json()).access_token;r.now+=1001;assert.equal((await grant(short)).status,401,'app expiry refuses new grants');assert.equal((await call('/groups',{token:shortToken})).status,401,'app expiry also ends issued tokens');
 const records=(await r.db.prepare("SELECT d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='admin_api_call'").all()).results.map(x=>JSON.parse(x.detail));
 assert.ok(records.some(x=>x.serviceApp===service.id&&x.owner==='service-owner'&&x.scope.includes('groups.manage')&&x.result==='allowed'));
 assert.ok(records.some(x=>x.serviceApp===service.id&&x.result==='precondition_failed'));
 assert.ok(records.some(x=>x.result==='admin_service_scope_required'));
 assert.ok(records.every(x=>'serviceApp'in x&&'owner'in x&&'scope'in x&&'result'in x));
 const stored=await everyRow(r);assert.ok(!stored.includes(access.access_token)&&!stored.includes(signed)&&!stored.includes(await exportJWK(privateKey).then(x=>x.d)),'assertions, tokens and private material never enter storage or audit');
});

test('machine directory and company-app commands share native lifecycle planning, dynamic membership, safe paginated reads and optimistic updates',async t=>{
 const {generateKeyPair,exportJWK,SignJWT}=await import('jose'),{r,owner}=await ownerInstall(t);
 await verifyDomains(t,r,owner.cookie,['example.com']);
 const keys=await generateKeyPair('ES256'),jwk={...await exportJWK(keys.publicKey),kid:'workforce',alg:'ES256',use:'sig'};
 const config=await r.call('/api/auth/admin-service-apps/create',post({name:'Workforce reconciler',purpose:'Maintain non-privileged workforce records and company access',ownerId:'owner',jwks:{keys:[jwk]},scopes:['people.manage','groups.manage','apps.manage','assignments.manage','policies.manage','logs.read','domains.read'],expiresAt:r.now+86400000},owner.cookie));assert.equal(config.status,201);const app=await config.json();
 const assertion=await new SignJWT({}).setProtectedHeader({alg:'ES256',kid:'workforce'}).setIssuer(app.clientId).setSubject(app.clientId).setAudience(r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+60).setJti(crypto.randomUUID()).sign(keys.privateKey);
 const granted=await r.call('/oidc/token',{method:'POST',form:{grant_type:'client_credentials',client_id:app.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion}});assert.equal(granted.status,200);const token=(await granted.json()).access_token;
 const call=(path,method='GET',data,etag)=>r.call('/api/auth/admin/v1'+path,{method,data,headers:{authorization:'Bearer '+token,...(data!==undefined?{'content-type':'application/json'}:{}),...(etag?{'if-match':etag}:{})}});
 const tag=async()=>(await call('/openapi.json')).headers.get('etag');
 const rankOwner=await passkeyPerson(r,'synthetic-auth-machine-admin','machine-admin@example.com','admin');
 await r.person('synthetic-auth-machine-peer','machine-peer@example.com','admin');await r.person('synthetic-auth-machine-worker','machine-worker@example.com');
 const rankConfig=await r.call('/api/auth/admin-service-apps/create',post({name:'Rank-fenced directory task',purpose:'Edit approved directory profiles subject to the accountable administrator rank',ownerId:'synthetic-auth-machine-admin',jwks:{keys:[jwk]},scopes:['people.manage'],resources:{people:['owner','synthetic-auth-machine-peer','synthetic-auth-machine-worker'],groups:[],apps:[]},expiresAt:r.now+86400000},owner.cookie));assert.equal(rankConfig.status,201);const rankService=await rankConfig.json();
 const rankAssertion=await new SignJWT({}).setProtectedHeader({alg:'ES256',kid:'workforce'}).setIssuer(rankService.clientId).setSubject(rankService.clientId).setAudience(r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+60).setJti(crypto.randomUUID()).sign(keys.privateKey);
 const rankGrant=await r.call('/oidc/token',{method:'POST',form:{grant_type:'client_credentials',client_id:rankService.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:rankAssertion}});assert.equal(rankGrant.status,200);const rankToken=(await rankGrant.json()).access_token;
 const rankCall=(path,method='GET',data,etag)=>r.call('/api/auth/admin/v1'+path,{method,data,headers:{authorization:'Bearer '+rankToken,...(data!==undefined?{'content-type':'application/json'}:{}),...(etag?{'if-match':etag}:{})}});
 const lower=await rankCall('/people/synthetic-auth-machine-worker','PATCH',{set:{department:'Rank-approved department'}},(await rankCall('/openapi.json')).headers.get('etag'));assert.equal(lower.status,200,await lower.clone().text());
 assert.equal((await (await rankCall('/people/synthetic-auth-machine-worker')).json()).profile.department,'Rank-approved department','the credential has the actual profile permission and named resources');
 for(const personId of ['synthetic-auth-machine-peer','owner']) {
  const before=await r.db.prepare('SELECT * FROM oa_operators WHERE id=?').bind(personId).first(),fields=(await r.db.prepare('SELECT * FROM auth_person_fields WHERE person_id=?').bind(personId).all()).results;
  const refused=await rankCall('/people/'+personId,'PATCH',{set:{department:'Forbidden rank change'}},(await rankCall('/openapi.json')).headers.get('etag'));
  assert.equal(refused.status,403);assert.equal((await refused.json()).error,'lower_rank_required','equal/higher account administration is refused by rank after permission and resources');
  assert.deepEqual(await r.db.prepare('SELECT * FROM oa_operators WHERE id=?').bind(personId).first(),before);assert.deepEqual((await r.db.prepare('SELECT * FROM auth_person_fields WHERE person_id=?').bind(personId).all()).results,fields);
 }
 assert.equal((await r.call('/api/auth/me',{cookie:rankOwner.cookie})).status,200,'machine refusals preserve the accountable administrator');
 const mailCount=(await r.mails()).length;
 const onboard=await call('/people','POST',{email:'worker@example.com',name:'Willa Worker',kind:'contractor',set:{department:'Engineering'}});assert.equal(onboard.status,201,await onboard.clone().text());const worker=await onboard.json();assert.equal((await r.mails()).length,mailCount,'record creation sends no automatic invitation');
 const workerRead=await call('/people/'+worker.id);assert.equal(workerRead.status,200);const safe=await workerRead.json();assert.equal(safe.state,'invited');assert.equal(safe.profile.department,'Engineering');assert.equal(safe.role,undefined);assert.equal(safe.amr,undefined);
 const firstPage=await(await call('/people?limit=1')).json();assert.equal(firstPage.items.length,1);assert.ok(firstPage.nextOffset!==null);assert.ok((await(await call('/people?limit=1&offset='+firstPage.nextOffset)).json()).items.length);
 const group=await(await call('/groups','POST',{name:'Engineering access'})).json();
 assert.equal((await call(`/groups/${group.id}/rule`,'PUT',{rule:{conditions:[{field:'department',op:'eq',value:'Engineering'}]}},await tag())).status,200);
 assert.equal((await(await call(`/groups/${group.id}/members`)).json()).items[0].id,worker.id,'the native rule planner adds the worker');
 const saml=await call('/apps','POST',{protocol:'saml',name:'Project board',entityId:'https://board.example.com/saml',acsUrl:'https://board.example.com/acs',attributes:[{name:'email',source:'email'}]});assert.equal(saml.status,201,await saml.clone().text());const samlApp=await saml.json();
 assert.equal((await call(`/assignments/${samlApp.id}/group/${group.id}`,'PUT',{role:'reader'},await tag())).status,200);
 assert.equal((await(await call('/assignments')).json()).items.find(a=>a.appId===samlApp.id).principalId,group.id);
 assert.equal((await call('/people/'+worker.id,'PATCH',{set:{department:'Support'}},await tag())).status,200);
 assert.deepEqual((await(await call(`/groups/${group.id}/members`)).json()).items,[],'the same profile planner removes obsolete group access');
 assert.equal((await call('/people/'+worker.id,'PATCH',{role:'admin'},await tag())).status,403);
 assert.equal((await r.db.prepare('SELECT role FROM oa_operators WHERE id=?').bind(worker.id).first()).role,'member');
 const ownerRefused=await call('/people/owner','PATCH',{state:'suspended'},await tag());assert.equal(ownerRefused.status,403,'a service cannot change an emergency owner');assert.equal((await ownerRefused.json()).error,'lower_rank_required');
 const oidc=await call('/apps','POST',{protocol:'oidc',name:'Time tracking',authMethod:'private_key_jwt',jwks:{keys:[jwk]},redirectUris:['https://time.example.com/callback']});assert.equal(oidc.status,201,await oidc.clone().text());const oidcApp=await oidc.json();assert.equal(oidcApp.clientSecret,null);
 const apps=(await(await call('/apps')).json()).items;assert.ok(apps.some(a=>a.id===oidcApp.id&&a.protocol==='oidc'));assert.ok(apps.every(a=>!('clientSecret'in a)&&!('jwks'in a)));
 assert.equal((await call('/apps/'+samlApp.id,'PATCH',{name:'Project board renamed',entityId:'https://board.example.com/saml',acsUrl:'https://board.example.com/acs'},await tag())).status,200);
 assert.equal((await(await call('/apps/'+samlApp.id)).json()).name,'Project board renamed');
 r.upstreamProviders=[{id:'company',preset:'google',clientId:'synthetic-auth-6',clientSecret:'synthetic-auth-7',tokenAuthMethod:'client_secret_basic'}];
 assert.equal((await call('/policies/example.com','PUT',{providerId:'company'},await tag())).status,200);
 assert.equal((await(await call('/policies')).json()).items[0].providerId,'company');
 assert.equal((await call('/policies/example.com','DELETE',undefined,await tag())).status,200);
 assert.equal((await call('/domains')).status,200);
 const logs=await call('/logs');assert.equal(logs.status,200);assert.ok((await logs.json()).items.some(e=>e.event==='admin_api_call'));
 assert.equal((await call(`/assignments/${samlApp.id}/group/${group.id}`,'DELETE',undefined,await tag())).status,200);
 assert.equal((await call('/apps/'+samlApp.id,'DELETE',undefined,await tag())).status,200);
 assert.equal((await call('/groups/'+group.id,'DELETE',undefined,await tag())).status,200);
});

test('scoped credential custodians own exact automation whose tokens and native decisions track current permissions, dynamic resources and revocation',async t=>{
 const {generateKeyPair,exportJWK,SignJWT}=await import('jose'),{r,owner}=await ownerInstall(t);
 const custodian=await passkeyPerson(r,'synthetic-auth-custodian','custodian@example.com','member');
 await r.person('synthetic-auth-worker','worker@example.com');
 const admin=async(path,data,cookie=owner.cookie)=>r.call('/api/auth/'+path,post(data,cookie));
 const created=async(path,data)=>{const response=await admin(path,data);assert.equal(response.status,201,await response.clone().text());return response.json();};
 const group=await created('groups/create',{name:'Engineering'}),app=await created('company-apps/create',{name:'Scoped board',entityId:'https://scoped-board.example.com/saml',acsUrl:'https://scoped-board.example.com/acs'});
 assert.equal((await admin('directory/edit',{personId:'synthetic-auth-worker',set:{department:'Engineering'}})).status,200);
 assert.equal((await admin('groups/rule',{groupId:group.id,rule:{conditions:[{field:'department',op:'eq',value:'Engineering'}]}})).status,200);
 const change=async data=>{
  const preview=await admin('roles/preview',data);assert.equal(preview.status,200,await preview.clone().text());
  const response=await admin('roles/apply',{previewId:(await preview.json()).previewId});assert.equal(response.status,200,await response.clone().text());return (await response.json()).plan;
 };
 const role=await change({kind:'role',role:{name:'Scoped automation custodian',rank:35,permissions:['roles.view','admin-api.manage','people.view','groups.view','groups.edit','groups.rules.edit','apps.view','apps.assign']}});
 const sets={people:[],groups:[group.id],apps:[app.id],cases:[]};
 const assigned=await change({kind:'grant',personId:'synthetic-auth-custodian',roleId:role.role.id,resources:{view:sets,edit:sets}});
 const keys=await generateKeyPair('ES256',{extractable:true}),jwk={...await exportJWK(keys.publicKey),kid:'synthetic-auth-custody',alg:'ES256',use:'sig'};
 const settings={name:'Scoped reconciler',purpose:'Maintain this approved app and group only',ownerId:'synthetic-auth-custodian',jwks:{keys:[jwk]},scopes:['groups.manage','assignments.manage'],resources:{people:['synthetic-auth-worker'],groups:[group.id],apps:[app.id]},expiresAt:r.now+86400000};
 const create=extra=>admin('admin-service-apps/create',{...settings,...extra},custodian.cookie);
 const legacyAdmin=await passkeyPerson(r,'synthetic-auth-admin','legacy-admin@example.com','admin');
 assert.equal((await admin('admin-service-apps/create',{...settings,ownerId:'owner'},legacyAdmin.cookie)).status,403,'an administrator cannot publish higher-ranked owner authority');
 assert.equal((await admin('admin-service-apps/create',{...settings,ownerId:'synthetic-auth-admin'},owner.cookie)).status,201,'the owner can publish lower administrator authority');
 assert.equal((await create({ownerId:'owner'})).status,403,'a scoped custodian cannot publish another human owner');
 assert.equal((await create({scopes:['people.manage']})).status,403,'a broad scope cannot manufacture missing profile/status permissions');
 assert.equal((await create({resources:{people:['synthetic-auth-worker'],groups:[group.id],apps:['synthetic-auth-foreign-app']}})).status,403);
 assert.equal((await create({resources:{people:['*'],groups:[group.id],apps:[app.id]}})).status,403,'scoped custody requires exact named resources');
 const response=await create({});assert.equal(response.status,201,await response.clone().text());const service=await response.json();
 const token=async svc=>{
  const assertion=await new SignJWT({}).setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(svc.clientId).setSubject(svc.clientId).setAudience(r.origin+'/oidc/token').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+60).setJti(crypto.randomUUID()).sign(keys.privateKey);
  return r.call('/oidc/token',{method:'POST',form:{grant_type:'client_credentials',client_id:svc.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion}});
 };
 const issued=await token(service);assert.equal(issued.status,200,await issued.clone().text());const bearer=(await issued.json()).access_token;
 const call=(path,method='GET',data,etag)=>r.call('/api/auth/admin/v1'+path,{method,data,headers:{authorization:'Bearer '+bearer,...(data!==undefined?{'content-type':'application/json'}:{}),...(etag?{'if-match':etag}:{})}});
 const initial=await call('/groups');assert.equal(initial.status,200);assert.deepEqual((await initial.json()).items.map(g=>g.id),[group.id]);
 const update=await call(`/assignments/${app.id}/person/synthetic-auth-worker`,'PUT',{role:'reader'},initial.headers.get('etag'));assert.equal(update.status,200,await update.clone().text());
 assert.equal((await r.db.prepare("SELECT role FROM auth_app_assignments WHERE app_id=? AND principal_id='synthetic-auth-worker'").bind(app.id).first()).role,'reader');
 assert.equal((await call('/groups','POST',{name:'Outside named custody'})).status,403);
 assert.equal((await call('/people/synthetic-auth-worker','PATCH',{state:'suspended'},update.headers.get('etag'))).status,403);
 assert.equal((await admin('admin-service-apps/reassign',{id:service.id,ownerId:'owner'},custodian.cookie)).status,403);
 const other=await admin('admin-service-apps/create',{...settings,ownerId:'owner'});assert.equal(other.status,201);
 assert.equal((await admin('admin-service-apps/revoke',{id:(await other.json()).id},custodian.cookie)).status,403);
 const revocableResponse=await create({name:'Revocable scoped task'});assert.equal(revocableResponse.status,201);const revocable=await revocableResponse.json();assert.equal((await token(revocable)).status,200);
 assert.equal((await admin('admin-service-apps/revoke',{id:revocable.id},custodian.cookie)).status,200);assert.equal((await token(revocable)).status,401);
 assert.equal((await admin('directory/edit',{personId:'synthetic-auth-worker',set:{department:'Support'}})).status,200);
 assert.equal((await call('/groups')).status,401,'the human edit set immediately loses a worker who left its dynamic group');assert.equal((await token(service)).status,401);
 assert.equal((await admin('directory/edit',{personId:'synthetic-auth-worker',set:{department:'Engineering'}})).status,200);assert.equal((await token(service)).status,200);
 await change({kind:'revoke',grantId:assigned.id});
 assert.equal((await token(service)).status,401,'removing current custody authority stops the next token');assert.equal((await call('/groups')).status,401,'already-issued machine claims do not retain the removed human role');
});

test('a packed Node SDK installs in an empty app and enforces scoped private-key administration, pagination, ETags and live revocation over HTTP',sdkAdminFlow);

test('a built Python wheel installs in an empty app and enforces scoped administration, ETags, pagination and cached-token revocation over HTTP',pythonAdminFlow);

test('an installed Hono quickstart checks genuine employee consent, callback binding, rotation and live revocation against fresh Auth',honoPermissionFlow);
