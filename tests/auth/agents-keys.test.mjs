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
 const before=await everyRow(r),sessions=(await table(r,'auth_sessions')).length;
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
 assert.equal(await everyRow(r).then(after=>after.replace(/"last_used_at":\d+/g,'')),before.replace(/"last_used_at":\d+/g,''),'nothing changed except the key\'s last use');
 assert.equal((await table(r,'auth_sessions')).length,sessions);
 assert.equal((await proposal(r,proposalId)).status,'pending');
 // The administrator still can, which shows the refusals were the key's.
 assert.equal((await approve(r,owner,proposalId)).status,200);
});

test('admin service apps use private-key OAuth for scoped group and assignment writes; resource, IP, expiry, owner and ETag fences refuse automation while every scope excludes identity and credential custody',async t=>{
 const {generateKeyPair,exportJWK,SignJWT,decodeJwt}=await import('jose');
 const {SCOPES}=await import('../../src/auth/admin-api/credentials/index.mjs');
 const {r,owner}=await ownerInstall(t),admin=await passkeyPerson(r,'service-owner','sara@example.com','admin');
 const {publicKey,privateKey}=await generateKeyPair('ES256'),jwk={...await exportJWK(publicKey),kid:'automation',alg:'ES256',use:'sig'};
 const settings={name:'Access reconciler',purpose:'Reconcile company groups and approved app assignments',ownerId:'service-owner',jwks:{keys:[jwk]},scopes:['groups.manage','assignments.manage'],allowedIps:['192.0.2.0/24'],expiresAt:r.now+86400000};
 const create=async(extra={},cookie=owner.cookie)=>r.call('/api/auth/admin-service-apps/create',post({...settings,...extra},cookie));
 assert.equal((await create({},null)).status,401);
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
 const call=(path,{token=access.access_token,headers={},method='GET',data}={})=>r.call('/api/auth/admin/v1'+path,{method,data,headers:{authorization:'Bearer '+token,...headers}});
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

 const narrowed=(await (await create({name:'Narrow reconciler',resources:{groups:[group.id],apps:[],people:[]}})).json()),narrowToken=(await(await grant(narrowed)).json()).access_token;
 assert.equal((await call('/groups',{token:narrowToken,method:'POST',data:{name:'Outside its grant'}})).status,403);
 assert.equal((await call(`/assignments/${app.id}/group/${group.id}`,{token:narrowToken,method:'DELETE',headers:{'if-match':(await call('/groups',{token:narrowToken})).headers.get('etag')}})).status,403);

 // The exclusion is checked separately under every issued scope, without a
 // wildcard credential or a rate-limit refusal obscuring the result.
 const excluded=['/people/service-owner/roles','/resource-sets','/people/service-owner/factors','/people/service-owner/recovery','/recovery/approve','/signing-keys','/admin-service-apps','/emergency-accounts','/admin-service-apps/self/policy'];
 for(const scope of SCOPES) {
  const scoped=await(await create({name:'Scope '+scope,scopes:[scope]})).json(),tokenResponse=await grant(scoped);assert.equal(tokenResponse.status,200);const token=(await tokenResponse.json()).access_token;
  const description=await call('/openapi.json',{token});assert.equal(description.status,200);const etag=description.headers.get('etag');
  for(const path of excluded)assert.equal((await call(path,{token,method:'PUT',data:{},headers:{'if-match':etag}})).status,403,`${scope} excludes ${path}`);
  for(const path of ['/api/auth/people/role','/api/auth/recovery/approve','/api/auth/keys/stage','/api/auth/admin-service-apps/create'])assert.equal((await r.call(path,{method:'POST',data:{},headers:{authorization:'Bearer '+token}})).status,401,`${scope} has no human door`);
 }
 const beforeOwnerChange=await grant();assert.equal(beforeOwnerChange.status,200);
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'service-owner'},owner.cookie))).status,200);
 assert.equal((await call('/groups')).status,403,'already-issued tokens stop on owner suspension');assert.equal((await grant()).status,401);
 assert.equal((await r.call('/api/auth/admin-service-apps/reassign',post({id:service.id,ownerId:'owner'},owner.cookie))).status,200);
 const reassigned=await grant();assert.equal(reassigned.status,200);assert.equal((await call('/groups')).status,401,'reassignment fences old revisions');
 const short=await(await create({name:'Short task',ownerId:'owner',expiresAt:r.now+1000})).json();r.now+=1001;assert.equal((await grant(short)).status,401,'app expiry refuses new grants');
 const records=(await r.db.prepare("SELECT d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='admin_api_call'").all()).results.map(x=>JSON.parse(x.detail));
 assert.ok(records.some(x=>x.serviceApp===service.id&&x.owner==='service-owner'&&x.scope.includes('groups.manage')&&x.result==='allowed'));
 assert.ok(records.some(x=>x.serviceApp===service.id&&x.result==='precondition_failed'));
 assert.ok(records.some(x=>x.result==='admin_service_scope_required'));
 assert.ok(records.every(x=>'serviceApp'in x&&'owner'in x&&'scope'in x&&'result'in x));
 const stored=await everyRow(r);assert.ok(!stored.includes(access.access_token)&&!stored.includes(signed)&&!stored.includes(await exportJWK(privateKey).then(x=>x.d)),'assertions, tokens and private material never enter storage or audit');
});
