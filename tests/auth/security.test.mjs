import {helpdeskRecoveryFlow} from './recovery-cases-flow.mjs';
import {verifyDomains} from './domain-helpers.mjs';
import {scopedUpstreamFlow} from './scoped-upstream-flow.mjs';
import {identityPairsFlow} from './identity-pairs-flow.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {createSession} from '../../src/auth/core.mjs';
import {openRuntime,cookieOf,emailSession} from './runtime.mjs';
import {authenticator,register,authenticate} from './webauthn.mjs';
import {requestProof,finishProof} from './policy-helpers.mjs';
import {mint,file,preparer,approvalProof,approve} from './agents-helpers.mjs';
const post=(data={},cookie)=>({method:'POST',data,cookie});
async function fixture(t){const r=await openRuntime();t.after(()=>r.close());await r.person('owner','owner@example.com','owner');await r.person('member','member@example.com');return r;}
test('email proof is uniform, browser bound, one use and preserves a safe return path',async t=>{
 const r=await fixture(t),known=await r.call('/auth/identity/email/request',post({email:'owner@example.com',returnTo:'/oidc/authorize?state=kept'})),unknown=await r.call('/auth/identity/email/request',post({email:'unknown@example.com'}));
 assert.equal(known.status,202);assert.equal(unknown.status,202);assert.deepEqual(await known.json(),await unknown.json());
 const token=new URL((await r.mails())[0].text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 assert.equal((await r.call('/auth/identity/email/confirm',post({token},cookieOf(unknown)))).status,400);
 const confirm=await r.call('/auth/identity/email/confirm',{method:'POST',form:{token},cookie:cookieOf(known)});assert.equal(confirm.status,303);assert.equal(confirm.headers.get('location'),'/oidc/authorize?state=kept');
 assert.equal((await r.call('/auth/identity/email/confirm',post({token},cookieOf(known)))).status,400);
 assert.equal((await r.call('/api/auth/people',{cookie:cookieOf(confirm)})).status,403);
});
test('email mail limits suppress delivery without changing public responses',async t=>{
 const r=await fixture(t);for(let i=0;i<8;i++)assert.equal((await r.call('/auth/identity/email/request',post({email:'owner@example.com'}))).status,202);
 const delivered=(await r.mails()).length;assert.ok(delivered>0&&delivered<8);
 assert.equal((await r.call('/auth/identity/email/request',{...post({email:'owner@example.com'}),headers:{origin:'https://elsewhere.example'}})).status,403);
});
test('admitted dev identity needs an Auth email link before first passkey enrollment',async t=>{
 const r=await fixture(t);r.local=true;r.origin='http://localhost:8787';
 const dev=await createSession({db:r.db,local:true,now:()=>r.now},'owner',['dev']),devCookie=dev.header.split(';')[0];
 assert.equal((await r.call('/api/auth/me',{cookie:devCookie})).status,401);
 assert.equal((await r.call('/api/auth/me',{cookie:devCookie,allowDevSession:true})).status,200);
 assert.equal((await r.call('/auth/passkeys/register/options',{...post({},devCookie),allowDevSession:true})).status,403);
 const emailCookie=await emailSession(r,'owner@example.com'),offered=await r.call('/auth/passkeys/register/options',post({},emailCookie));assert.equal(offered.status,200);
 const tx=await offered.json(),data={transaction:tx.transaction,response:authenticator(r.origin).register(tx.options)},bound=cookieOf(offered);
 assert.equal((await r.call('/auth/passkeys/register/verify',{...post(data,`${devCookie}; ${bound}`),allowDevSession:true})).status,403);
 assert.equal((await r.call('/auth/passkeys/register/verify',post(data,`${emailCookie}; ${bound}`))).status,200);
 r.local=false;r.origin='https://auth.example.com';
 assert.equal((await r.call('/api/auth/me',{cookie:devCookie.replace('auth_session=','__Host-auth_session='),allowDevSession:true})).status,401);
});
test('upstream identity needs an Auth email link before first passkey enrollment',async t=>{
 const r=await fixture(t),issuer='https://accounts.google.com',keys=await generateKeyPair('RS256');
 r.upstreamProviders=[{id:'google',preset:'google',clientId:'auth-upstream',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only'}];
 r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[{...await exportJWK(keys.publicKey),kid:'upstream',alg:'RS256',use:'sig'}]}};
 const started=await r.call('/auth/oidc/google/start',post({}));assert.equal(started.status,303);const location=new URL(started.headers.get('location'));
 r.upstream.tokens={id_token:await new SignJWT({sub:'owner-subject',email:'owner@example.com',email_verified:true,hd:'example.com',nonce:location.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:'upstream'}).setIssuer(issuer).setAudience('auth-upstream').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
 const signedIn=await r.call('/auth/oidc/google/callback?'+new URLSearchParams({code:'upstream-code',state:location.searchParams.get('state'),iss:issuer}),{cookie:cookieOf(started)});assert.equal(signedIn.status,303);
 const upstreamCookie=signedIn.headers.getSetCookie().find(c=>c.startsWith('__Host-auth_session=')).split(';')[0];
 assert.equal((await r.call('/api/auth/me',{cookie:upstreamCookie})).status,200);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},upstreamCookie))).status,403);
 const emailCookie=await emailSession(r,'owner@example.com'),offered=await r.call('/auth/passkeys/register/options',post({},emailCookie));assert.equal(offered.status,200);
 const tx=await offered.json(),data={transaction:tx.transaction,response:authenticator(r.origin).register(tx.options)},bound=cookieOf(offered);
 assert.equal((await r.call('/auth/passkeys/register/verify',post(data,`${upstreamCookie}; ${bound}`))).status,403);
 assert.equal((await r.call('/auth/passkeys/register/verify',post(data,`${emailCookie}; ${bound}`))).status,200);
});
test('real passkey proof grants admin; later email session cannot administer or enroll another key',async t=>{
 const r=await fixture(t),emailCookie=await emailSession(r,'owner@example.com');
 const offered=await r.call('/auth/passkeys/register/options',post({},emailCookie));assert.equal(offered.status,200);const tx=await offered.json();
 const {key,cookie}=await register(r,emailCookie);
 assert.equal((await r.call('/api/auth/people',{cookie})).status,200);
 const later=await emailSession(r,'owner@example.com');assert.equal((await r.call('/auth/passkeys/register/options',post({},later))).status,403);
 assert.equal((await r.call('/auth/passkeys/register/verify',post({transaction:tx.transaction,response:authenticator(r.origin).register(tx.options)},`${emailCookie}; ${cookieOf(offered)}`))).status,403);
 const additional=await register(r,cookie);assert.equal((await authenticate(r,additional.key)).response.status,200);
 assert.equal((await r.call('/api/auth/people/invite',post({email:'new@example.com'},later))).status,403);
 assert.equal((await r.call('/api/auth/people/invite',post({email:'new@example.com'},cookie))).status,201);
 await verifyDomains(t,r,cookie,['company.example']);
 assert.equal((await r.call('/api/auth/people/domain',post({domain:'company.example'},cookie))).status,201);
 const auth=await authenticate(r,key);assert.equal(auth.response.status,200);
 const memberCookie=await emailSession(r,'member@example.com'),memberOptions=await r.call('/auth/passkeys/register/options',post({},memberCookie));assert.equal(memberOptions.status,200);const memberTx=await memberOptions.json();
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'member'},cookie))).status,200);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},memberCookie))).status,401);
 assert.equal((await r.call('/auth/passkeys/register/verify',post({transaction:memberTx.transaction,response:authenticator(r.origin).register(memberTx.options)},`${memberCookie}; ${cookieOf(memberOptions)}`))).status,401);
 assert.equal((await r.db.prepare("SELECT status FROM oa_operators WHERE id='member'").first()).status,'inactive');
});
test('passkey verifies host, challenge and signature; stale email proof asks only after an attempt',async t=>{
 const r=await fixture(t),{key}=await register(r,await emailSession(r,'owner@example.com'));
 const options=await r.call('/auth/passkeys/authenticate/options',post()),tx=await options.json();const forged=key.authenticate(tx.options,{origin:'https://other.example.com'});
 assert.equal((await r.call('/auth/passkeys/authenticate/verify',post({transaction:tx.transaction,response:forged},cookieOf(options)))).status,400);
 r.now+=31*86400000;const count=(await r.mails()).length;
 assert.equal((await r.call('/oidc/jwks')).status,200);assert.equal((await r.mails()).length,count);
 const attempt=await authenticate(r,key);assert.equal(attempt.response.status,202);assert.equal((await r.mails()).length,count+1);
 const token=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 assert.equal((await r.call('/auth/identity/email/confirm',post({token}))).status,400);
 const finished=await r.call('/auth/identity/email/confirm',post({token},attempt.binding));assert.equal(finished.status,200);assert.equal((await r.call('/api/auth/people',{cookie:cookieOf(finished)})).status,200);
});
test('recovery waits 72 hours, notifies every session, supports cancellation and distinct admin approval',async t=>{
 await helpdeskRecoveryFlow(t);
 const r=await fixture(t),owner=await register(r,await emailSession(r,'owner@example.com')),emailCookie=await emailSession(r,'owner@example.com');
 let result=await r.call('/api/auth/recovery/start',post({},emailCookie)),rec=await result.json();assert.equal(result.status,201);
 assert.equal((await (await r.call('/api/auth/notices',{cookie:owner.cookie})).json()).length,1);
 assert.equal((await r.call('/api/auth/recovery/approve',post({id:rec.id},owner.cookie))).status,403);
 assert.equal((await r.call('/api/auth/recovery/complete',post({id:rec.id},emailCookie))).status,403);
 assert.equal((await r.call('/api/auth/recovery/cancel',post({id:rec.id},owner.cookie))).status,200);
 assert.equal((await r.call('/api/auth/recovery/complete',post({id:rec.id},emailCookie))).status,404);
 result=await r.call('/api/auth/recovery/start',post({},emailCookie));rec=await result.json();r.now+=72*3600000;
 const resumed=await emailSession(r,'owner@example.com');assert.equal((await r.call('/api/auth/recovery/complete',post({id:rec.id},resumed))).status,200);
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM auth_passkeys WHERE person_id='owner'").first()).n,0);
 const ownerAgain=await register(r,resumed);await r.person('admin','admin@example.com');
 assert.equal((await r.call('/api/auth/people/role',post({id:'admin',role:'admin'},ownerAgain.cookie))).status,200);
 const admin=await register(r,await emailSession(r,'admin@example.com'));
 const started=await r.call('/api/auth/recovery/start',post({},resumed)),again=await started.json();assert.equal(started.status,201);
 // Equal or higher administrators are viewable, but their accounts cannot be
 // changed or exported by this administrator through any administration door.
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'owner'},admin.cookie))).status,403);
 assert.equal((await r.call('/api/auth/people/role',post({id:'owner',role:'member'},admin.cookie))).status,403);
 assert.equal((await r.call('/api/auth/recovery/approve',post({id:again.id},admin.cookie))).status,403);
 assert.equal((await r.call('/api/auth/recovery/complete',post({id:again.id},resumed))).status,403);
 await r.person('peer','peer@example.com','admin');
 const peer=await register(r,await emailSession(r,'peer@example.com')),peerEmail=await emailSession(r,'peer@example.com');
 const peerRecovery=await (await r.call('/api/auth/recovery/start',post({},peerEmail))).json();
 for(const [path,data] of [
  ['/people/suspend',{personId:'peer'}],
  ['/people/role',{id:'peer',role:'member'}],
  ['/directory/edit',{personId:'peer',set:{title:'Changed by peer'}}],
  ['/directory/edit',{personId:'peer',state:'suspended'}],
  ['/recovery/approve',{id:peerRecovery.id}],
 ])assert.equal((await r.call('/api/auth'+path,post(data,admin.cookie))).status,403,path);
 assert.equal((await r.call('/api/auth/roles/people?personId=peer',{cookie:admin.cookie})).status,200,'rank does not block viewing an administrator');
 assert.equal((await r.call('/api/auth/roles/export?personId=peer',{cookie:admin.cookie})).status,403,'person export carries the account rank fence');
 assert.equal((await r.db.prepare("SELECT role,status,display_name FROM oa_operators WHERE id='peer'").first()).role,'admin');
 assert.equal((await r.db.prepare('SELECT approved_by FROM auth_recoveries WHERE id=?').bind(peerRecovery.id).first()).approved_by,null);
 assert.equal((await r.call('/api/auth/recovery/approve',post({id:peerRecovery.id},ownerAgain.cookie))).status,200,'owner can approve a lower administrator');
 assert.equal((await r.call('/api/auth/recovery/complete',post({id:peerRecovery.id},peerEmail))).status,200);
 assert.equal((await r.call('/api/auth/directory/edit',post({personId:'peer',set:{title:'Owner-approved title'}},ownerAgain.cookie))).status,200);
 assert.equal((await r.call('/api/auth/people/role',post({id:'peer',role:'member'},ownerAgain.cookie))).status,200,'owner can demote a lower administrator');
 assert.equal((await r.call('/api/auth/people/role',post({id:'peer',role:'admin'},ownerAgain.cookie))).status,200);
 assert.equal((await r.call('/api/auth/people/suspend',post({personId:'peer'},ownerAgain.cookie))).status,200,'owner can suspend a lower administrator');
 assert.equal((await r.call('/api/auth/directory/edit',post({personId:'peer',state:'active'},admin.cookie))).status,403,'suspension does not remove administrator protection');
 assert.equal((await r.call('/api/auth/directory/edit',post({personId:'peer',state:'active'},ownerAgain.cookie))).status,200,'owner can restore a lower administrator');
 assert.equal((await r.call('/api/auth/me',{cookie:peer.cookie})).status,401,'completed recovery ended the original hardware session');
});
test('wrangler-installed recovery token is owner-only and one use',async t=>{
 const r=await fixture(t),owner=await register(r,await emailSession(r,'owner@example.com')),emailCookie=await emailSession(r,'owner@example.com'),raw='R'.repeat(43);
 const pending=await r.call('/auth/identity/email/request',post({email:'owner@example.com'}));
 const pendingToken=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 await r.call('/',{action:'recovery-token',token:raw});
 assert.equal((await r.call('/api/auth/recovery/token',post({token:raw},await emailSession(r,'member@example.com')))).status,403);
 assert.equal((await r.call('/api/auth/recovery/token',post({token:raw},emailCookie))).status,200);
 assert.equal((await r.call('/api/auth/recovery/token',post({token:raw},emailCookie))).status,400);
 assert.equal((await r.call('/auth/identity/email/confirm',post({token:pendingToken},cookieOf(pending)))).status,400);
 assert.equal((await r.call('/api/auth/people',{cookie:emailCookie})).status,403);
 assert.equal((await r.call('/api/auth/me',{cookie:owner.cookie})).status,401);
 const replacement=await register(r,emailCookie);assert.equal((await r.call('/api/auth/people',{cookie:replacement.cookie})).status,200);
});

test('organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions',async t=>{
 const r=await fixture(t),owner=await register(r,await emailSession(r,'owner@example.com'));
 const command=async(client,cookie,path,data,status=200)=>{
  const response=await client.call('/api/auth/'+path,post(data,cookie));assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();
 };
 assert.equal((await r.call('/api/auth/organizations/create',post({name:'Foreign'},await emailSession(r,'member@example.com')))).status,403);
 await command(r,owner.cookie,'people/role',{id:'member',role:'admin'});
 const installationAdmin=await register(r,await emailSession(r,'member@example.com'));
 const north=await command(r,owner.cookie,'organizations/create',{name:'Northwind Manufacturing'},201),south=await command(r,owner.cookie,'organizations/create',{name:'Contoso Research'},201);
 const scoped=id=>({origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),async call(path,options){
  const response=await r.call('/org/'+id+path,options);assert.ok(response.status<500,path+' '+await response.clone().text());return response;
 }});
 const a=scoped(north.id),b=scoped(south.id),adminA=await register(a,await emailSession(a,'owner@example.com')),adminB=await register(b,await emailSession(b,'owner@example.com'));
 // Isolated employers reserve custom role design to their own owner. A local
 // legacy administrator's directory authority does not include that choice.
 await command(a,adminA.cookie,'organizations/invite',{email:'organization-admin@example.com',name:'Organization administrator'},201);
 const acceptedAdmin=await emailSession(a,'organization-admin@example.com'),organizationAdminId=(await (await a.call('/api/auth/me',{cookie:acceptedAdmin})).json()).user.id;
 await command(a,adminA.cookie,'people/role',{id:organizationAdminId,role:'admin'});
 const organizationAdmin=await register(a,await emailSession(a,'organization-admin@example.com'));
 const customRole={kind:'role',role:{name:'Organization directory reviewers',rank:50,permissions:['people.view']}};
 const refusedRole=await a.call('/api/auth/roles/preview',post(customRole,organizationAdmin.cookie));assert.equal(refusedRole.status,403);assert.equal((await refusedRole.json()).error,'owner_admin_required');
 const ownerRole=await command(a,adminA.cookie,'roles/preview',customRole);await command(a,adminA.cookie,'roles/apply',{previewId:ownerRole.previewId});
 const rootRole=await command(r,installationAdmin.cookie,'roles/preview',customRole);await command(r,installationAdmin.cookie,'roles/apply',{previewId:rootRole.previewId});
 for(const [client,cookie,canDesignRoles] of [[a,organizationAdmin.cookie,false],[a,adminA.cookie,true],[r,installationAdmin.cookie,true]])assert.equal((await (await client.call('/api/auth/roles',{cookie})).json()).canDesignRoles,canDesignRoles);
 const group=await command(a,adminA.cookie,'groups/create',{name:'Confidential Northwind'},201);
 await command(a,adminA.cookie,'organizations/invite',{email:'contractor@example.com',name:'Cole Reed'},201);
 await command(b,adminB.cookie,'organizations/invite',{email:'contractor@example.com',name:'Cole Reed'},201);
 const memberA=await emailSession(a,'contractor@example.com');
 const onlyA=await (await a.call('/api/auth/organizations',{cookie:memberA})).json();
 assert.deepEqual(onlyA.memberships.map(m=>m.name),['Northwind Manufacturing'],'matching email does not prove the other membership');
 assert.equal((await (await b.call('/api/auth/people',{cookie:adminB.cookie})).json()).find(p=>p.email==='contractor@example.com').status,'invited','activation in A leaves the same email invited in B');
 const memberB=await emailSession(b,'contractor@example.com');
 const personA=(await (await a.call('/api/auth/me',{cookie:memberA})).json()).user,personB=(await (await b.call('/api/auth/me',{cookie:memberB})).json()).user;
 assert.notEqual(personA.id,personB.id,'same-email memberships keep independent identities');
 await scopedUpstreamFlow({r,a,b,adminA,adminB,owner,personA,personB});
 const inB=cookie=>cookie.replaceAll('_'+north.id+'=','_'+south.id+'=');
 assert.equal((await b.call('/api/auth/me',{cookie:inB(memberA)})).status,401,'renaming a synthetic session cookie cannot transplant its authority');

 // First enrollment, its challenge and the credential itself remain local,
 // even though both employers share a browser origin and the same email.
 const firstKey=authenticator(r.origin),enrollment=await a.call('/auth/passkeys/register/options',post({},memberA)),enroll=await enrollment.json();
 assert.equal(enrollment.status,200);
 const registration={transaction:enroll.transaction,response:firstKey.register(enroll.options)},enrollmentBinding=cookieOf(enrollment);
 assert.equal((await b.call('/auth/passkeys/register/verify',post(registration,memberB+'; '+inB(enrollmentBinding)))).status,400,'A enrollment challenge is unavailable in B');
 assert.deepEqual(await (await b.call('/api/auth/methods',{cookie:memberB})).json(),[],'A enrollment attempt creates no B factor');
 const enrolledA=await a.call('/auth/passkeys/register/verify',post(registration,memberA+'; '+enrollmentBinding));assert.equal(enrolledA.status,200);
 const firstCookieA=cookieOf(enrolledA),contractorB=await register(b,memberB);
 assert.equal((await authenticate(b,firstKey)).response.status,400,'A passkey cannot sign in to B');
 assert.equal((await authenticate(a,contractorB.key)).response.status,400,'B passkey cannot sign in to A');
 assert.equal((await authenticate(a,firstKey)).response.status,200);

 // Approval and completion for one membership cannot satisfy its peer's
 // recovery, nor revoke the peer's independently enrolled factor or sessions.
 const recoveryA=await command(a,memberA,'recovery/start',{},201),recoveryB=await command(b,memberB,'recovery/start',{},201);
 await command(a,adminA.cookie,'recovery/approve',{id:recoveryA.id});
 assert.equal((await b.call('/api/auth/recovery/approve',post({id:recoveryA.id},adminB.cookie))).status,404);
 assert.equal((await b.call('/api/auth/recovery/complete',post({id:recoveryA.id},memberB))).status,404);
 assert.equal((await b.call('/api/auth/recovery/complete',post({id:recoveryB.id},memberB))).status,403,'A recovery approval does not release B recovery');
 await command(a,memberA,'recovery/complete',{id:recoveryA.id});
 assert.equal((await a.call('/api/auth/me',{cookie:firstCookieA})).status,401);
 assert.equal((await b.call('/api/auth/me',{cookie:contractorB.cookie})).status,200,'A recovery does not end B sessions');
 assert.equal((await authenticate(b,contractorB.key)).response.status,200,'A recovery does not remove B factor');
 assert.equal((await authenticate(a,firstKey)).response.status,400,'A recovery removes only its own factor');
 await command(b,contractorB.cookie,'recovery/cancel',{id:recoveryB.id});

 // An exact passkey approval is local to its proposal, session and factor.
 const keyA=await mint(a,adminA.cookie,'Northwind preparer'),keyB=await mint(b,adminB.cookie,'Contoso preparer');
 assert.equal((await preparer(b,keyA)).status,401,'A preparer credential confers no B visibility');
 const proposal={kind:'invite_person',target:'approval@example.com',name:'Local approval recipient',reason:'Explicit employer approval required'};
 const proposalA=await file(a,keyA,proposal),proposalB=await file(b,keyB,proposal),proofA=await approvalProof(a,adminA,proposalA);
 assert.equal((await b.call('/api/auth/agents/approve',post(proofA.request.data,adminB.cookie+'; '+inB(proofA.request.cookie.split('; ').at(-1))))).status,400,'A signed approval challenge cannot execute in B');
 assert.equal((await a.call('/api/auth/agents/approve',proofA.request)).status,200);
 const pendingB=await (await b.call('/api/auth/agents',{cookie:adminB.cookie})).json();
 assert.equal(pendingB.proposals.find(p=>p.id===proposalB).status,'pending','A approval leaves B proposal pending');
 assert.ok(!(await (await b.call('/api/auth/people',{cookie:adminB.cookie})).json()).some(p=>p.email===proposal.target),'A approval creates no B account');
 const proofB=await approvalProof(b,adminB,proposalB);proofB.request.data.response=adminA.key.authenticate(proofB.options);
 assert.equal((await b.call('/api/auth/agents/approve',proofB.request)).status,400,'B approval requires its own factor');
 assert.equal((await approve(b,adminB,proposalB)).status,200);

 const both=memberA+'; '+memberB;
 const memberships=await (await a.call('/api/auth/organizations',{cookie:both})).json();
 assert.deepEqual(memberships.memberships.map(m=>m.name).sort(),['Contoso Research','Northwind Manufacturing']);
 const switched=await command(a,both,'organizations/switch',{organizationId:south.id});assert.equal(switched.redirect,'/org/'+south.id+'/app/account');
 assert.equal((await a.call('/api/auth/organizations/switch',post({organizationId:south.id},memberA))).status,403);
 for(const cookie of [owner.cookie,adminB.cookie,memberB])assert.equal((await a.call('/api/auth/me',{cookie})).status,401,'foreign session refused');
 const importA=await command(a,adminA.cookie,'move-in/stage',{fileName:'workers.csv',exportDate:'2026-10-21',text:'user_id,email,name,email_verified\nsynthetic-auth-7,confidential@northwind.example.com,Private Contractor,true\n'},201);
 await command(a,adminA.cookie,'move-in/admit',{batchId:importA.batchId,rows:[0]});
 const ownExport=await a.call('/api/auth/move-in/subjects.csv?batch='+importA.batchId,{cookie:adminA.cookie});assert.equal(ownExport.status,200);assert.ok((await ownExport.text()).includes('confidential@northwind.example.com'));
 assert.equal((await b.call('/api/auth/move-in/subjects.csv?batch='+importA.batchId,{cookie:adminB.cookie})).status,404);
 // Populate real employer credentials before probing installation authority.
 // Only the remote SCIM server is faked; Auth seals and uses its credential.
 const connectorCredential='synthetic-auth-tenancy-1',scim=await (await import('./scim-server.mjs')).scimServer(t,connectorCredential);r.scimServer=scim.url;
 const credentialApp=await command(a,adminA.cookie,'oidc-apps/create',{name:'Employer credential custody',authMethod:'client_secret_basic',redirectUris:['https://custody.example.com/callback']},201);
 assert.ok(credentialApp.clientSecret,'an employer-issued client secret exists');
 await command(a,adminA.cookie,'provisioning/connect',{appId:credentialApp.id,baseUrl:'https://scim.example.com/scim/v2',token:connectorCredential,pushGroups:false},201);
 const connection=await command(a,adminA.cookie,'provisioning/test',{appId:credentialApp.id});assert.equal(connection.ok,true);assert.equal(connection.usersStatus,200);assert.ok(scim.log.some(entry=>entry.path.startsWith('/scim/v2/Users')));
 const assertNoCredentials=text=>{
  for(const secret of [connectorCredential,credentialApp.clientSecret])assert.ok(!text.includes(secret),'a public response/export excludes employer credential values');
  assert.doesNotMatch(text,/"(?:encrypted_private|encryptedPrivate|sealed_token|sealedToken|secret_hash|client_secret|clientSecret|private_key|privateKey|private_jwk|privateJwk|d|p|q|dp|dq|qi|oth|k)"\s*:/,'public issuer and directory responses expose no private key or credential fields');
 };
 const employerExports=['reports/mfa-enrollment?format=csv','roles/export?personId='+personA.id,'roles/audit/export','move-in/subjects.csv?batch='+importA.batchId];
 for(const path of ['me','apps','company-apps','activity',...employerExports]) {
  const response=await a.call('/api/auth/'+path,{cookie:adminA.cookie});assert.equal(response.status,200,path);assertNoCredentials(await response.text());
 }
 const publicIssuer=await a.call('/oidc/jwks',{cookie:owner.cookie});assert.equal(publicIssuer.status,200);const published=await publicIssuer.text();assert.ok(JSON.parse(published).keys.length>0);assertNoCredentials(published);
 const connectorModel=await (await a.call('/api/auth/company-apps',{cookie:adminA.cookie})).json();
 assert.equal(connectorModel.companyApps.find(app=>app.id===credentialApp.id).provisioning.baseUrl,'https://scim.example.com/scim/v2','the credential-free response describes the populated connector');
 const reads=['me','people','directory','directory/groups','apps','activity','agents','move-in','hooks','roles','roles/people','roles/export','resource-apis','delegations','hr-feeds','reports','reports/mfa-enrollment','reports/mfa-enrollment?format=csv'];
 for(const path of reads) {
  const response=await b.call('/api/auth/'+path,{cookie:adminB.cookie});
  assert.equal(response.status,200,path+' '+await response.clone().text());
  assert.ok(!(await response.text()).includes('Confidential Northwind'),path+' cannot read another organization');
 }
 const issuerKeyPair=await generateKeyPair('ES256'),machineJwk={...await exportJWK(issuerKeyPair.publicKey),kid:'synthetic-auth-tenancy-2',alg:'ES256',use:'sig'};
 const isolatedWrites=[
  ['hr-feeds/create',{name:'Foreign source',schedule:'daily',mapping:{sourceId:'ID',email:'Email',state:'State',effectiveAt:'Effective'},fingerprint:'synthetic-auth-invalid',confirm:true}],
  ['hr-feeds/upload',{feedId:'synthetic-auth-foreign',fileName:'foreign.csv',text:'ID,Email,State,Effective'}],
  ['hr-feeds/apply',{feedId:'synthetic-auth-foreign',fileId:'synthetic-auth-file',digest:'synthetic-auth-digest',rows:[0],confirm:true}],
  ['people/invite',{email:'intrusion@example.com'}],
  ['people/role',{personId:personA.id,role:'admin'}],
  ['directory/edit',{personId:personA.id,set:{title:'Installation intrusion'}}],
  ['groups/add',{groupId:group.id,personId:personA.id}],
  ['company-apps/update',{id:credentialApp.id,name:'Installation intrusion'}],
  ['oidc-apps/rotate-secret',{appId:credentialApp.id}],
  ['provisioning/rotate',{appId:credentialApp.id,token:'synthetic-auth-tenancy-3'}],
  ['provisioning/test',{appId:credentialApp.id}],
  ['keys/stage',{alg:'ES256'}],
  ['saml-keys/stage',{}],
  ['agents/mint',{label:'Installation intrusion'}],
  ['move-in/stage',{fileName:'intrusion.csv',exportDate:'2026-10-21',text:'user_id,email,name,email_verified\nsynthetic-auth-tenancy-4,intrusion@example.com,Intrusion,true\n'}],
  ['hooks/register',{point:'registration',url:'https://intrusion.example.com/hook'}],
  ['roles/preview',{kind:'grant',personId:personA.id,roleId:'app-administrator',resources:{view:{apps:[credentialApp.id]},edit:{apps:[credentialApp.id]}}}],
  ['resource-apis/register',{appId:credentialApp.id,name:'Installation intrusion',audience:'https://intrusion.example.com/api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['record:1']}],resources:[{id:'record:1'}]}],
  ['admin-service-apps/create',{name:'Installation intrusion',purpose:'Intrusion',jwks:{keys:[machineJwk]},scopes:['assignments.manage'],resources:{people:[personA.id],groups:[],apps:[credentialApp.id]},expiresAt:new Date(r.now+3600000).toISOString()}],
  ['delegations/agents/register',{name:'Installation intrusion',purpose:'Intrusion',jwks:{keys:[machineJwk]},appIds:[credentialApp.id],personIds:[personA.id],expiresAt:r.now+3600000}],
  ['organizations/invite',{email:'intrusion@example.com'}],
  ['erasure/preview',{kind:'person',target:personA.id}],
 ];
 for(const [role,installationCookie] of [['installation owner',owner.cookie],['installation administrator',installationAdmin.cookie]]) {
  assert.equal((await r.call('/api/auth/people',{cookie:installationCookie})).status,200,role+' has live hardware installation authority');
  for(const cookie of [installationCookie,installationCookie.replace('__Host-auth_session=','__Host-auth_session_'+north.id+'=')]) {
   for(const path of [...new Set([...reads,'company-apps','profile','organizations','roles/audit','erasure/receipts','erasure/journal','erasure/integrity',...employerExports])]) {
    const response=await a.call('/api/auth/'+path,{cookie});assert.equal(response.status,401,role+' isolated read/export '+path);assert.deepEqual(await response.json(),{error:'sign_in_required'});
   }
   for(const [path,data] of isolatedWrites) {
    const response=await a.call('/api/auth/'+path,post(data,cookie));assert.equal(response.status,401,role+' isolated write '+path);assert.deepEqual(await response.json(),{error:'sign_in_required'});
   }
  }
  for(const path of ['me','apps','activity']) {
   const response=await r.call('/api/auth/'+path,{cookie:installationCookie});assert.equal(response.status,200);const text=await response.text();assertNoCredentials(text);assert.ok(!text.includes('Employer credential custody'),'installation models do not project the employer connector');
  }
 }
 const preserved=await (await a.call('/api/auth/company-apps',{cookie:adminA.cookie})).json();assert.equal(preserved.companyApps.find(app=>app.id===credentialApp.id).name,'Employer credential custody');
 assert.ok(!(await (await a.call('/api/auth/people',{cookie:adminA.cookie})).json()).some(person=>person.email==='intrusion@example.com'),'refused installation writes created no employer membership');
 assert.equal((await command(a,adminA.cookie,'provisioning/test',{appId:credentialApp.id})).ok,true,'refused installation writes did not replace the live connector credential');
 assert.equal((await b.call('/api/auth/groups/add',post({groupId:group.id,personId:(await (await b.call('/api/auth/me',{cookie:memberB})).json()).user.id},adminB.cookie))).status,404);
 assert.equal((await b.call('/api/auth/roles/preview',post({kind:'grant',personId:(await (await b.call('/api/auth/me',{cookie:memberB})).json()).user.id,roleId:'app-administrator',resources:{view:{apps:[group.id]},edit:{apps:[group.id]}}},adminB.cookie))).status,404);
 assert.equal((await a.call('/api/auth/organizations/invite',post({email:'escalated@example.com',role:'owner'},adminA.cookie))).status,403);
 await command(a,adminA.cookie,'organizations/invite',{email:'expired@example.com',expiresAt:r.now+1},201);
 r.now+=2;const before=(await r.mails()).length;await a.call('/auth/identity/email/request',post({email:'expired@example.com'}));assert.equal((await r.mails()).length,before,'expired admission sends no sign-in proof');
 await command(a,adminA.cookie,'organizations/invite',{email:'cancelled@example.com'},201);
 await command(a,adminA.cookie,'organizations/cancel-invitation',{email:'cancelled@example.com'});
 const cancelledBefore=(await r.mails()).length;await a.call('/auth/identity/email/request',post({email:'cancelled@example.com'}));assert.equal((await r.mails()).length,cancelledBefore);
 // The same contractor receives one app and one explicitly named recovery case.
 const contractor=await register(a,memberA),contractorId=(await (await a.call('/api/auth/me',{cookie:contractor.cookie})).json()).user.id;
 const appA=await command(a,adminA.cookie,'oidc-apps/create',{name:'Northwind wiki',authMethod:'none',redirectUris:['https://wiki.example.com/callback']},201);
 const otherApp=await command(a,adminA.cookie,'oidc-apps/create',{name:'Restricted payroll',authMethod:'none',redirectUris:['https://payroll.example.com/callback']},201);
 const delegate=async(roleId,resources)=>{const preview=await command(a,adminA.cookie,'roles/preview',{kind:'grant',personId:contractorId,roleId,resources});return command(a,adminA.cookie,'roles/apply',{previewId:preview.previewId});};
 await delegate('app-administrator',{view:{apps:[appA.id]},edit:{apps:[appA.id]}});
 await command(a,contractor.cookie,'roles/command',{action:'/oidc-apps/update',params:{appId:appA.id,name:'Northwind knowledge',redirectUris:['https://wiki.example.com/new-callback']}});
 assert.equal((await a.call('/api/auth/roles/command',post({action:'/oidc-apps/update',params:{appId:otherApp.id,name:'Intrusion'}},contractor.cookie))).status,403);
 await command(a,contractor.cookie,'resource-apis/register',{appId:appA.id,name:'Delegated wiki API',audience:'https://wiki.example.com/api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['page:1']}],resources:[{id:'page:1'}]},201);
 assert.equal((await a.call('/api/auth/resource-apis/register',post({appId:otherApp.id,name:'Forbidden API',audience:'https://payroll.example.com/api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['page:1']}],resources:[{id:'page:1'}]},contractor.cookie))).status,403);
 assert.equal((await (await a.call('/api/auth/resource-apis',{cookie:contractor.cookie})).json()).apis.length,1);
 assert.equal((await a.call('/api/auth/people/role',post({id:contractorId,role:'admin'},contractor.cookie))).status,403);
 await command(a,adminA.cookie,'organizations/invite',{email:'recover@example.com',name:'Recovery employee'},201);
 const worker=await register(a,await emailSession(a,'recover@example.com')),workerId=(await (await a.call('/api/auth/me',{cookie:worker.cookie})).json()).user.id;
 for(const roleId of ['manager','group-owner','app-owner']) {
  const preview=await command(a,adminA.cookie,'roles/preview',{kind:'grant',personId:workerId,roleId,resources:{view:{people:[workerId],apps:[appA.id]},edit:{apps:[appA.id]}}});
  await command(a,adminA.cookie,'roles/apply',{previewId:preview.previewId});
 }
 const workerView=await (await a.call('/api/auth/roles/people?personId='+workerId,{cookie:adminA.cookie})).json();
 assert.equal(workerView.people[0].canResetFactors,true,'manager/group/app ownership does not confer administrator custody');
 const recovery=await command(a,adminA.cookie,'roles/recovery-case',{action:'open',personId:workerId,reason:'Employee reported a lost device'},201);
 await delegate('help-desk',{view:{people:[workerId],cases:[recovery.caseId]},edit:{people:[workerId],cases:[recovery.caseId]}});
 assert.equal((await a.call('/api/auth/directory/edit',post({personId:workerId,set:{manager:(await (await a.call('/api/auth/me',{cookie:adminA.cookie})).json()).user.id}},adminA.cookie))).status,200);
 assert.equal((await a.call('/api/auth/recovery/case-attest',post({caseId:recovery.caseId},adminA.cookie))).status,200);
 await command(a,contractor.cookie,'roles/reset-factors',{personId:workerId,caseId:recovery.caseId,reason:'Verified replacement enrollment'});
 assert.equal((await a.call('/api/auth/me',{cookie:worker.cookie})).status,401);
 await command(a,adminA.cookie,'organizations/invite',{email:'helpdesk@example.com',name:'Help desk verifier'},201);
 const helpdesk=await register(a,await emailSession(a,'helpdesk@example.com')),helpdeskId=(await (await a.call('/api/auth/me',{cookie:helpdesk.cookie})).json()).user.id;
 const helperGrant=await command(a,adminA.cookie,'roles/preview',{kind:'grant',personId:helpdeskId,roleId:'help-desk',resources:{view:{people:[contractorId]},edit:{people:[contractorId]}}});
 await command(a,adminA.cookie,'roles/apply',{previewId:helperGrant.previewId});
 await command(a,adminA.cookie,'directory/edit',{personId:contractorId,state:'suspended'});
 assert.equal((await a.call('/api/auth/roles/command',post({action:'/people/restore',params:{personId:contractorId}},helpdesk.cookie))).status,403,'suspended scoped administrator keeps its protected account rank');
 await command(a,adminA.cookie,'directory/edit',{personId:contractorId,state:'active'});

 const discoveryA=await (await a.call('/.well-known/openid-configuration')).json(),discoveryB=await (await b.call('/.well-known/openid-configuration')).json();
 assert.equal(discoveryA.issuer,r.origin+'/org/'+north.id);assert.equal(discoveryB.issuer,r.origin+'/org/'+south.id);
 // A fresh local email step-up in A cannot refresh a live hardware session in B.
 r.now+=11*60000;
 const proof=await requestProof(a,'owner@example.com',adminA.cookie);
 assert.equal((await b.call('/auth/identity/email/confirm',post({token:proof.token},inB(proof.binding)))).status,400,'A email challenge is unavailable in B');
 const refreshedA=await finishProof(a,proof);assert.equal(refreshedA.status,200);adminA.cookie=cookieOf(refreshedA);
 await command(a,adminA.cookie,'groups/create',{name:'Fresh proof in Northwind'},201);
 const refusedB=await b.call('/api/auth/groups/create',post({name:'Borrowed Northwind step-up'},adminB.cookie+'; '+adminA.cookie));
 assert.equal(refusedB.status,403);assert.equal((await refusedB.json()).error,'local_email_step_up_required');
 assert.equal((await b.call('/auth/passkeys/register/options',post({},adminB.cookie))).status,403,'A step-up cannot authorize B enrollment');
 assert.equal((await b.call('/api/auth/me',{cookie:adminB.cookie})).status,200,'B session still permits ordinary reads');
 const refreshedB=await finishProof(b,await requestProof(b,'owner@example.com',adminB.cookie));assert.equal(refreshedB.status,200);adminB.cookie=cookieOf(refreshedB);
 await command(b,adminB.cookie,'groups/create',{name:'Independent proof in Contoso'},201);

 const keysA=await (await a.call('/oidc/jwks')).json(),keysB=await (await b.call('/oidc/jwks')).json();assert.ok(keysA.keys.every(ka=>keysB.keys.every(kb=>ka.kid!==kb.kid)),'issuer private keys are distinct');
});

import {continuityFlow} from './continuity-flow.mjs';
test('scheduled continuity drill exercises protected lost-factor recovery, upstream outage and expired signing-certificate replacement',continuityFlow);

 test('voluntary independent identity pairs keep employer release notices private through installation erasure, holds, membership erasure and creator removal',identityPairsFlow);

import {totpFlow,factorLossFlow,recoveryCodesFlow,assuranceFlow} from './factors-flow.mjs';
test('native TOTP enrollment protects secrets, refuses replay and preserves administrator assurance',totpFlow);
test('lost-factor removal ends current sessions and preserves a replacement passkey',factorLossFlow);
test('single-use recovery codes rotate, refuse foreign or privileged use and end after replacement enrollment',recoveryCodesFlow);
test('sensitive app factor policy rechecks assurance at authorization and token issuance',assuranceFlow);
