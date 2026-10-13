import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {openRuntime,cookieOf,emailSession} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {issueClient,beginPasskey,finishPasskey,requestProof,finishProof,sessionCookie,browserCookie} from './policy-helpers.mjs';
// Google trusts a verified address only at gmail.com (or with a matching hd claim),
// so the owner's address is a fresh gmail.com mailbox name generated per run.
const ownerGmail=`owner-${randomBytes(6).toString('hex')}@gmail.com`;
async function fixture(t,preset='google',subjectEmails={}) {
 const r=await openRuntime();t.after(()=>r.close());await r.person('owner',ownerGmail,'owner');await r.person('member','member@company.example');
 const keys=await generateKeyPair('RS256'),jwk={...await exportJWK(keys.publicKey),kid:'upstream',alg:'RS256',use:'sig'};
 const issuer=preset==='google'?'https://accounts.google.com':preset==='microsoft'?'https://login.microsoftonline.com/tenant-id/v2.0':'https://company.okta.com/oauth2/default';
 r.upstreamProviders=[{id:'company',preset,...(preset==='microsoft'?{tenant:'tenant-id'}:preset==='okta'?{issuer}:{}),clientId:'auth-upstream',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only',subjectEmails}];
 r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[jwk]}};
 r.login=async(claims,provider='company')=>{
  const started=await r.call(`/auth/oidc/${provider}/start`,{method:'POST',data:{returnTo:'/app/account'}});assert.equal(started.status,303,await started.clone().text());
  const location=new URL(started.headers.get('location'));
  r.upstream.tokens={id_token:await new SignJWT({...claims,nonce:location.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:'upstream'}).setIssuer(issuer).setAudience('auth-upstream').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(keys.privateKey)};
  return r.call(`/auth/oidc/${provider}/callback?`+new URLSearchParams({code:'upstream-code',state:location.searchParams.get('state'),iss:issuer}),{cookie:cookieOf(started)});
 };
 return r;
}
test('Google verified gmail is trusted; unhosted business email is refused and upstream never grants admin',async t=>{
 const r=await fixture(t),allowed=await r.login({sub:'gmail-subject',email:ownerGmail,email_verified:true});assert.equal(allowed.status,303);
 const authCookie=allowed.headers.getSetCookie().find(c=>c.startsWith('__Host-auth_session=')).split(';')[0];assert.equal((await r.call('/api/auth/people',{cookie:authCookie})).status,403);
 assert.equal((await r.login({sub:'company-unhosted',email:'member@company.example',email_verified:true})).status,403);
 assert.equal((await r.login({sub:'company-hosted',email:'member@company.example',email_verified:true,hd:'company.example'})).status,303);
 assert.equal((await r.login({sub:'gmail-subject',email:'member@company.example',email_verified:true,hd:'company.example'})).status,403);
});
test('Microsoft and Okta require configured subject association and retain actual local email-proof age',async t=>{
 for(const preset of ['microsoft','okta']) {
  const r=await fixture(t,preset,{'known-subject':'member@company.example'});
  assert.equal((await r.login({sub:'unknown-subject',email:'member@company.example',email_verified:true})).status,403);
  const associated=await r.login({sub:'known-subject',email:'untrusted@elsewhere.example',email_verified:true});assert.equal(associated.status,303);assert.equal(associated.headers.get('location'),'/signin?reproof=1');
  assert.equal(await r.db.prepare("SELECT verified_at FROM auth_emails WHERE person_id='member'").first(),null);
  await emailSession(r,'member@company.example');const completed=await r.login({sub:'known-subject'});assert.equal(completed.status,303);assert.equal(completed.headers.get('location'),'/app/account');
 }
});

const post=(data={},cookie)=>({method:'POST',data,cookie});
const googlePerson=(address='member@company.example',sub='member-subject')=>({sub,email:address,email_verified:true,hd:address.split('@')[1]});
const policy=(r,cookie,providerId='company',domain='company.example')=>r.call('/api/auth/people/domain-rule',post({domain,providerId},cookie));
async function policyFixture(t,preset='google',subjects={}) {
 const r=await fixture(t,preset,subjects);
 const emailCookie=await emailSession(r,ownerGmail);r.owner=await register(r,emailCookie);r.ownerEmail=emailCookie;
 r.upstreamProviders.push({...r.upstreamProviders[0],id:'other'});
 return r;
}

test('domain policy requires an Auth passkey admin, separates enrollment, and exempts only the owner',async t=>{
 const r=await policyFixture(t),memberEmail=await emailSession(r,'member@company.example'),member=await register(r,memberEmail);
 const pending=await requestProof(r,'member@company.example');
 assert.equal((await policy(r,r.ownerEmail)).status,403);
 assert.equal((await policy(r,member.cookie)).status,403);
 assert.equal((await policy(r,r.owner.cookie,'missing')).status,400);
 assert.equal((await policy(r,r.owner.cookie)).status,200);
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_domains').first()).n,0);
 assert.equal((await r.call('/api/auth/me',{cookie:memberEmail})).status,401);
 assert.equal((await r.call('/api/auth/people',{cookie:member.cookie})).status,401);
 assert.equal((await finishProof(r,pending)).status,403);
 const count=(await r.mails()).length;
 const excluded=await r.call('/auth/identity/email/request',post({email:'member@company.example',providerId:'company',amr:['oidc']}));
 const unknown=await r.call('/auth/identity/email/request',post({email:'nobody@company.example'}));
 assert.equal(excluded.status,202);assert.deepEqual(await excluded.json(),await unknown.json());assert.equal((await r.mails()).length,count);
 assert.equal((await authenticate(r,member.key)).response.status,403);
 assert.equal((await r.login(googlePerson(),'other')).status,403);
 const correct=await r.login(googlePerson());assert.equal(correct.status,303);const upstream=sessionCookie(correct);
 assert.equal((await r.call('/api/auth/me',{cookie:upstream})).status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:upstream})).status,403);
 // Even an oidc label cannot satisfy a rule without verified adapter evidence.
 await r.db.prepare("UPDATE auth_sessions SET amr='[\"oidc\",\"hwk\"]' WHERE upstream_proof_id IS NULL AND person_id='member'").run();
 assert.equal((await r.call('/api/auth/me',{cookie:member.cookie})).status,401);
 assert.equal((await policy(r,r.owner.cookie,'company','gmail.com')).status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:r.owner.cookie})).status,200);
 assert.equal((await authenticate(r,r.owner.key)).response.status,200);
 assert.equal((await r.call('/api/auth/me',{cookie:await emailSession(r,ownerGmail)})).status,200);
 assert.equal((await policy(r,r.owner.cookie,'')).status,200);
 assert.equal((await r.call('/api/auth/me',{cookie:await emailSession(r,'member@company.example')})).status,200);
 const ownerProvider=await r.login(googlePerson(ownerGmail,'owner-subject'));assert.equal(ownerProvider.status,303);
 r.upstreamProviders=[];
 const exempt=await finishPasskey(r,await beginPasskey(r,r.owner.key,sessionCookie(ownerProvider)));assert.equal(exempt.status,200);
 assert.equal((await policy(r,sessionCookie(exempt),'','gmail.com')).status,403);
 const ownerConfirmed=await finishProof(r,await requestProof(r,ownerGmail,sessionCookie(exempt)));assert.equal(ownerConfirmed.status,200);
 assert.equal((await policy(r,sessionCookie(ownerConfirmed),'','gmail.com')).status,200);
});

test('verified upstream email and owner exemption cannot replace fresh Auth email step-up',async t=>{
 const r=await policyFixture(t);r.now+=11*60000;
 const upstream=await r.login(googlePerson(ownerGmail,'owner-subject'));assert.equal(upstream.status,303);
 assert.equal((await policy(r,r.owner.cookie)).status,403,'upstream proof cannot refresh an older browser session');
 const hardware=await finishPasskey(r,await beginPasskey(r,r.owner.key,sessionCookie(upstream)));assert.equal(hardware.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(hardware)})).status,200);
 assert.equal((await policy(r,sessionCookie(hardware))).status,403);
 const confirmed=await finishProof(r,await requestProof(r,ownerGmail,sessionCookie(hardware)));assert.equal(confirmed.status,200);
 assert.equal((await policy(r,sessionCookie(confirmed),'company','gmail.com')).status,200);
 r.now+=10*60000+1;
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(confirmed)})).status,200,'owner remains exempt from the provider policy');
 assert.equal((await policy(r,sessionCookie(confirmed),'','gmail.com')).status,403);
});

test('matching provider proof survives Auth email, passkey enrollment, authentication and approved recovery',async t=>{
 const r=await policyFixture(t,'okta',{'member-subject':'member@company.example'});
 assert.equal((await r.call('/api/auth/people/role',post({id:'member',role:'admin'},r.owner.cookie))).status,200);
 assert.equal((await policy(r,r.owner.cookie)).status,200);
 const login=await r.login({sub:'member-subject'});assert.equal(login.status,303);
 const mailProof={binding:browserCookie(login),token:new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token')};
 assert.equal((await finishProof(r,{...mailProof,binding:undefined})).status,400);
 const confirmed=await finishProof(r,mailProof);assert.equal(confirmed.status,200);const emailCookie=sessionCookie(confirmed);
 assert.equal((await r.call('/api/auth/people',{cookie:emailCookie})).status,403);
 const member=await register(r,emailCookie);assert.equal((await r.call('/api/auth/people',{cookie:member.cookie})).status,200);
 assert.equal((await policy(r,member.cookie,'company','another.example')).status,200);
 const authenticated=await finishPasskey(r,await beginPasskey(r,member.key,emailCookie));assert.equal(authenticated.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(authenticated)})).status,200);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},emailCookie))).status,403);
 const started=await r.call('/api/auth/recovery/start',post({},emailCookie));assert.equal(started.status,201);const recovery=await started.json();
 assert.equal((await r.call('/api/auth/recovery/approve',post({id:recovery.id},r.owner.cookie))).status,200);
 assert.equal((await r.call('/api/auth/recovery/complete',post({id:recovery.id},emailCookie))).status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:emailCookie})).status,403);
 const recovered=await register(r,emailCookie);assert.equal((await r.call('/api/auth/people',{cookie:recovered.cookie})).status,200);
 assert.equal((await authenticate(r,recovered.key)).response.status,403);
 // Reproof after thirty days starts only after a fresh matching OIDC response.
 r.now+=31*86400000;const before=(await r.mails()).length;
 assert.equal((await authenticate(r,recovered.key)).response.status,403);assert.equal((await r.mails()).length,before);
 const stale=await r.login({sub:'member-subject'});assert.equal(stale.status,303);assert.equal((await r.mails()).length,before+1);
 const renewed=await finishProof(r,{binding:browserCookie(stale),token:new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token')});assert.equal(renewed.status,200);
 const hardware=await finishPasskey(r,await beginPasskey(r,recovered.key,sessionCookie(renewed)));assert.equal(hardware.status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:sessionCookie(hardware)})).status,200);
});

test('policy changes and missing configuration stop pending proofs, passkeys, recovery and code redemption',async t=>{
 const r=await policyFixture(t),member=await register(r,await emailSession(r,'member@company.example'));
 const client=await issueClient(r),beforeRule=await client.authorize(member.cookie);
 assert.ok(beforeRule.code);assert.equal((await policy(r,r.owner.cookie)).status,200);
 assert.equal((await client.redeem(beforeRule)).status,400);
 const login=await r.login(googlePerson()),upstream=sessionCookie(login);
 const email=await finishProof(r,await requestProof(r,'member@company.example',upstream));assert.equal(email.status,200);const emailCookie=sessionCookie(email);
 const passkey=await beginPasskey(r,member.key,emailCookie),proof=await requestProof(r,'member@company.example',emailCookie),grant=await client.authorize(emailCookie);
 assert.ok(grant.code);
 const started=await r.call('/api/auth/recovery/start',post({},emailCookie));assert.equal(started.status,201);const recovery=await started.json();
 assert.equal((await policy(r,r.owner.cookie,'other')).status,200);
 assert.equal((await r.call('/api/auth/me',{cookie:emailCookie})).status,401);
 assert.equal((await client.authorize(emailCookie)).code,null);
 assert.equal((await client.redeem(grant)).status,400);
 assert.equal((await finishProof(r,proof)).status,403);
 assert.equal((await finishPasskey(r,passkey)).status,403);
 assert.equal((await r.call('/api/auth/recovery/complete',post({id:recovery.id},emailCookie))).status,401);
 assert.equal((await r.login(googlePerson())).status,403);
 const other=await r.login(googlePerson(),'other');assert.equal(other.status,303);const otherCookie=sessionCookie(other);
 assert.equal((await client.redeem(await client.authorize(otherCookie))).status,200);
 const missingGrant=await client.authorize(otherCookie);r.upstreamProviders=r.upstreamProviders.filter(p=>p.id!=='other');
 assert.equal((await r.call('/api/auth/me',{cookie:otherCookie})).status,401);
 assert.equal((await client.redeem(missingGrant)).status,400);
 const before=(await r.mails()).length;assert.equal((await r.call('/auth/identity/email/request',post({email:'member@company.example'}))).status,202);assert.equal((await r.mails()).length,before);
 assert.equal((await policy(r,r.owner.cookie,'')).status,200);
 assert.equal((await r.call('/api/auth/people',{cookie:r.owner.cookie})).status,200);
});

test('required provider enrollment respects exact allowed domains and never supplies Auth email enrollment proof',async t=>{
 const r=await policyFixture(t);assert.equal((await policy(r,r.owner.cookie)).status,200);
 assert.equal((await r.login(googlePerson('new@company.example','new-subject'))).status,403);
 assert.equal((await r.call('/api/auth/people/domain',post({domain:'company.example'},r.owner.cookie))).status,201);
 assert.equal((await r.login(googlePerson('new@sub.company.example','sub-subject'))).status,403);
 assert.equal((await r.login(googlePerson('new@company.example','new-subject'),'other')).status,403);
 const admitted=await r.login(googlePerson('new@company.example','new-subject'));assert.equal(admitted.status,303);const upstream=sessionCookie(admitted);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},upstream))).status,403);
 const email=await finishProof(r,await requestProof(r,'new@company.example',upstream));assert.equal(email.status,200);
 const enrolled=await register(r,sessionCookie(email));assert.equal((await r.call('/api/auth/me',{cookie:enrolled.cookie})).status,200);
 assert.equal((await r.login(googlePerson('someone@company.example','new-subject'))).status,403);
 r.upstreamProviders[0].clientId='changed-client';
 assert.equal((await r.call('/api/auth/me',{cookie:enrolled.cookie})).status,401);
 assert.equal((await r.login(googlePerson('new@company.example','new-subject'))).status,403);
 r.upstreamProviders[0].clientId='auth-upstream';
 // A rule on the parent does not restrict an independently allowed subdomain.
 assert.equal((await r.call('/api/auth/people/domain',post({domain:'sub.company.example'},r.owner.cookie))).status,201);
 assert.equal((await r.call('/api/auth/me',{cookie:await emailSession(r,'new@sub.company.example')})).status,200);
 r.now+=86400001;assert.equal((await r.call('/api/auth/me',{cookie:enrolled.cookie})).status,401);
 assert.equal((await authenticate(r,enrolled.key)).response.status,403);
});

test('new exact-domain Microsoft and Okta people complete the bound Auth email proof after activation',async t=>{
 for(const preset of ['microsoft','okta']) {
  const r=await policyFixture(t,preset,{'new-subject':'new@company.example'});
  assert.equal((await r.call('/api/auth/people/domain',post({domain:'company.example'},r.owner.cookie))).status,201);
  assert.equal((await policy(r,r.owner.cookie)).status,200);
  const admitted=await r.login({sub:'new-subject',email:'untrusted@elsewhere.example',email_verified:true});assert.equal(admitted.status,303);
  const confirmation=await finishProof(r,{binding:browserCookie(admitted),token:new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token')});
  assert.equal(confirmation.status,200);
  const enrolled=await register(r,sessionCookie(confirmation));assert.equal((await r.call('/api/auth/me',{cookie:enrolled.cookie})).status,200);
 }
});
