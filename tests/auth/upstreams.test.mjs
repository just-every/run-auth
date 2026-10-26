import {federationFlow} from './federation-flow.mjs';
import {verifyDomains} from './domain-helpers.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {cookieOf,emailSession} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {passkeyPerson,mint,preparer} from './agents-helpers.mjs';
import {issueClient,beginPasskey,finishPasskey,requestProof,finishProof,sessionCookie,browserCookie} from './policy-helpers.mjs';
import {upstreamFixture as fixture,ownerGmail} from './upstream-helpers.mjs';
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
 await verifyDomains(t,r,r.owner.cookie,['company.example','gmail.com']);
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
 await verifyDomains(t,r,member.cookie,['another.example']);
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
 await verifyDomains(t,r,r.owner.cookie,['sub.company.example']);
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

// Google (company) and Okta (work) at their own network edges, for people who connect a second identity.
async function twoUpstreams(t) {
 const r=await fixture(t,'google'),oktaKeys=await generateKeyPair('RS256'),jwk={...await exportJWK(oktaKeys.publicKey),kid:'work-upstream',alg:'RS256',use:'sig'},oktaIssuer='https://company.okta.com/oauth2/default';
 const people={'okta-member':'member@company.example','okta-bob':'bob@company.example','okta-erin':'erin@company.example'};
 r.upstreamProviders.push({id:'work',preset:'okta',issuer:oktaIssuer,clientId:'auth-work',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only',subjectEmails:people});
 const edge={discovery:{issuer:oktaIssuer,authorization_endpoint:oktaIssuer+'/authorize',token_endpoint:oktaIssuer+'/token',jwks_uri:oktaIssuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true},jwks:{keys:[jwk]}};
 r.upstreams={'https://company.okta.com':edge};
 await r.person('bob','bob@company.example');await r.person('erin','erin@company.example');await r.person('carol','carol@company.example');
 // Start connecting a provider from a signed-in browser, then answer as that provider would.
 r.connect=async(cookie,provider,claims,{extra={},confirm=true}={})=>{
  const started=await r.call('/api/auth/profile/links/start',post({providerId:provider,confirm},cookie));
  if(started.status!==200)return {started};
  const location=new URL((await started.json()).redirect),jar=[cookie,...started.headers.getSetCookie().map(c=>c.split(';')[0])].join('; ');
  const work=provider==='work',issuer=work?oktaIssuer:r.issuer,edgeOf=work?edge:r.upstream;
  edgeOf.tokens={id_token:await new SignJWT({...claims,nonce:location.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:work?'work-upstream':'upstream'}).setIssuer(issuer).setAudience(work?'auth-work':'auth-upstream').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(work?oktaKeys.privateKey:r.keys.privateKey)};
  const callback=r.call(`/auth/oidc/${provider}/callback?`+new URLSearchParams({code:'upstream-code',state:location.searchParams.get('state'),iss:issuer}),{cookie:jar,...extra});
  return {started,jar,callback,response:extra.barrier?undefined:await callback};
 };
 return r;
}
const bindings=async(r,personId)=>(await r.db.prepare('SELECT issuer,subject FROM oa_external_identities WHERE operator_id=?').bind(personId).all()).results;
const linkedTo=async(r,cookie)=>(await (await r.call('/api/auth/profile',{cookie})).json()).links.map(l=>l.providerId);

test('a signed-in person connects a second proven identity after confirming, and disconnects it; an email collision, a foreign subject, a replay and a concurrent binding are refused',async t=>{
 const r=await twoUpstreams(t),member=await emailSession(r,'member@company.example'),bob=await emailSession(r,'bob@company.example');
 // Each door needs a session, the explicit confirmation, a fresh local email proof and a configured provider.
 assert.equal((await r.call('/api/auth/profile/links/start',post({providerId:'work',confirm:true}))).status,401);
 for(const [data,status,error] of [[{providerId:'work'},400,'confirmation_required'],[{providerId:'nowhere',confirm:true},400,'unknown_provider']]){const refused=await r.call('/api/auth/profile/links/start',post(data,member));assert.deepEqual([refused.status,(await refused.json()).error],[status,error]);}
 r.now+=11*60000;const stale=await r.call('/api/auth/profile/links/start',post({providerId:'work',confirm:true},member));assert.equal(stale.status,403);assert.equal((await stale.json()).error,'local_email_step_up_required');r.now-=11*60000;
 // The address Okta proves is Bob's: connecting it to someone else's account is refused and nothing is bound.
 const collision=await r.connect(member,'work',{sub:'okta-bob'});assert.equal(collision.response.headers.get('location'),'/app/account?link=upstream_email_collision');
 assert.deepEqual(await bindings(r,'member'),[]);
 // Bob connects his own identity; Member then cannot take that subject, whatever address it carries.
 const bobs=await r.connect(bob,'work',{sub:'okta-bob'});assert.equal(bobs.response.status,303);assert.equal(bobs.response.headers.get('location'),'/app/account?link=connected');
 assert.equal(bobs.response.headers.getSetCookie().some(c=>/auth_session=[^;]/.test(c)),false,'connecting never starts a session');
 assert.deepEqual(await linkedTo(r,bob),['work']);
 const foreign=await r.connect(member,'work',{sub:'okta-bob'});assert.equal(foreign.response.headers.get('location'),'/app/account?link=upstream_subject_bound');
 assert.deepEqual(await bindings(r,'member'),[]);
 // Member's own: connected once. The provider's answer replayed finds the request spent.
 const own=await r.connect(member,'work',{sub:'okta-member'});assert.equal(own.response.headers.get('location'),'/app/account?link=connected');
 assert.deepEqual(await linkedTo(r,member),['work']);
 const replay=await r.call(`/auth/oidc/work/callback?`+new URLSearchParams({code:'upstream-code',state:'x',iss:'https://company.okta.com/oauth2/default'}),{cookie:own.jar});assert.notEqual(replay.headers.get('location'),'/app/account?link=connected');
 assert.equal((await bindings(r,'member')).length,1);
 const again=await r.connect(member,'work',{sub:'okta-member'});assert.equal(again.response.headers.get('location'),'/app/account?link=already_linked');
 // Disconnecting needs the confirmation too, and ends exactly that binding.
 assert.equal((await r.call('/api/auth/profile/links/unlink',post({providerId:'work'},member))).status,400);
 assert.equal((await r.call('/api/auth/profile/links/unlink',post({providerId:'work',confirm:true},member))).status,200);
 assert.deepEqual(await bindings(r,'member'),[]);assert.deepEqual(await linkedTo(r,bob),['work']);
 assert.equal((await r.call('/api/auth/profile/links/unlink',post({providerId:'work',confirm:true},member))).status,404);
 const trail=(await r.db.prepare("SELECT a.event,a.actor_id,d.detail FROM auth_activity a LEFT JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event LIKE 'identity_%' ORDER BY a.id").all()).results;
 assert.deepEqual(trail.map(e=>[e.event,e.actor_id,e.event==='identity_link_refused'?JSON.parse(e.detail).reason:null]),[['identity_link_refused','member','upstream_email_collision'],['identity_linked','bob',null],['identity_link_refused','member','upstream_subject_bound'],['identity_linked','member',null],['identity_link_refused','member','already_linked'],['identity_unlinked','member',null]]);
 // Two people answering with the same Google subject at once: one binding.
 const carol=await emailSession(r,'carol@company.example');
 const racers=await Promise.all([[member,'member@company.example'],[carol,'carol@company.example']].map(async([cookie,address])=>{
  const started=await r.call('/api/auth/profile/links/start',post({providerId:'company',confirm:true},cookie)),location=new URL((await started.json()).redirect);
  return {jar:[cookie,...started.headers.getSetCookie().map(c=>c.split(';')[0])].join('; '),location,address};
 }));
 const answers=[];
 for(const racer of racers) {
  r.upstream.tokens={id_token:await new SignJWT({sub:'shared-google-subject',email:racer.address,email_verified:true,hd:'company.example',nonce:racer.location.searchParams.get('nonce')}).setProtectedHeader({alg:'RS256',kid:'upstream'}).setIssuer(r.issuer).setAudience('auth-upstream').setIssuedAt(Math.floor(r.now/1000)).setExpirationTime(Math.floor(r.now/1000)+120).sign(r.keys.privateKey)};
  answers.push(r.call('/auth/oidc/company/callback?'+new URLSearchParams({code:'upstream-code',state:racer.location.searchParams.get('state'),iss:r.issuer}),{cookie:racer.jar,barrier:{name:'link-race',size:2}}));
 }
 const outcomes=await Promise.all(answers);assert.deepEqual(outcomes.map(x=>x.headers.get('location')).sort(),['/app/account?link=connected','/app/account?link=upstream_subject_bound']);
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM oa_external_identities WHERE subject='shared-google-subject'").first()).n,1);
});

test('an agent proposal, imported metadata or a matching email never connects an identity, and the last usable sign-in cannot be disconnected',async t=>{
 const r=await twoUpstreams(t),ownerCookie=await emailSession(r,ownerGmail),owner=await register(r,ownerCookie);
 // An agent can suggest administration, but "link this identity" is not something it can file.
 const key=await mint(r,owner.cookie,'Directory agent');
 const filed=await preparer(r,key,{method:'POST',data:{kind:'link_identity',target:'member@company.example',reason:'matches an Okta user'}});assert.equal(filed.status,400);
 // Staged and imported rows with a provider's id data bind nothing.
 const imported=await r.call('/api/auth/directory/source',post({source:'hr',records:[{sourceId:'W-1',email:'member@company.example',fields:{department:'Sales',issuer:'https://company.okta.com/oauth2/default',subject:'okta-member'}}]},owner.cookie));
 assert.deepEqual((await imported.json()).outcomes.map(o=>o.outcome),['review_required']);
 assert.deepEqual(await bindings(r,'member'),[]);
 // Erin signs in with Google, which her domain requires: her only way in is that provider.
 const upstream=sessionCookie(await r.login(googlePerson('erin@company.example','erin-google')));
 const confirmed=await finishProof(r,await requestProof(r,'erin@company.example',upstream)),erin=sessionCookie(confirmed);
 await verifyDomains(t,r,owner.cookie,['company.example']);
 await r.db.prepare("INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) VALUES('company.example','company','owner',?)").bind(r.now).run();
 assert.equal((await r.call('/api/auth/me',{cookie:erin})).status,200);
 const last=await r.call('/api/auth/profile/links/unlink',post({providerId:'company',confirm:true},erin));assert.equal(last.status,409);assert.equal((await last.json()).error,'last_sign_in');
 assert.equal((await bindings(r,'erin')).length,1);
 // A second identity can be connected and removed; the required one stays.
 const second=await r.connect(erin,'work',{sub:'okta-erin'});assert.equal(second.response.headers.get('location'),'/app/account?link=connected');assert.equal((await bindings(r,'erin')).length,2);
 assert.equal((await r.call('/api/auth/profile/links/unlink',post({providerId:'work',confirm:true},erin))).status,200);
 assert.equal((await r.call('/api/auth/profile/links/unlink',post({providerId:'company',confirm:true},erin))).status,409);
 // With no required provider her email address is still a way in, so the last binding can go.
 await r.db.prepare('DELETE FROM oa_domain_rules').run();
 assert.equal((await r.call('/api/auth/profile/links/unlink',post({providerId:'company',confirm:true},erin))).status,200);
 assert.deepEqual(await bindings(r,'erin'),[]);
});

test('delegated federation tests a representative without granting a session, previews exact immutable mappings, activates with owner consent and refuses drift and collisions',federationFlow);
