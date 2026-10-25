import assert from 'node:assert/strict';
import {X509Certificate} from 'node:crypto';
import {openRuntime,emailSession} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {passkeyPerson,post} from './agents-helpers.mjs';
import {securityReceiver} from './continuity-security.mjs';
import {requestProof,finishProof,sessionCookie} from './policy-helpers.mjs';
import {idpCertificates,serviceProvider,spCredentials,metadataOf,addApp,signIn,posted} from './saml-helpers.mjs';

const identities={owner:['synthetic-auth-1','synthetic-auth-1@emergency.example.com'],admin:['synthetic-auth-2','synthetic-auth-2@company.example.com'],worker:['synthetic-auth-3','synthetic-auth-3@company.example.com'],emergency:['synthetic-auth-20','synthetic-auth-20@emergency.example.com']};

// A scheduled rehearsal of the existing root-installation gates. The fixture
// clock ages a genuinely issued certificate; it never installs recovery authority.
export async function continuityFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());
 r.now=Date.now()-6*365*86400000;
 const expired=await idpCertificates(r);
 assert.ok(Date.parse(new X509Certificate(expired[0]).validTo)<Date.now(),'fixture signing certificate has actually expired');
 r.now=Date.now();r.tick=()=>{r.now=Date.now();};
 const owner=await passkeyPerson(r,...identities.owner,'owner');
 const spare=await register(r,owner.cookie);
 const admin=await passkeyPerson(r,...identities.admin,'admin');
 const lostKey=await register(r,admin.cookie);
 const worker=await passkeyPerson(r,...identities.worker);
 const backup=await passkeyPerson(r,...identities.emergency,'admin'),backupSpare=await register(r,backup.cookie);
 const command=async(path,data,cookie,status=200)=>{
  const response=await r.call('/api/auth/'+path,post(data,cookie));
  assert.equal(response.status,status,path);return response.json();
 };
 const security=await securityReceiver(t,r,owner);

 // Lost phone and key: email can request recovery, but cannot enroll around
 // the hardware gate or approve its own request. A separate owner approves.
 const email=await emailSession(r,identities.admin[1]);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},email))).status,403);
 const cancelled=await command('recovery/start',{},email,201);
 await command('recovery/approve',{id:cancelled.id},worker.cookie,403);
 await command('recovery/approve',{id:cancelled.id},admin.cookie,403);
 await command('recovery/complete',{id:cancelled.id},email,403);
 const notices=await (await r.call('/api/auth/notices',{cookie:admin.cookie})).json();
 assert.ok(notices.some(n=>n.recovery_id===cancelled.id),'existing hardware session receives the recovery notice');
 await r.restart();
 const persisted=await (await r.call('/api/auth/notices',{cookie:admin.cookie})).json();
 assert.ok(persisted.some(n=>n.recovery_id===cancelled.id),'notice survives runtime restart');
 await security.resume(cancelled.id);
 const beforeApproval=(await r.mails()).filter(m=>m.to===identities.admin[1]).length;
 await command('recovery/approve',{id:cancelled.id},owner.cookie);
 assert.equal((await r.mails()).filter(m=>m.to===identities.admin[1]).length,beforeApproval+1,'the affected employee is notified when recovery is approved');
 const beforeCancel=(await r.mails()).filter(m=>m.to===identities.admin[1]).length;
 await command('recovery/cancel',{id:cancelled.id},admin.cookie);
 assert.equal((await r.mails()).filter(m=>m.to===identities.admin[1]).length,beforeCancel+1);
 await security.assertDelivered(cancelled.id,['recovery.requested','recovery.approved','recovery.cancelled']);
 await command('recovery/complete',{id:cancelled.id},email,404);
 await command('recovery/approve',{id:cancelled.id},owner.cookie,404);
 assert.equal((await authenticate(r,lostKey.key)).response.status,200,'cancellation preserves the existing factor');
 assert.ok((await (await r.call('/api/auth/notices',{cookie:admin.cookie})).json()).some(n=>n.recovery_id===cancelled.id),'cancellation does not erase the notice');
 const recovery=await command('recovery/start',{},email,201);
 await command('recovery/approve',{id:recovery.id},spare.cookie);
 const beforeComplete=(await r.mails()).filter(m=>m.to===identities.admin[1]).length;
 await command('recovery/complete',{id:recovery.id},email);
 assert.equal((await r.mails()).filter(m=>m.to===identities.admin[1]).length,beforeComplete+1);
 await security.assertDelivered(recovery.id,['recovery.requested','recovery.approved','recovery.completed']);
 await r.restart();
 const finalNotices=await(await r.call('/api/auth/notices',{cookie:email})).json();assert.ok(finalNotices.some(n=>n.recovery_id===recovery.id),'completion notice remains in the surviving email session');
 await command('recovery/complete',{id:recovery.id},email,404);
 assert.equal((await r.call('/api/auth/me',{cookie:admin.cookie})).status,401);
 for(const key of [admin.key,lostKey.key])assert.equal((await authenticate(r,key)).response.status,400,'lost factor cannot be replayed after recovery');
 const replacement=await register(r,email);
 assert.equal((await authenticate(r,replacement.key)).response.status,200);

 await upstreamOutage(r,owner,worker,backupSpare,command);
 await expiredCertificate(r,owner,expired,command,t);
 t.diagnostic('MEASURED Auth certificate-date refusal before assertion release and independently validated replacement; lost-factor recovery, independent higher-rank approval, redundant owner factor, durable notices, cancellation, replay refusal, required-upstream refusal and owner recovery, expired-certificate replacement');
 t.diagnostic('MEASURED separately held backup administrator and redundant hardware; local owner recovery retains the explicit AUTH-IDENTITY-001 emergency-token exception');
}

async function upstreamOutage(r,owner,worker,backup,command) {
 const issuer='https://accounts.google.com';
 r.upstreamProviders=[{id:'synthetic-auth-4',preset:'google',clientId:'synthetic-auth-5',clientSecret:'synthetic-auth-6',tokenAuthMethod:'client_secret_basic'}];
 // Only the upstream HTTP edge is simulated; no upstream identity or session
 // is fabricated in the database. Discovery succeeds before the edge is lost.
 r.upstream={discovery:{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',jwks_uri:issuer+'/keys',response_types_supported:['code'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_basic'],authorization_response_iss_parameter_supported:true}};
 const started=await r.call('/auth/oidc/synthetic-auth-4/start',post());assert.equal(started.status,303);
 const redirect=new URL(started.headers.get('location'));
 await command('people/domain-rule',{domain:'company.example.com',providerId:'synthetic-auth-4'},owner.cookie);
 const callback='/auth/oidc/synthetic-auth-4/callback?'+new URLSearchParams({code:'synthetic-auth-7',state:redirect.searchParams.get('state'),iss:issuer});
 const binding=started.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
 // An absent edge makes the existing fixture's upstream fetch reject. The
 // production network verifier must translate that into its unavailable gate.
 r.upstream=null;
 const unavailable=await r.call(callback,{cookie:binding});assert.equal(unavailable.status,502);
 assert.equal(sessionCookie(unavailable),undefined,'upstream outage creates no Auth session');
 assert.equal((await r.call(callback,{cookie:binding})).status,400,'failed callback cannot be replayed');
 assert.equal((await authenticate(r,worker.key)).response.status,403,'worker cannot invoke an emergency provider bypass');
 const count=(await r.mails()).length;
 assert.equal((await r.call('/auth/identity/email/request',post({email:identities.worker[1]}))).status,202);
 assert.equal((await r.mails()).length,count,'email does not bypass the required upstream');
 const emergency=await authenticate(r,backup.key);assert.equal(emergency.response.status,200);
 const cookie=sessionCookie(emergency.response);
 await command('people/domain-rule',{domain:'company.example.com',providerId:''},cookie,403);
 const proof=await finishProof(r,await requestProof(r,identities.emergency[1],cookie));assert.equal(proof.status,200);
 await command('people/domain-rule',{domain:'company.example.com',providerId:''},sessionCookie(proof));
 assert.equal((await authenticate(r,worker.key)).response.status,200,'ordinary sign-in resumes only after an authorized policy change');
}

async function expiredCertificate(r,owner,expired,command,t) {
 r.owner=owner;r.admin=(path,data)=>r.call('/api/auth/'+path,post(data,owner.cookie));
 const sp=await spCredentials('synthetic-auth-8'),entity='https://synthetic-auth-9.example.com';
 const old=serviceProvider(r,{entity,idpCerts:expired,sp,response:true,assertion:false});
 await addApp(r,{metadata:metadataOf(old,sp),sign:'response',attributes:'email=email',assign:[identities.worker[0]]});
 const workerEmail=await emailSession(r,identities.worker[1]);
 const before=await signIn(r,old,workerEmail);
 assert.equal(before.status,503,'Auth refuses an expired signer before releasing an assertion');
 const refusal=await before.text();assert.match(refusal,/saml_signing_certificate_expired/);assert.doesNotMatch(refusal,/name="SAMLResponse"/);
 // The independent relying-party edge validates the real XML signature and
 // enforces its configured X.509 validity policy. Node-SAML alone does not
 // enforce dates, so the edge makes that check explicit rather than pretending
 // that its signature verifier rejected an otherwise valid signature.
 const accept=async(consumer,certificate,response)=>{
  const identity=await consumer.validatePostResponseAsync({SAMLResponse:response});
  const cert=new X509Certificate(certificate),now=Date.now();
  if(Date.parse(cert.validFrom)>now||Date.parse(cert.validTo)<=now)throw new Error('relying_party_certificate_expired');
  return identity;
 };
 await command('saml-keys/stage',{},workerEmail,403);
 const inventory=await (await r.call('/api/auth/company-apps',{cookie:owner.cookie})).json();
 const previous=inventory.samlKeys.find(key=>key.state==='active');assert.ok(previous);
 const staged=await command('saml-keys/stage',{},owner.cookie,201);
 await command('saml-keys/activate',{kid:staged.kid},owner.cookie);
 const current=await idpCertificates(r);
 assert.ok(Date.parse(new X509Certificate(current[0]).validTo)>Date.now());
 const updated=serviceProvider(r,{entity,idpCerts:[current[0]],sp,response:true,assertion:false});
 const after=await posted(await signIn(r,updated,workerEmail));
 assert.equal((await accept(updated,current[0],after.SAMLResponse)).profile.email,identities.worker[1]);
 await assert.rejects(old.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,old,workerEmail))).SAMLResponse}),'old trust alone cannot validate the replacement signer');
 await command('saml-keys/retire',{kid:previous.kid},owner.cookie);
 assert.ok(!(await idpCertificates(r)).includes(expired[0]),'expired signer is no longer published');
}
