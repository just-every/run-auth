import {nativeGrant} from './notifications-flow.mjs';
import {samlInstall} from './saml-helpers.mjs';
import {decodeJwt} from 'jose';
import {fixture as protocolFixture} from './protocol-helpers.mjs';
import assert from 'node:assert/strict';
import {createHmac,createHash} from 'node:crypto';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {requestProof,finishProof} from './policy-helpers.mjs';
const address=n=>'synthetic-auth-'+n+'@'+'example.test';
const post=(data,cookie,extra={})=>({method:'POST',data,cookie,...extra});
const path='/api/auth/factors';
export function authenticatorCode(secret,now) {
 const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const c of secret)bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
 const key=Buffer.from(bits.match(/.{8}/g).map(b=>parseInt(b,2))),counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(now/30000)));
 const digest=createHmac('sha1',key).update(counter).digest(),offset=digest[19]&15;
 return String((digest.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0');
}
async function ok(response,status=200){assert.equal(response.status,status,await response.clone().text());return response.json();}
async function fixture(t) {
 const r=await openRuntime();t.after(()=>r.close());await r.person('synthetic-auth-1',address(1),'owner');await r.person('synthetic-auth-2',address(2));await r.person('synthetic-auth-3',address(3));
 r.owner=await register(r,await emailSession(r,address(1)));r.member=await register(r,await emailSession(r,address(2)));return r;
}
async function enroll(r,user=r.member) {
 const f=await ok(await r.call(path+'/totp/begin',post({},user.cookie)));
 await ok(await r.call(path+'/totp/confirm',post({id:f.id,code:authenticatorCode(f.secret,r.now)},user.cookie)));return f;
}
async function fresh(r,user,n) {
 const response=await finishProof(r,await requestProof(r,address(n),cookieOf((await authenticate(r,user.key)).response)));await ok(response);return cookieOf(response);
}
export async function totpFlow(t) {
 const r=await fixture(t),email=await emailSession(r,address(2));
 assert.equal((await r.call(path+'/totp/begin',post({}))).status,401);
 assert.equal((await r.call(path+'/totp/begin',post({},email))).status,403);
 const pending=await ok(await r.call(path+'/totp/begin',post({},r.member.cookie)));
 assert.equal((await r.call(path+'/totp/confirm',post({id:pending.id,code:'wrong'},r.member.cookie))).status,403);
 assert.equal((await r.call(path+'/totp/confirm',post({id:pending.id,code:authenticatorCode(pending.secret,r.now)},r.owner.cookie))).status,404);
 await ok(await r.call(path+'/totp/confirm',post({id:pending.id,code:authenticatorCode(pending.secret,r.now)},r.member.cookie)));
 const row=await r.db.prepare('SELECT * FROM auth_totp_factors WHERE id=?').bind(pending.id).first();assert.equal(row.sealed_secret.includes(pending.secret),false);
 const inventory=await ok(await r.call(path,{cookie:email}));assert.deepEqual(inventory.totp.map(f=>f.id),[pending.id]);assert.equal(JSON.stringify(inventory).includes(pending.secret),false);
 r.now+=30000;await r.restart();
 const code=authenticatorCode(pending.secret,r.now);
 await ok(await r.call(path+'/totp/verify',post({code},email)));
 assert.equal((await r.call(path+'/totp/verify',post({code},email))).status,403,'a TOTP step cannot be replayed after a successful proof');
 assert.equal((await r.call('/api/auth/people',{cookie:email})).status,403,'TOTP does not confer passkey administration');
 assert.equal((await r.call('/auth/passkeys/register/options',post({},email))).status,403,'TOTP cannot enroll a new administrator credential');
 r.now+=30000;
 const parallel=await Promise.all([0,1].map(()=>r.call(path+'/totp/verify',post({code:authenticatorCode(pending.secret,r.now)},email,{barrier:{name:'synthetic-auth-totp',size:2}}))));
 assert.deepEqual(parallel.map(response=>response.status).sort(),[200,403],'only one concurrent request can claim a TOTP step');
 const ownerFactor=await enroll(r,r.owner),ownerEmail=await emailSession(r,address(1));r.now+=30000;
 await ok(await r.call(path+'/totp/verify',post({code:authenticatorCode(ownerFactor.secret,r.now)},ownerEmail)));
 assert.equal((await r.call('/api/auth/people',{cookie:ownerEmail})).status,403,'an owner using TOTP cannot administer');
 assert.equal((await r.call('/auth/passkeys/register/options',post({},ownerEmail))).status,403,'an owner using TOTP cannot enroll an administrator factor');
 r.now+=11*60000;
 assert.equal((await r.call(path+'/remove',post({id:pending.id,kind:'totp'},r.member.cookie))).status,403,'fresh local email is still mandatory');
}
export async function factorLossFlow(t) {
 const r=await fixture(t),totp=await enroll(r),extra=await register(r,r.member.cookie);
 await ok(await r.call('/api/auth/notifications/settings',post({confirm:true,emailEnabled:true,newDevice:false,factorEnrolled:true,securityOwnerId:'synthetic-auth-1',slackEnabled:false,endSessionsOnReport:false},r.owner.cookie)));
 assert.equal((await r.call(path+'/remove',post({id:r.owner.key.id,kind:'passkey'},r.member.cookie))).status,403,'a foreign factor cannot be removed');
 const email=await emailSession(r,address(2));r.now+=30000;
 await ok(await r.call(path+'/totp/verify',post({code:authenticatorCode(totp.secret,r.now)},email)));
 await ok(await r.call(path+'/remove',post({id:totp.id,kind:'totp'},extra.cookie)));
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM auth_security_notifications WHERE person_id=? AND event='factor_removed' AND delivery_state='accepted'").bind('synthetic-auth-2').first()).n,1,'configured factor-loss notice reaches the native mail edge exactly once');
 for(const cookie of [email,r.member.cookie,extra.cookie])assert.equal((await r.call('/api/auth/me',{cookie})).status,401,'factor removal reaches every current session');
 const returned=await fresh(r,r.member,2);
 assert.equal((await r.call(path+'/totp/verify',post({code:authenticatorCode(totp.secret,r.now+30000)},returned))).status,403);
 await ok(await r.call(path+'/remove',post({id:extra.key.id,kind:'passkey'},returned)));
 assert.equal((await authenticate(r,extra.key)).response.status,400,'the lost key cannot authenticate again');
 const remaining=await fresh(r,r.member,2);
 assert.equal((await r.call(path+'/remove',post({id:r.member.key.id,kind:'passkey'},remaining))).status,409,'the last passkey needs a replacement first');
 assert.equal((await r.call('/api/auth/me',{cookie:remaining})).status,200);
 const enrolledAgain=await enroll(r,{cookie:remaining});
 await ok(await r.call('/api/auth/erasure/policy',post({confirm:true,automaticDeletion:false,honorLegalHolds:true},r.owner.cookie)));
 const preview=await ok(await r.call('/api/auth/erasure/preview',post({kind:'person',target:'synthetic-auth-2'},r.owner.cookie)));
 await ok(await r.call('/api/auth/erasure/confirm',post({previewId:preview.id,confirmation:'ERASE',destinations:[]},r.owner.cookie)));
 await r.restart();
 assert.equal((await r.call('/api/auth/me',{cookie:remaining})).status,401);
 assert.equal((await r.call(path+'/totp/verify',post({code:authenticatorCode(enrolledAgain.secret,r.now+30000)},remaining))).status,401,'an erased factor cannot restore the identity');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_totp_factors WHERE person_id=?').bind('synthetic-auth-2').first()).n,0);
}
export async function recoveryCodesFlow(t) {
 const r=await fixture(t),email=await emailSession(r,address(2));
 const issued=await ok(await r.call(path+'/recovery/rotate',post({},r.member.cookie)));
 assert.equal(new Set(issued.codes).size,8);assert.equal((await r.call('/api/auth/me',{cookie:email})).status,401);
 const stored=(await r.db.prepare('SELECT * FROM auth_person_recovery_codes').all()).results;
 assert.ok(issued.codes.every(code=>!JSON.stringify(stored).includes(code)),'only code digests are persisted');
 const after=await fresh(r,r.member,2),rotated=await ok(await r.call(path+'/recovery/rotate',post({},after)));
 const recoveryEmail=await emailSession(r,address(2)),other=await emailSession(r,address(3));
 assert.equal((await r.call(path+'/recovery/redeem',post({code:issued.codes[0]},recoveryEmail))).status,403,'rotation ends old codes');
 assert.equal((await r.call(path+'/recovery/redeem',post({code:rotated.codes[0]},other))).status,403,'another person cannot redeem the code');
 assert.equal((await r.call(path+'/recovery/rotate',post({},r.owner.cookie))).status,403,'administrators cannot issue unusable lower-assurance recovery codes');
 const ownerEmail=await emailSession(r,address(1));
 assert.equal((await r.call(path+'/recovery/redeem',post({code:rotated.codes[0]},ownerEmail))).status,403,'administrator recovery cannot downgrade');
 await r.restart();
 const attempts=await Promise.all([0,1].map(()=>r.call(path+'/recovery/redeem',post({code:rotated.codes[0]},recoveryEmail,{barrier:{name:'synthetic-auth-recovery',size:2}}))));
 assert.deepEqual(attempts.map(response=>response.status).sort(),[200,403],'only one concurrent redemption can reset factors');
 const redeemed=attempts.find(response=>response.status===200);await ok(redeemed);const limited=cookieOf(redeemed);
 assert.equal((await r.call('/api/auth/people',{cookie:limited})).status,403);
 assert.equal((await r.call(path+'/totp/verify',post({code:'000000'},limited))).status,403);
 assert.equal((await r.call(path+'/recovery/redeem',post({code:rotated.codes[0]},await emailSession(r,address(2))))).status,403,'the consumed code stays consumed across new sessions');
 assert.equal((await authenticate(r,r.member.key)).response.status,400,'recovery invalidates lost factors');
 const replacement=await register(r,limited);
 assert.equal((await r.call('/api/auth/me',{cookie:limited})).status,401,'enrollment ends the recovery capability');
 assert.equal((await authenticate(r,replacement.key)).response.status,200);
 assert.equal((await r.call('/api/auth/me',{cookie:replacement.cookie})).status,200);
 // A real SDK grant proves that ending browser sessions also reaches existing
 // native access tokens and refresh credentials, including a protected app.
 const native=await samlInstall(t),strong=await register(native,native.ada);
 const command=async(suffix,data,status=200,cookie=native.owner.cookie)=>ok(await native.call('/api/auth'+suffix,post(data,cookie)),status);
 const grant=await nativeGrant(native,command,'ada',strong.cookie);
 await command('/factors/policy',{appId:grant.app.id,method:'passkey',maxAgeSeconds:60});
 assert.ok((await grant.sdk.refresh()).refresh_token,'a current passkey satisfies protected native refresh');
 assert.equal((await grant.sdk.resourceRequest('/api/auth/resource-apis/check',{apiId:grant.api.id,action:'read',resource:'document:one'})).allowed,true,'the same native access request works before rotation');
 await command('/factors/recovery/rotate',{},200,strong.cookie);
 await assert.rejects(grant.sdk.resourceRequest('/api/auth/resource-apis/check',{apiId:grant.api.id,action:'read',resource:'document:one'}));
 await assert.rejects(grant.sdk.refresh(),'code rotation ends an existing native refresh grant');

}
export async function assuranceFlow(t) {
 const r=await fixture(t),totp=await enroll(r),admin=(suffix,data)=>r.call('/api/auth/'+suffix,post(data,r.owner.cookie));
 const app=await ok(await admin('oidc-apps/create',{name:'Sensitive payroll',authMethod:'none',redirectUris:'https://payroll.example.test/callback',requirePkce:true}),201);
 const other=await ok(await admin('oidc-apps/create',{name:'Ordinary documents',authMethod:'none',redirectUris:'https://docs.example.test/callback',requirePkce:true}),201);
 for(const item of [app,other])await ok(await admin('company-apps/assign',{appId:item.id,principalType:'person',principalId:'synthetic-auth-2'}));
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const verifier='synthetic-auth-'.repeat(4),challenge=createHash('sha256').update(verifier).digest('base64url');
 const authorize=(item,cookie)=>r.call('/oidc/authorize?'+new URLSearchParams({client_id:item.clientId,redirect_uri:item===app?'https://payroll.example.test/callback':'https://docs.example.test/callback',response_type:'code',scope:'openid',state:'synthetic-auth-4',nonce:'synthetic-auth-5',code_challenge:challenge,code_challenge_method:'S256'}),{cookie});
 const result=response=>new URL(response.headers.get('location')).searchParams;
 const policy=method=>r.call(path+'/policy',post({appId:app.id,method,maxAgeSeconds:60},r.owner.cookie));
 await ok(await policy('passkey'));
 const email=await emailSession(r,address(2));assert.equal(result(await authorize(app,email)).get('error'),'interaction_required');
 assert.ok(result(await authorize(other,email)).get('code'),'the policy is scoped to the selected app');
 r.now+=30000;await ok(await r.call(path+'/totp/verify',post({code:authenticatorCode(totp.secret,r.now)},email)));
 assert.equal(result(await authorize(app,email)).get('error'),'interaction_required','TOTP cannot satisfy passkey-only assurance');
 await ok(await policy('passkey_or_totp'));
 const exchange=code=>r.call('/oidc/token',{method:'POST',form:{client_id:app.clientId,grant_type:'authorization_code',code,redirect_uri:'https://payroll.example.test/callback',code_verifier:verifier}});
 const otpGranted=await ok(await exchange(result(await authorize(app,email)).get('code')));assert.ok(decodeJwt(otpGranted.id_token).amr.includes('otp'),'the app receives the actual lower-assurance method');
 const authorized=result(await authorize(app,email));assert.ok(authorized.get('code'));
 await ok(await policy('passkey'));
 assert.equal((await exchange(authorized.get('code'))).status,400,'token issuance rechecks the current policy');
 const passkey=cookieOf((await authenticate(r,r.member.key)).response),strong=result(await authorize(app,passkey));assert.ok(strong.get('code'));
 assert.ok((await ok(await exchange(strong.get('code')))).id_token);
 r.now+=61000;assert.equal(result(await authorize(app,passkey)).get('error'),'interaction_required','stale assurance requires another step-up');
 const reproof=await finishProof(r,await requestProof(r,address(2),passkey));await ok(reproof);
 assert.equal(result(await authorize(app,cookieOf(reproof))).get('error'),'interaction_required','email confirmation cannot renew passkey assurance age');
 assert.equal((await r.call(path+'/policy',post({appId:app.id,method:'passkey_or_totp',maxAgeSeconds:60},email))).status,403);
 const saml=await ok(await admin('company-apps/create',{name:'Sensitive SAML app',entityId:'https://saml.example.test',acsUrl:'https://saml.example.test/acs',idpInitiated:true}),201);
 await ok(await admin('company-apps/assign',{appId:saml.id,principalType:'person',principalId:'synthetic-auth-2'}));
 await ok(await r.call(path+'/policy',post({appId:saml.id,method:'passkey',maxAgeSeconds:60},r.owner.cookie)));
 const samlRefused=await r.call('/saml/launch/'+saml.id,{cookie:email});assert.equal(samlRefused.status,400);assert.match(await samlRefused.text(),/factor_step_up_required/,'direct SAML launch cannot bypass assurance');
 const freshPasskey=cookieOf((await authenticate(r,r.member.key)).response);
 const launched=await r.call('/saml/launch/'+saml.id,{cookie:freshPasskey});assert.equal(launched.status,200);assert.match(await launched.text(),/name="SAMLResponse"/);
 const native=await protocolFixture(t),nativeOwner=await register(native,native.cookie);
 await ok(await native.call(path+'/policy',post({appId:'app',method:'passkey',maxAgeSeconds:60},nativeOwner.cookie)));
 const denied=await native.authorize();assert.equal(new URL(denied.response.headers.get('location')).searchParams.get('error'),'interaction_required','RER authorization enforces its app policy');
 native.cookie=nativeOwner.cookie;const accepted=await native.authorize();assert.ok(accepted.code);
 native.now+=61000;assert.equal((await native.redeem(accepted)).status,400,'RER token exchange rechecks assurance age');
 const before=await r.db.prepare('SELECT revision FROM auth_factor_policies WHERE app_id=?').bind(app.id).first();
 const raced=await r.call(path+'/policy',post({appId:app.id,method:'passkey_or_totp',maxAgeSeconds:300},r.owner.cookie,{factorRace:"UPDATE auth_sessions SET local_email_verified_at=0 WHERE person_id='synthetic-auth-1'"}));
 assert.equal(raced.status,403,'email authority is rechecked in the policy commit');
 assert.deepEqual(await r.db.prepare('SELECT revision FROM auth_factor_policies WHERE app_id=?').bind(app.id).first(),before,'a refused policy write leaves the previous revision intact');

}
