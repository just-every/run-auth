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
 r.now+=11*60000;
 assert.equal((await r.call(path+'/remove',post({id:pending.id,kind:'totp'},r.member.cookie))).status,403,'fresh local email is still mandatory');
}
export async function factorLossFlow(t) {
 const r=await fixture(t),totp=await enroll(r),extra=await register(r,r.member.cookie);
 assert.equal((await r.call(path+'/remove',post({id:r.owner.key.id,kind:'passkey'},r.member.cookie))).status,403,'a foreign factor cannot be removed');
 const email=await emailSession(r,address(2));r.now+=30000;
 await ok(await r.call(path+'/totp/verify',post({code:authenticatorCode(totp.secret,r.now)},email)));
 await ok(await r.call(path+'/remove',post({id:totp.id,kind:'totp'},extra.cookie)));
 for(const cookie of [email,r.member.cookie,extra.cookie])assert.equal((await r.call('/api/auth/me',{cookie})).status,401,'factor removal reaches every current session');
 const returned=await fresh(r,r.member,2);
 assert.equal((await r.call(path+'/totp/verify',post({code:authenticatorCode(totp.secret,r.now+30000)},returned))).status,403);
 await ok(await r.call(path+'/remove',post({id:extra.key.id,kind:'passkey'},returned)));
 assert.equal((await authenticate(r,extra.key)).response.status,400,'the lost key cannot authenticate again');
 const remaining=await fresh(r,r.member,2);
 assert.equal((await r.call(path+'/remove',post({id:r.member.key.id,kind:'passkey'},remaining))).status,409,'the last passkey needs a replacement first');
 assert.equal((await r.call('/api/auth/me',{cookie:remaining})).status,200);
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
 const ownerCodes=await ok(await r.call(path+'/recovery/rotate',post({},r.owner.cookie))),ownerEmail=await emailSession(r,address(1));
 assert.equal((await r.call(path+'/recovery/redeem',post({code:ownerCodes.codes[0]},ownerEmail))).status,403,'administrator recovery cannot downgrade');
 await r.restart();
 const redeemed=await r.call(path+'/recovery/redeem',post({code:rotated.codes[0]},recoveryEmail));await ok(redeemed);const limited=cookieOf(redeemed);
 assert.equal((await r.call('/api/auth/people',{cookie:limited})).status,403);
 assert.equal((await r.call(path+'/totp/verify',post({code:'000000'},limited))).status,403);
 assert.equal((await r.call(path+'/recovery/redeem',post({code:rotated.codes[0]},await emailSession(r,address(2))))).status,403,'the consumed code stays consumed across new sessions');
 assert.equal((await authenticate(r,r.member.key)).response.status,400,'recovery invalidates lost factors');
 const replacement=await register(r,limited);
 assert.equal((await r.call('/api/auth/me',{cookie:limited})).status,401,'enrollment ends the recovery capability');
 assert.equal((await authenticate(r,replacement.key)).response.status,200);
 assert.equal((await r.call('/api/auth/me',{cookie:replacement.cookie})).status,200);
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
 const authorized=result(await authorize(app,email));assert.ok(authorized.get('code'));
 await ok(await policy('passkey'));
 const exchange=code=>r.call('/oidc/token',{method:'POST',form:{client_id:app.clientId,grant_type:'authorization_code',code,redirect_uri:'https://payroll.example.test/callback',code_verifier:verifier}});
 assert.equal((await exchange(authorized.get('code'))).status,400,'token issuance rechecks the current policy');
 const passkey=cookieOf((await authenticate(r,r.member.key)).response),strong=result(await authorize(app,passkey));assert.ok(strong.get('code'));
 assert.ok((await ok(await exchange(strong.get('code')))).id_token);
 r.now+=61000;assert.equal(result(await authorize(app,passkey)).get('error'),'interaction_required','stale assurance requires another step-up');
 assert.equal((await r.call(path+'/policy',post({appId:app.id,method:'passkey_or_totp',maxAgeSeconds:60},email))).status,403);
}
