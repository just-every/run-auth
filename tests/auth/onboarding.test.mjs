import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {hash} from '../../src/auth/core.mjs';
const DAY=86400000,post=(data={},cookie,extra={})=>({method:'POST',data,cookie,...extra});
async function fixture(t) {
 const r=await openRuntime();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');r.owner=await register(r,await emailSession(r,'owner@example.com'));
 r.base=r.now;r.admin=(action,data)=>r.call('/api/auth/onboarding/'+action,post(data,r.owner.cookie));
 r.start=(days)=>new Date(r.base+days*DAY).toISOString().slice(0,16);
 r.refresh=async()=>{r.owner=await registerOrProve(r);};
 return r;
}
async function registerOrProve(r) {
 const signed=await authenticate(r,r.owner.key);assert.equal(signed.response.status,200);
 const hardware=cookieOf(signed.response),requested=await r.call('/auth/identity/email/request',post({email:'owner@example.com'},hardware));
 const message=(await r.mails()).at(-1),token=new URL(message.text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 const confirmed=await r.call('/auth/identity/email/confirm',post({token},hardware+'; '+cookieOf(requested)));assert.equal(confirmed.status,200);
 return {...r.owner,cookie:cookieOf(confirmed)};
}
async function hire(r,days=10,extra={}) {
 const response=await r.admin('create',{name:'Future worker',email:'hire@example.com',personalEmail:'personal@example.net',startLocal:r.start(days),timeZone:'UTC',leadDays:7,...extra});
 assert.equal(response.status,201,await response.clone().text());return (await response.json()).personId;
}
async function invitation(r) {const message=(await r.mails()).filter(m=>m.subject==='Activate your Auth enrollment').at(-1);assert.ok(message);return new URL(message.text.match(/https?:\/\/\S+$/)[0]);}
const redeem=(r,link,cookie)=>r.call(link.pathname+link.search,post({},cookie));
async function app(r,id) {
 const created=await r.call('/api/auth/oidc-apps/create',post({name:'Native app',authMethod:'none',redirectUris:'https://rp.example.com/cb'},r.owner.cookie));assert.equal(created.status,201,await created.clone().text());const a=await created.json();
 assert.equal((await r.call('/api/auth/company-apps/assign',post({appId:a.id,principalType:'person',principalId:id},r.owner.cookie))).status,200);return a;
}
const verifier='synthetic-auth-verifier-with-at-least-43-characters';
async function authorization(r,a,cookie) {
 return r.call('/oidc/authorize?'+new URLSearchParams({client_id:a.clientId,redirect_uri:'https://rp.example.com/cb',response_type:'code',scope:'openid email',state:'synthetic-auth-state',code_challenge:await hash(verifier),code_challenge_method:'S256'}),{cookie});
}
async function exchange(r,a,response) {
 const code=new URL(response.headers.get('location')).searchParams.get('code');assert.ok(code);
 return r.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',client_id:a.clientId,redirect_uri:'https://rp.example.com/cb',code,code_verifier:verifier}});
}

test('future hire activates once at the lead boundary, enrolls with personal proof only, and obeys changed start times at protocol doors',async t=>{
 const r=await fixture(t),id=await hire(r),a=await app(r,id);
 const createdSaml=await r.call('/api/auth/company-apps/create',post({name:'Native SAML',entityId:'https://sp.example.com',acsUrl:'https://sp.example.com/acs',idpInitiated:true},r.owner.cookie));assert.equal(createdSaml.status,201);const saml=await createdSaml.json();
 assert.equal((await r.call('/api/auth/company-apps/assign',post({appId:saml.id,principalType:'person',principalId:id},r.owner.cookie))).status,200);
 assert.equal((await r.mails()).filter(m=>m.subject==='Activate your Auth enrollment').length,0);
 r.now=r.base+3*DAY-1;await r.call('/',{action:'maintain'});assert.equal((await r.mails()).filter(m=>m.subject==='Activate your Auth enrollment').length,0);
 r.now++;await r.call('/',{action:'maintain'});await r.restart();await r.call('/',{action:'maintain'});
 assert.equal((await r.mails()).filter(m=>m.subject==='Activate your Auth enrollment').length,1);
 await r.refresh();
 const link=await invitation(r),stored=await r.db.prepare('SELECT * FROM auth_onboarding WHERE person_id=?').bind(id).first();
 assert.equal(stored.token_hash,await hash(link.searchParams.get('token')));assert.equal(stored.personal_verified_at,null);
 assert.equal((await redeem(r,link,r.owner.cookie)).status,403,'another person cannot consume this activation');
 const activated=await redeem(r,link);assert.equal(activated.status,200,await activated.clone().text());
 assert.equal((await redeem(r,link)).status,403);
 const enrolled=await register(r,cookieOf(activated));
 assert.equal((await r.call('/api/auth/organizations',{cookie:enrolled.cookie})).status,403,'personal proof is enrollment only');
 const denied=await authorization(r,a,enrolled.cookie);assert.equal(new URL(denied.headers.get('location')).searchParams.get('error'),'access_denied');
 const before=(await r.mails()).length;await r.call('/auth/identity/email/request',post({email:'personal@example.net'}));assert.equal((await r.mails()).length,before,'personal contact is not a work alias');
 const work=await emailSession(r,'hire@example.com'),hardware=await authenticate(r,enrolled.key);assert.equal(hardware.response.status,200);let cookie=cookieOf(hardware.response);
 assert.equal(new URL((await authorization(r,a,cookie)).headers.get('location')).searchParams.get('error'),'access_denied');
 const samlDenied=await r.call('/saml/launch/'+saml.id,{cookie});assert.equal(samlDenied.status,400);assert.match(await samlDenied.text(),/start_time_or_work_proof_required/);
 await r.refresh();
 assert.equal((await r.admin('schedule',{personId:id,startLocal:r.start(3),timeZone:'UTC',leadDays:7})).status,200);
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 assert.equal((await r.call('/saml/launch/'+saml.id,{cookie})).status,200,'SAML launches at the earlier start');
 let allowed=await authorization(r,a,cookie);assert.ok(new URL(allowed.headers.get('location')).searchParams.get('code'));
 assert.equal((await r.admin('schedule',{personId:id,startLocal:r.start(12),timeZone:'UTC',leadDays:7})).status,200);
 assert.equal((await exchange(r,a,allowed)).status,400,'moving later refuses a previously issued code');
 assert.equal((await r.admin('schedule',{personId:id,startLocal:r.start(3),timeZone:'UTC',leadDays:7})).status,200);
 allowed=await authorization(r,a,cookie);const issued=await exchange(r,a,allowed);assert.equal(issued.status,200,await issued.clone().text());const token=(await issued.json()).access_token;
 assert.equal((await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+token}})).status,200);
 assert.equal((await r.admin('schedule',{personId:id,startLocal:r.start(12),timeZone:'UTC',leadDays:7})).status,200);
 assert.equal((await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+token}})).status,401,'existing token use follows the moved gate');
 r.now=r.base+12*DAY;const signed=await authenticate(r,enrolled.key);cookie=cookieOf(signed.response);
 assert.ok(new URL((await authorization(r,a,cookie)).headers.get('location')).searchParams.get('code'),'launch works at start');
 const mails=(await r.mails()).filter(m=>m.to==='personal@example.net').length;await r.call('/',{action:'maintain'});assert.equal((await r.mails()).filter(m=>m.to==='personal@example.net').length,mails,'activation mail stops at start');
 assert.ok(work);
});

test('expiry, explicit reissue, duplicate addresses and rescission never merge identities or retain enrollment authority',async t=>{
 const r=await fixture(t);await r.person('personal-owner','personal@example.net');
 const id=await hire(r,30,{leadDays:30}),old=await invitation(r);
 assert.equal((await r.admin('create',{name:'Duplicate',email:'hire@example.com',personalEmail:'other@example.net',startLocal:r.start(30),timeZone:'UTC'})).status,409);
 assert.equal((await r.db.prepare("SELECT count(*) AS n FROM oa_operators WHERE email='personal@example.net'").first()).n,1);
 r.now+=7*DAY;assert.equal((await redeem(r,old)).status,403);
 await r.refresh();assert.equal((await r.admin('reissue',{personId:id})).status,200);const fresh=await invitation(r);assert.notEqual(fresh.href,old.href);
 const foreign=new URL(fresh);foreign.searchParams.set('person','personal-owner');assert.equal((await redeem(r,foreign)).status,403);
 assert.equal((await redeem(r,old)).status,403);
 const responses=await Promise.all([redeem(r,fresh),redeem(r,fresh)]);assert.deepEqual(responses.map(r=>r.status).sort(),[200,403]);
 const enrolled=await register(r,cookieOf(responses.find(r=>r.status===200)));
 assert.equal((await r.admin('rescind',{personId:id})).status,200);
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_passkeys WHERE person_id=?').bind(id).first()).n,0);
 assert.equal((await r.call('/auth/passkeys/register/options',post({},enrolled.cookie))).status,401);
 assert.equal((await authenticate(r,enrolled.key)).response.status,400);
 assert.equal((await redeem(r,fresh)).status,403);
 await r.restart();await r.call('/',{action:'maintain'});assert.equal((await r.mails()).filter(m=>m.subject==='Activate your Auth enrollment').length,2);
});

test('future-hire administration refuses missing, weak, foreign and expired authority and invalid local schedules',async t=>{
 const r=await fixture(t),data={name:'Future worker',email:'hire@example.com',personalEmail:'personal@example.net',startLocal:r.start(10),timeZone:'UTC'};
 for(const cookie of [undefined,await emailSession(r,'owner@example.com')])assert.equal((await r.call('/api/auth/onboarding/create',post(data,cookie))).status,cookie?403:401);
 for(const delta of [{leadDays:31},{leadDays:-1},{timeZone:'invalid'},{startLocal:'2026-02-30T10:00'},{startLocal:'2027-03-14T02:30',timeZone:'America/New_York'},{startLocal:'2027-11-07T01:30',timeZone:'America/New_York'}])assert.equal((await r.admin('create',{...data,...delta})).status,400);
 const id=await hire(r);await r.person('member','member@example.com');const member=await register(r,await emailSession(r,'member@example.com'));
 assert.equal((await r.call('/api/auth/onboarding/rescind',post({personId:id},member.cookie))).status,403);
 r.now+=11*60000;assert.equal((await r.admin('rescind',{personId:id})).status,403);
 assert.equal((await r.db.prepare('SELECT rescinded_at FROM auth_onboarding WHERE person_id=?').bind(id).first()).rescinded_at,null);
});
