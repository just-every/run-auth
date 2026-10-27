import {test} from 'node:test';
import assert from 'node:assert/strict';
import {openRuntime,emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';
const post=(data={},cookie,extra={})=>({method:'POST',data,cookie,...extra});
const policy={sourceLimit:2,aggregateLimit:4,cooldownSeconds:30};
async function fixture(t) {
 const r=await openRuntime();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');await r.person('member','member@example.com');
 r.owner=await register(r,await emailSession(r,'owner@example.com'));
 return r;
}
async function configure(r,settings=policy) {
 const response=await r.call('/api/auth/abuse/configure',post(settings,r.owner.cookie));
 assert.equal(response.status,200,await response.clone().text());return (await response.json()).policy;
}

test('attack configuration requires live administrator hardware and fresh email authority at commit',async t=>{
 const r=await fixture(t),ownerEmail=await emailSession(r,'owner@example.com'),member=await register(r,await emailSession(r,'member@example.com'));
 for(const cookie of [undefined,ownerEmail,member.cookie])assert.equal((await r.call('/api/auth/abuse/configure',post(policy,cookie))).status,cookie?403:401);
 assert.equal((await r.call('/api/auth/abuse',{cookie:ownerEmail})).status,403);
 for(const bad of [{sourceLimit:0},{cooldownSeconds:301},{aggregateLimit:1}])assert.equal((await r.call('/api/auth/abuse/configure',post({...policy,...bad},r.owner.cookie))).status,400);
 const saved=await configure(r);assert.equal(saved.sourceLimit,2);assert.equal(saved.aggregateLimit,4);assert.equal(saved.cooldownSeconds,30);
 await r.restart();assert.deepEqual((await(await r.call('/api/auth/abuse',{cookie:r.owner.cookie})).json()).policy,saved);
 // The storage boundary expires the proof after handler authorization and
 // before the guarded D1 write, reproducing a concurrent authority change.
 const raced=await r.call('/api/auth/abuse/configure',post({...policy,sourceLimit:1},r.owner.cookie,{expireAbuseProof:true}));
 assert.equal(raced.status,403);
 assert.deepEqual((await(await r.call('/api/auth/abuse',{cookie:r.owner.cookie})).json()).policy,saved,'a concurrent proof loss makes no configuration change');
 r.now+=11*60000;
 assert.equal((await r.call('/api/auth/abuse/configure',post(policy,r.owner.cookie))).status,403);
 const hardware=await fixture(t),unchanged=await configure(hardware);
 const lostHardware=await hardware.call('/api/auth/abuse/configure',post({...policy,sourceLimit:1},hardware.owner.cookie,{expireAbuseProof:'hardware'}));
 assert.equal(lostHardware.status,403,'hardware authority is rechecked inside the configuration write');
 assert.equal((await lostHardware.json()).error,'session_authority_changed');
 assert.deepEqual(JSON.parse((await hardware.db.prepare("SELECT value FROM auth_settings WHERE key='abuse_policy'").first()).value),unchanged);

});

test('native attack doors enforce durable burst and distributed budgets without trusting forwarding headers or leaking employers',async t=>{
 const r=await fixture(t);
 const created=await r.call('/api/auth/organizations/create',post({name:'Independent employer'},r.owner.cookie));assert.equal(created.status,201);const org=await created.json();
 await configure(r);r.now+=60000;
 const attempt=(path,source,headers={})=>r.call(path,post({},undefined,{sourceIdentity:source,headers}));
 const options='/auth/passkeys/authenticate/options';
 const burst=await Promise.all(Array.from({length:3},(_,i)=>attempt(options,'synthetic-auth-source-1',{'x-forwarded-for':`192.0.2.${i}`,'forwarded':`for=192.0.2.${i}`,'cf-connecting-ip':`192.0.2.${i}`})));
 assert.deepEqual(burst.map(r=>r.status).sort(),[200,200,429]);
 await r.restart();
 assert.equal((await attempt(options,'synthetic-auth-source-1',{'x-forwarded-for':'198.51.100.1'})).status,429);
 // A genuinely different trusted source still spends the aggregate allowance.
 const blocked=await attempt(options,'synthetic-auth-source-2');assert.equal(blocked.status,429);
 assert.equal(blocked.headers.get('retry-after'),'30');
 const foreign=await attempt('/org/'+org.id+options,'synthetic-auth-source-1');assert.equal(foreign.status,200,'other employers retain their allowance');
 const refusal=(await(await r.call('/api/auth/abuse',{cookie:r.owner.cookie})).json()).refusals.map(r=>JSON.parse(r.detail));
 assert.ok(refusal.some(r=>r.reason==='source_limit'));assert.ok(refusal.some(r=>r.reason==='aggregate_limit'&&r.door==='webauthn'));
 // Rejected attempts cannot slide the deadline forward, even across restart.
 r.now+=29000;assert.equal((await attempt(options,'synthetic-auth-source-2')).headers.get('retry-after'),'1');
 r.now+=1000;assert.equal((await attempt(options,'synthetic-auth-source-2')).status,200);
 // Distributed sources still meet one employer-wide budget.
 r.now+=30000;
 for(let i=0;i<4;i++)assert.equal((await attempt(options,'synthetic-auth-distributed-'+i)).status,200);
 assert.equal((await attempt(options,'synthetic-auth-distributed-5')).status,429);
 // Untrusted standalone headers cannot create source identities, either.
 r.now+=30000;
 for(let i=0;i<2;i++)assert.equal((await r.call(options,post({},undefined,{headers:{'cf-connecting-ip':`203.0.113.${i}`}}))).status,200);
 assert.equal((await r.call(options,post({},undefined,{headers:{'cf-connecting-ip':'203.0.113.99'}}))).status,429);
});

test('email responses stay uniform under distributed traffic and every native authentication family refuses excess attempts',async t=>{
 const r=await fixture(t);
 await emailSession(r,'owner@example.com');
 await configure(r);r.now+=60000;
 const bodies=[];
 for(let i=0;i<6;i++) {
  const response=await r.call('/auth/identity/email/request',post({email:i%2?'unknown@example.com':'owner@example.com'},undefined,{sourceIdentity:'synthetic-auth-'+i}));
  assert.equal(response.status,202);bodies.push(await response.text());
 }
 assert.equal(new Set(bodies).size,1);
 assert.equal((await r.mails()).filter(m=>m.subject==='Your Auth sign-in link').length,4,'only the two admitted known-address requests add mail to the two setup confirmations');
 for(const path of ['/auth/identity/email/confirm','/auth/passkeys/register/options','/auth/identity/passkeys/register/verify','/auth/passkeys/authenticate/verify','/api/auth/recovery/token']) {
  r.now+=30000;
  const replies=[];
  for(let i=0;i<5;i++)replies.push(await r.call(path,post({},undefined,{sourceIdentity:'synthetic-auth-'+i})));
  assert.equal(replies.at(-1).status,429,path);
 }
});

test('proved emergency recovery survives anonymous exhaustion and retains one-use proof',async t=>{
 const r=await fixture(t),proved=await emailSession(r,'owner@example.com');
 await configure(r);r.now+=60000;
 for(let i=0;i<5;i++)await r.call('/api/auth/recovery/token',post({},undefined,{sourceIdentity:'synthetic-auth-'+i}));
 const token='synthetic-auth-emergency-token-with-at-least-43-characters';
 await r.call('/',{action:'recovery-token',token});
 assert.equal((await r.call('/api/auth/recovery/token',post({token},proved))).status,200,'anonymous recovery attempts cannot spend a proved session allowance');
 assert.equal((await r.call('/api/auth/recovery/token',post({token},proved))).status,400,'recovery proof remains single use');
 assert.equal((await r.db.prepare("SELECT count(*) AS n FROM auth_passkeys WHERE person_id='owner'").first()).n,0);
});
