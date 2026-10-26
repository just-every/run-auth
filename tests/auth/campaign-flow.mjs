import assert from 'node:assert/strict';
import {upstreamFixture} from './upstream-helpers.mjs';
import {register} from './webauthn.mjs';
import {emailSession} from './runtime.mjs';
import {post,stage,admit} from './move-in-helpers.mjs';
import {sessionCookie,browserCookie,finishProof} from './policy-helpers.mjs';

export async function campaignFlow(t) {
 const subjects=Object.fromEntries(Array.from({length:20},(_,i)=>['synthetic-auth-'+i,`worker${i}@company.example`]));
 const r=await upstreamFixture(t,'okta',subjects);
 const owner=await r.db.prepare("SELECT email FROM oa_operators WHERE id='owner'").first();
 const admin=await register(r,await emailSession(r,owner.email));
 await r.person('manager','manager@company.example');
 const users=Object.entries(subjects).map(([id,email],i)=>({id,status:'ACTIVE',profile:{email,login:email,firstName:'Campaign',lastName:'Worker '+i}}));
 const staged=await stage(r,admin.cookie,'campaign-okta.json',{text:JSON.stringify(users)});assert.equal(staged.status,201,await staged.clone().text());
 const batch=(await staged.json()).batchId;
 assert.equal((await admit(r,admin.cookie,batch,users.map((_,i)=>i))).status,200);
 // Beginning a sign-in independently verifies and pins the actual discovery.
 const probe=await r.call('/auth/oidc/company/start',post({returnTo:'/app/account'}));assert.equal(probe.status,303);
 const data={name:'Engineering cutover',providerId:'company',batchId:batch,rows:users.map((_,i)=>i),startsAt:r.now,deadlineAt:r.now+4*86400000,cutoverAt:r.now+5*86400000,managerId:'manager',confirm:true,employeeConsent:false,managerConsent:true,administratorConsent:true};
 const created=await r.call('/api/auth/move-in/campaigns/create',post(data,admin.cookie));assert.equal(created.status,201,await created.clone().text());
 const id=(await created.json()).id;
 const dashboard=async cookie=>{const response=await r.call('/api/auth/move-in/campaigns',{cookie});assert.equal(response.status,200,await response.clone().text());return (await response.json()).campaigns[0];};
 assert.equal((await dashboard(admin.cookie)).remaining,20);
 assert.equal((await r.login({sub:'synthetic-auth-0',amr:['pwd']})).status,403,'incumbent proof without MFA is refused');
 assert.equal((await r.login({sub:'synthetic-auth-foreign',email:'worker0@company.example',email_verified:true,amr:['mfa']})).status,403,'matching email cannot replace reviewed immutable subject');
 for(let i=0;i<17;i++) {
  const login=await r.login({sub:'synthetic-auth-'+i,amr:['pwd','mfa']});assert.equal(login.status,303,await login.clone().text());
  const link=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]);
  const confirmed=await finishProof(r,{binding:browserCookie(login),token:link.searchParams.get('token')});assert.equal(confirmed.status,200);
  const member=await register(r,sessionCookie(confirmed));
  assert.equal((await r.call('/api/auth/people',{cookie:member.cookie})).status,403,'campaign enrollment cannot administer');
 }
 let current=await dashboard(admin.cookie);assert.equal(current.counts.passkey_ready,17);assert.equal(current.remaining,3);
 const countdown=current.secondsToCutover;
 r.now+=86400000;await r.restart();
 await r.call('/',{action:'maintain'});
 const notices=(await r.mails()).filter(mail=>mail.subject==='Auth campaign manager reminder');assert.equal(notices.length,3);
 assert.ok(notices.every(mail=>mail.to==='manager@company.example'));
 assert.deepEqual(notices.map(mail=>Number(mail.text.match(/worker(\d+)@/)[1])).sort((a,b)=>a-b),[17,18,19]);
 await r.call('/',{action:'maintain'});assert.equal((await r.mails()).filter(mail=>mail.subject==='Auth campaign manager reminder').length,3,'restart and repeated workers cannot duplicate notices');
 const renewed=await registerExisting(r,admin.key,owner.email);
 current=await dashboard(renewed);assert.ok(current.secondsToCutover<countdown);
 r.now+=3*86400000;await r.call('/',{action:'maintain'});
 const atDeadline=await registerExisting(r,admin.key,owner.email);
 current=await dashboard(atDeadline);assert.equal(current.counts.overdue,3);
 const exported=await r.call('/api/auth/move-in/campaigns/export.csv?campaign='+id,{cookie:atDeadline});assert.equal(exported.status,200);
 const csv=await exported.text();for(const i of [17,18,19])assert.ok(csv.includes(`worker${i}@company.example`));assert.ok(!csv.includes('worker0@company.example'));
 assert.equal((await r.mails()).filter(mail=>mail.subject==='Auth campaign enrollment overdue').length,3);
 // The final three can still enroll before cutover without a help-desk write.
 for(let i=17;i<20;i++) {
  const login=await r.login({sub:'synthetic-auth-'+i,amr:['mfa']});assert.equal(login.status,303);
  const confirmed=await finishProof(r,{binding:browserCookie(login),token:new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token')});assert.equal(confirmed.status,200);
  await register(r,sessionCookie(confirmed));
 }
 assert.equal((await dashboard(atDeadline)).counts.passkey_ready,20);
 assert.equal((await dashboard(atDeadline)).remaining,0);
 const person=await r.db.prepare("SELECT id FROM oa_operators WHERE email='worker19@company.example'").first();
 await r.call('/api/auth/people/role',post({id:person.id,role:'admin'},atDeadline));
 assert.equal((await r.login({sub:'synthetic-auth-19',amr:['mfa']})).status,403,'an administrator cannot reuse campaign proof');
 r.now=data.cutoverAt;
 assert.equal((await r.call('/auth/oidc/company/start',post({returnTo:'/app/account'}))).status,404,'the campaign provider is removed exactly at cutover');
 assert.equal((await r.call('/api/auth/move-in/campaigns',{cookie:await emailSession(r,owner.email)})).status,403,'dashboard requires local hardware administration');
}

async function registerExisting(r,key,email) {
 const {authenticate}=await import('./webauthn.mjs');
 const response=await authenticate(r,key);assert.equal(response.response.status,200,await response.response.clone().text());
 // Refresh only this session's local proof; upstream proof never refreshes it.
 const cookie=sessionCookie(response.response);
 const requested=await r.call('/auth/identity/email/request',post({email},cookie));assert.equal(requested.status,202);
 const token=new URL((await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 const confirmed=await r.call('/auth/identity/email/confirm',post({token},cookie+'; '+browserCookie(requested)));assert.equal(confirmed.status,200,await confirmed.clone().text());return sessionCookie(confirmed);
}
