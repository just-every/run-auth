import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {register} from './webauthn.mjs';

async function setup(t) {
 const r=await openRuntime();t.after(()=>r.close());
 for(const [id,role] of [['synthetic-auth-owner','owner'],['synthetic-auth-manager','member'],['synthetic-auth-helper','member'],['synthetic-auth-other','member']])await r.person(id,id+'@example.com',role);
 const actors={};for(const role of ['owner','manager','helper','other'])actors[role]=await register(r,await emailSession(r,`synthetic-auth-${role}@example.com`));
 const call=async(path,data,cookie=actors.owner.cookie,status=200)=>{
  const result=await r.call(path,{method:'POST',data,cookie});assert.equal(result.status,status,`${path}: ${await result.clone().text()}`);return result;
 };
 const created=await call('/api/auth/onboarding/create',{email:'synthetic-auth-hire@example.com',personalEmail:'synthetic-auth-personal@example.net',name:'Synthetic Auth Hire',startLocal:new Date(r.now+86400000).toISOString().slice(0,16),timeZone:'UTC',leadDays:0,contactAuthority:true},undefined,201);
 const {personId}=await created.json();
 await call('/api/auth/directory/edit',{personId,set:{manager:'synthetic-auth-manager'}});
 const group=await (await call('/api/auth/groups/create',{name:'Synthetic Auth onboarding'},undefined,201)).json();
 await call('/api/auth/groups/add',{groupId:group.id,personId});
 const grant=await (await call('/api/auth/roles/preview',{kind:'grant',personId:'synthetic-auth-helper',roleId:'help-desk',resources:{view:{groups:[group.id]},edit:{groups:[group.id]}}})).json();
 await call('/api/auth/roles/apply',{previewId:grant.previewId});
 const request=async()=> (await (await call('/api/auth/temporary-passes/request',{personId,reason:'Manager verified the new hire in person'},actors.manager.cookie,201)).json()).requestId;
 const issue=async()=> (await (await call('/api/auth/temporary-passes/issue',{requestId:await request()},actors.helper.cookie,201)).json());
 return {r,actors,call,personId,group,request,issue};
}

async function assignedApps(call,personId,r) {
 const oidc=await (await call('/api/auth/oidc-apps/create',{name:'Synthetic Auth OIDC',authMethod:'none',redirectUris:'https://synthetic-auth-app.example.com/cb'},undefined,201)).json();
 const saml=await (await call('/api/auth/company-apps/create',{name:'Synthetic Auth SAML',entityId:'https://synthetic-auth-sp.example.com',acsUrl:'https://synthetic-auth-sp.example.com/acs',idpInitiated:true},undefined,201)).json();
 for(const app of [oidc,saml])await call('/api/auth/company-apps/assign',{appId:app.id,principalType:'person',principalId:personId});
 // Remove the future-start gate, so these refusals prove the TAP restriction.
 await call('/api/auth/onboarding/schedule',{personId,startLocal:new Date(r.now).toISOString().slice(0,16),timeZone:'UTC',leadDays:0});
 return async(cookie,pass)=>{
  for(const prompt of [{prompt:'none'},{prompt:'login'},{max_age:'0'}]){
   const query=new URLSearchParams({client_id:oidc.clientId,redirect_uri:'https://synthetic-auth-app.example.com/cb',response_type:'code',scope:'openid email',state:'synthetic-auth-state',code_challenge:createHash('sha256').update('synthetic-auth-verifier-with-at-least-43-characters').digest('base64url'),code_challenge_method:'S256',...prompt});
   const response=await r.call('/oidc/authorize?'+query,{cookie});assert.equal(response.status,prompt.prompt==='none'?302:303);
   const location=new URL(response.headers.get('location'),r.origin);assert.equal(location.searchParams.get('code'),null);
   if(prompt.prompt==='none')assert.equal(location.searchParams.get('error'),'access_denied');
  }
  const refused=await r.call('/oidc/token',{method:'POST',cookie,form:{grant_type:'temporary_access_pass',client_id:oidc.clientId,pass}});
  assert.equal(refused.status,400);const error=await refused.json();assert.equal(error.error,'unsupported_grant_type');assert.equal(error.access_token,undefined);
  const assertion=await r.call('/saml/launch/'+saml.id,{cookie});assert.equal(assertion.status,400);const html=await assertion.text();assert.match(html,/start_time_or_work_proof_required/);assert.ok(!html.includes('name="SAMLResponse"'));
 };
}

test('manager verification and scoped issuance give a one-use pass that enrolls after work email proof and ends its restricted session',async t=>{
 const {r,actors,call,personId,issue}=await setup(t);
 const refuseApps=await assignedApps(call,personId,r);
 await call('/api/auth/temporary-passes/request',{personId,reason:'Wrong manager'},actors.other.cookie,403);
 await call('/api/auth/temporary-passes/request',{personId:'synthetic-auth-owner',reason:'Privileged target'},actors.manager.cookie,403);
 await call('/api/auth/temporary-passes/issue',{requestId:'synthetic-auth-unverified'},actors.helper.cookie,403);
 const issued=await issue();
 const stored=await r.db.prepare('SELECT * FROM auth_temporary_passes WHERE id=?').bind(issued.passId).first();
 assert.ok(stored.token_hash);assert.ok(!JSON.stringify(stored).includes(issued.pass));
 const attempts=await Promise.all([1,2].map(()=>r.call('/auth/identity/temporary-pass',{method:'POST',data:{pass:issued.pass}})));
 const won=attempts.filter(response=>response.status===200);assert.equal(won.length,1);assert.ok(attempts.filter(response=>response.status!==200).every(response=>[403,409].includes(response.status)));
 const tapCookie=cookieOf(won[0]);
 await refuseApps(tapCookie,issued.pass);
 await call('/auth/identity/temporary-pass',{pass:issued.pass},null,403);
 await call('/auth/passkeys/register/options',{},tapCookie,403);
 assert.equal((await r.call('/api/auth/people',{cookie:tapCookie})).status,403);
 const requested=await call('/auth/identity/email/request',{email:'synthetic-auth-hire@example.com'},tapCookie,202);
 const mail=(await r.mails()).findLast(message=>message.to==='synthetic-auth-hire@example.com');assert.ok(mail);
 const token=new URL(mail.text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 const confirmed=await call('/auth/identity/email/confirm',{token},`${tapCookie}; ${cookieOf(requested)}`);
 const enrollmentCookie=cookieOf(confirmed);
 await refuseApps(enrollmentCookie,issued.pass);
 const durable=await register(r,enrollmentCookie);
 assert.equal((await r.call('/api/auth/me',{cookie:enrollmentCookie})).status,401);
 assert.equal((await r.call('/api/auth/me',{cookie:durable.cookie})).status,200);
 const pass=await r.db.prepare('SELECT * FROM auth_temporary_passes WHERE id=?').bind(issued.passId).first();assert.ok(pass.completed_at);
 assert.ok(await emailSession(r,'synthetic-auth-hire@example.com'),'a work-proved hire can confirm email again after durable enrollment');
 const details=(await r.db.prepare('SELECT detail FROM auth_role_operations WHERE subject_id=?').bind(issued.passId).all()).results;
 assert.ok(!JSON.stringify(details).includes(issued.pass));
 const events=(await r.db.prepare('SELECT event FROM auth_activity WHERE subject_id=?').bind(issued.passId).all()).results.map(row=>row.event);
 for(const event of ['temporary_pass.issued','temporary_pass.used','temporary_pass.completed'])assert.ok(events.includes(event));
});

test('temporary pass authority follows current group, manager, revocation, expiry and privileged-target protection',async t=>{
 const {r,actors,call,personId,group,request,issue}=await setup(t);
 const requestId=await request();
 const limitedRole=await (await call('/api/auth/roles/preview',{kind:'role',role:{name:'Synthetic Auth limited reset',rank:10,permissions:['roles.view','cases.open','people.factors.reset']}})).json();
 await call('/api/auth/roles/apply',{previewId:limitedRole.previewId});
 const limitedGrant=await (await call('/api/auth/roles/preview',{kind:'grant',personId:'synthetic-auth-other',roleId:limitedRole.plan.role.id,resources:{view:{groups:[group.id]},edit:{groups:[group.id]}}})).json();
 await call('/api/auth/roles/apply',{previewId:limitedGrant.previewId});
 await call('/api/auth/temporary-passes/issue',{requestId},actors.other.cookie,403);
 await call('/api/auth/groups/remove',{groupId:group.id,personId});
 await call('/api/auth/temporary-passes/issue',{requestId},actors.helper.cookie,403);
 await call('/api/auth/groups/add',{groupId:group.id,personId});
 const raced=await r.call('/api/auth/temporary-passes/issue',{method:'POST',cookie:actors.helper.cookie,data:{requestId},onboardingRace:{prefix:'SELECT * FROM auth_temporary_pass_requests WHERE id=?',sql:`DELETE FROM auth_group_members WHERE group_id='${group.id}' AND person_id='${personId}'`}});
 assert.equal(raced.status,409,'a scope change after role preflight refuses the atomic issue claim');
 assert.equal((await r.db.prepare('SELECT issued_at FROM auth_temporary_pass_requests WHERE id=?').bind(requestId).first()).issued_at,null);
 await call('/api/auth/groups/add',{groupId:group.id,personId});
 let issued=await (await call('/api/auth/temporary-passes/issue',{requestId},actors.helper.cookie,201)).json();
 await call('/api/auth/directory/edit',{personId,set:{manager:'synthetic-auth-other'}});
 await call('/auth/identity/temporary-pass',{pass:issued.pass},null,403);
 await call('/api/auth/directory/edit',{personId,set:{manager:'synthetic-auth-manager'}});
 await call('/api/auth/temporary-passes/revoke',{passId:issued.passId},actors.helper.cookie);
 await call('/auth/identity/temporary-pass',{pass:issued.pass},null,403);
 issued=await issue();
 const redeemed=await call('/auth/identity/temporary-pass',{pass:issued.pass},null);
 const tapCookie=cookieOf(redeemed);
 await call('/api/auth/groups/remove',{groupId:group.id,personId});
 assert.equal((await r.call('/api/auth/me',{cookie:tapCookie})).status,401);
 await call('/api/auth/groups/add',{groupId:group.id,personId});
 const pending=await request();
 const privileged=await (await call('/api/auth/roles/preview',{kind:'grant',personId,roleId:'help-desk',resources:{view:{groups:[group.id]},edit:{groups:[group.id]}}})).json();
 await call('/api/auth/roles/apply',{previewId:privileged.previewId});
 await call('/api/auth/temporary-passes/issue',{requestId:pending},actors.helper.cookie,403);
 const revoke=await (await call('/api/auth/roles/preview',{kind:'revoke',grantId:privileged.plan.id})).json();
 await call('/api/auth/roles/apply',{previewId:revoke.previewId});
 issued=await issue();r.now=issued.expiresAt;
 await call('/auth/identity/temporary-pass',{pass:issued.pass},null,403);
 const cancelled=await setup(t),cancelRequest=await cancelled.request();
 await cancelled.call('/api/auth/onboarding/rescind',{personId:cancelled.personId});
 await cancelled.call('/api/auth/temporary-passes/issue',{requestId:cancelRequest},cancelled.actors.helper.cookie,403);
});
