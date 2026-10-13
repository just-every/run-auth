import {test} from 'node:test';
import assert from 'node:assert/strict';
import {emailSession} from './runtime.mjs';
import {issueClient} from './policy-helpers.mjs';
import {ownerInstall,passkeyPerson,mint,preparer,file,approve,approvalProof,reject,post,table,proposal,person,activity,signInAgain} from './agents-helpers.mjs';

const ADA='ada@northwind.example.com',IVY='ivy@northwind.example.com',SAM='sam@northwind.example.com';
const PROVIDERS=[{id:'company',label:'Company Google',preset:'google',clientId:'agent-test',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only'}];

// A populated install: an app with a grant, a signed-in member, an invitation,
// a suspended person, an allowed domain and a required-provider rule.
async function install(t) {
 const {r,owner}=await ownerInstall(t);r.upstreamProviders=PROVIDERS;
 const app=await issueClient(r);
 const ada=await passkeyPerson(r,'ada',ADA,'member');
 assert.equal((await app.redeem(await app.authorize(ada.cookie))).status,200,'ada uses the app');
 await r.person('sam',SAM,'member');const sam=await emailSession(r,SAM);
 for(const [path,data] of [['/api/auth/people/invite',{email:IVY,name:'Ivy'}],['/api/auth/people/suspend',{personId:'sam'}],['/api/auth/people/domain',{domain:'northwind.example.com'}],['/api/auth/people/domain-rule',{domain:'contractors.example.com',providerId:'company'}]])
  assert.ok((await r.call(path,post(data,owner.cookie))).ok,path);
 return {r,owner,app,ada,sam,key:await mint(r,owner.cookie)};
}
const snapshot=async r=>({people:await table(r,'oa_operators'),sessions:await table(r,'auth_sessions'),grants:await table(r,'auth_grants'),apps:await table(r,'auth_clients'),rules:await table(r,'oa_domain_rules'),domains:await table(r,'auth_domains'),passkeys:await table(r,'auth_passkeys'),links:await table(r,'oa_external_identities'),cancellations:await table(r,'oa_invitation_cancellations'),mail:(await r.mails()).length});

// Field names the inventory may return; anything else fails the test.
const ALLOWED=new Set(['key','key.id','key.label','key.expiresAt','people','people[].id','people[].email','people[].name','people[].role','people[].state','people[].suspended','people[].passkey','people[].lastSignInAt',
 'invitations','invitations[].id','invitations[].email','invitations[].name','invitations[].invitedAt','allowedDomains','allowedDomains[]','domainRules','domainRules[].domain','domainRules[].providerId',
 'providers','providers[].id','providers[].label','apps','apps[].id','apps[].name','apps[].origin','apps[].disabled',
 'proposals','proposals[].id','proposals[].kind','proposals[].target','proposals[].reason','proposals[].status','proposals[].effect.person','proposals[].effect.person.email','proposals[].effect.person.name','proposals[].effect.person.role','proposals[].effect.person.status','proposals[].effect.after','proposals[].effect.after.id','proposals[].effect.after.label',
 'proposals[].effect.activeSessions','proposals[].effect.apps','proposals[].effect.apps[].name','proposals[].effect.apps[].origin','proposals[].effect.passkey','proposals[].effect.invitationEmail',
 'proposals[].effect.domain','proposals[].effect.provider','proposals[].effect.provider.id','proposals[].effect.provider.label','proposals[].effect.people','proposals[].effect.people[].email','proposals[].effect.people[].status',
 'proposals[].outcome','proposals[].outcome.reason','proposals[].outcome.changed','proposals[].outcome.changed[]','proposals[].createdAt','proposals[].expiresAt','proposals[].decidedAt',
 'proposalKinds','proposalKinds[]','unavailableKinds','unavailableKinds[].kind','unavailableKinds[].reason','generatedAt']);
// Every field name in a response, as a path such as people[].email.
function paths(value,prefix='',found=new Set()) {
 if(Array.isArray(value)){found.add(prefix);for(const item of value)paths(item,prefix+'[]',found);}
 else if(value&&typeof value==='object')for(const [k,v] of Object.entries(value))paths(v,prefix?`${prefix}.${k}`:k,found);
 else found.add(prefix);
 return found;
}

test('the inventory returns only allow-listed fields and no session, passkey, key or token material from a populated store',async t=>{
 const {r,owner,key}=await install(t);
 await r.db.prepare("INSERT INTO auth_recoveries(id,person_id,session_id,created_at,ready_at) VALUES('recovery-1','ada','s',?,?)").bind(r.now,r.now+1).run();
 await r.call('/api/auth/keys/stage',post({alg:'RS256'},owner.cookie));
 const decided=await file(r,key,{kind:'remove_invitation',target:IVY,reason:'Invited by mistake'});
 assert.equal((await reject(r,owner.cookie,decided)).status,200);
 await file(r,key,{kind:'suspend_person',target:ADA,reason:'Left on 10 October'});
 const response=await preparer(r,key);assert.equal(response.status,200);
 const text=await response.text(),inventory=JSON.parse(text);
 const unexpected=[...paths(inventory)].filter(path=>!ALLOWED.has(path));
 assert.deepEqual(unexpected,[],'every returned field is on the allow-list');
 // What the store holds that must never leave through a key.
 const secrets=[key,key.slice(9)];
 for(const [sql,columns] of [['SELECT id,token_hash FROM auth_sessions',['id','token_hash']],['SELECT id,public_key FROM auth_passkeys',['id','public_key']],['SELECT secret_hash FROM auth_agent_keys',['secret_hash']],['SELECT kid,encrypted_private FROM auth_signing_keys',['kid','encrypted_private']],['SELECT code_hash FROM auth_codes',['code_hash']],['SELECT id FROM auth_challenges',['id']],['SELECT id,session_id FROM auth_recoveries',['id']]])
  for(const row of (await r.db.prepare(sql).all()).results)for(const column of columns)secrets.push(String(row[column]));
 assert.ok(secrets.length>12,'the store holds sessions, passkeys, keys, signing keys and codes');
 for(const secret of secrets)assert.ok(!text.includes(secret),'no secret material in the inventory');
 // And it does describe the install.
 const ada=inventory.people.find(p=>p.email===ADA);assert.deepEqual({state:ada.state,passkey:ada.passkey,suspended:ada.suspended},{state:'active',passkey:true,suspended:false});assert.ok(ada.lastSignInAt);
 assert.equal(inventory.people.find(p=>p.email===SAM).suspended,true);
 assert.deepEqual(inventory.invitations.map(i=>i.email),[IVY]);
 assert.deepEqual(inventory.domainRules,[{domain:'contractors.example.com',providerId:'company'}]);assert.deepEqual(inventory.allowedDomains,['northwind.example.com']);
 assert.deepEqual(inventory.apps.map(a=>a.name),['Policy app']);
 assert.deepEqual(inventory.proposals.map(p=>p.status).sort(),['pending','rejected']);
});

// Each kind: filing changes nothing; approval does exactly its effect.
const KINDS=[
 ['suspend_person',{target:ADA},async({r,ada},effect)=>{
  assert.deepEqual(effect.apps.map(a=>a.name),['Policy app']);assert.ok(effect.activeSessions>=1);assert.equal(effect.passkey,true);
  return async()=>{assert.equal((await person(r,ADA)).status,'inactive');assert.equal((await r.call('/api/auth/me',{cookie:ada.cookie})).status,401,'her session ends');
   assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_sessions WHERE person_id=? AND revoked_at IS NULL').bind('ada').first()).n,0);};
 }],
 ['restore_person',{target:SAM},async({r,sam})=>async()=>{assert.equal((await person(r,SAM)).status,'active');assert.equal((await r.call('/api/auth/me',{cookie:sam})).status,401,'earlier sessions stay ended');}],
 ['invite_person',{target:'new@northwind.example.com',name:'Nell New'},async({r},effect)=>{assert.equal(effect.invitationEmail,true);
  return async()=>{const p=await person(r,'new@northwind.example.com');assert.deepEqual([p.role,p.status,p.display_name],['member','invited','Nell New']);assert.deepEqual((await r.mails()).slice(-1).map(m=>m.to),['new@northwind.example.com']);};}],
 ['remove_invitation',{target:IVY},async({r})=>async()=>{const p=await person(r,IVY);assert.equal(p.status,'inactive');assert.ok(await r.db.prepare('SELECT 1 FROM oa_invitation_cancellations WHERE operator_id=?').bind(p.id).first());}],
 ['add_domain_rule',{target:'northwind.example.com',providerId:'company'},async({r},effect)=>{assert.deepEqual(effect.people.map(p=>p.email),[ADA,IVY]);assert.equal(effect.after.label,'Company Google');
  return async()=>assert.equal((await r.db.prepare("SELECT provider_id FROM oa_domain_rules WHERE domain='northwind.example.com'").first()).provider_id,'company');}],
 ['remove_domain_rule',{target:'contractors.example.com'},async({r})=>async()=>assert.equal(await r.db.prepare("SELECT 1 FROM oa_domain_rules WHERE domain='contractors.example.com'").first(),null)],
 ['remove_app_link',{target:'policy-app'},async({r},effect)=>{assert.deepEqual([effect.app.name,effect.after],['Policy app','removed']);
  return async()=>assert.ok((await r.db.prepare("SELECT disabled_at FROM auth_clients WHERE id='policy-app'").first()).disabled_at,'the app is unlinked');}],
];
for(const [kind,data,expect] of KINDS) test(`${kind.replace(/_/g,' ')}: filing changes nothing but the proposal; one passkey approval runs exactly it and Activity names the key, the approver and the result`,async t=>{
 const setup=await install(t),{r,owner,key}=setup;
 const before=await snapshot(r);
 const filed=await preparer(r,key,{method:'POST',data:{kind,...data,reason:'Requested in the directory review'}});assert.equal(filed.status,201,await filed.clone().text());
 const {id,status,expiresAt}=await filed.json();assert.equal(status,'pending');assert.equal(expiresAt,r.now+86400000);
 assert.deepEqual(await snapshot(r),before,'filing leaves people, sessions, apps, links, rules and mail unchanged');
 const stored=await proposal(r,id);assert.ok(stored.state_digest&&stored.effect&&stored.reason);
 const verify=await expect(setup,JSON.parse(stored.effect));
 const approved=await approve(r,owner,id);assert.equal(approved.status,200,await approved.clone().text());
 await verify();
 const [done]=await activity(r,'agent_proposal_done');
 assert.deepEqual({actor:done.actor_id,subject:done.subject_id,key:done.detail.key,result:done.detail.result},{actor:'owner',subject:id,key:'Directory agent',result:'done'});
 assert.equal((await proposal(r,id)).status,'done');
});

test('approval is one exact passkey approval by an administrator, rechecked at execution: who may approve, stale targets, expiry, replay and rejection',async t=>{
 const {r,owner,ada,key}=await install(t);
 const member=await passkeyPerson(r,'member','member@example.com','member'),ownerEmailOnly=await emailSession(r,'owner@example.com');
 const id=await file(r,key,{kind:'suspend_person',target:ADA,reason:'Left on 10 October'});
 for(const [label,cookie,error] of [['no session',undefined,'sign_in_required'],['member passkey session',member.cookie,'passkey_admin_required'],['owner email-link-only session',ownerEmailOnly,'passkey_admin_required']]) {
  const refused=await approve(r,{cookie,key:owner.key},id);assert.ok([401,403].includes(refused.status),label);assert.equal((await refused.json()).error,error,label);
 }
 // The challenge must be signed by the approver's own passkey, in the session that asked.
 const foreign=await approvalProof(r,owner,id);foreign.request.data.response=ada.key.authenticate(foreign.options);
 assert.equal((await r.call('/api/auth/agents/approve',foreign.request)).status,400,'another person\'s passkey is refused');
 const elsewhere=await approvalProof(r,owner,id),second=await passkeyPerson(r,'ann','ann@example.com','admin');
 elsewhere.request.cookie=elsewhere.request.cookie.replace(owner.cookie,second.cookie);
 assert.equal((await r.call('/api/auth/agents/approve',elsewhere.request)).status,403,'a challenge works only in the session that asked for it');
 assert.equal((await person(r,ADA)).status,'active');assert.equal((await proposal(r,id)).status,'pending');

 // Replay: the signed challenge is spent, and a decided proposal accepts no new approval.
 const proof=await approvalProof(r,owner,id);
 assert.equal((await r.call('/api/auth/agents/approve',proof.request)).status,200);
 const replayed=await r.call('/api/auth/agents/approve',proof.request);assert.equal(replayed.status,400);assert.equal((await replayed.json()).error,'invalid_challenge');
 const again=await approve(r,owner,id);assert.equal(again.status,409);assert.equal((await again.json()).error,'proposal_decided');
 assert.equal((await activity(r,'agent_proposal_done')).length,1);

 // Stale: the target changed after filing, so the proposal closes and says what changed.
 await r.person('bo','bo@northwind.example.com','member');
 const staleId=await file(r,key,{kind:'suspend_person',target:'bo@northwind.example.com',reason:'Contract ended'});
 assert.equal((await r.call('/api/auth/people/role',post({id:'bo',role:'admin'},owner.cookie))).status,200);
 const page=await (await r.call('/api/auth/agents?proposal='+staleId,{cookie:owner.cookie})).json();
 assert.equal(page.proposal.unchanged,false);assert.deepEqual(page.proposal.changed,['role: member → admin']);assert.equal(page.proposal.fresh.person.role,'admin');assert.equal(page.proposal.effect.person.role,'member');
 const stale=await approve(r,owner,staleId);assert.equal(stale.status,409);assert.deepEqual(await stale.json(),{error:'proposal_stale',changed:['role: member → admin']});
 assert.equal((await person(r,'bo@northwind.example.com')).status,'active');
 assert.deepEqual(JSON.parse((await proposal(r,staleId)).outcome),{reason:'stale',changed:['role: member → admin']});
 assert.deepEqual((await activity(r,'agent_proposal_rejected')).at(-1).detail.changed,['role: member → admin']);

 // Rejecting is one click and recorded; a rejected proposal cannot then be approved.
 const rejectedId=await file(r,key,{kind:'invite_person',target:'eve@northwind.example.com',reason:'New starter'});
 assert.equal((await reject(r,member.cookie,rejectedId)).status,403);
 assert.equal((await reject(r,owner.cookie,rejectedId)).status,200);
 assert.equal((await approve(r,owner,rejectedId)).status,409);assert.equal(await person(r,'eve@northwind.example.com'),null);
 assert.equal((await activity(r,'agent_proposal_rejected')).at(-1).detail.reason,'rejected_by_person');

 // Expiry: after 24 hours a proposal runs for nobody, even freshly signed in.
 const expiringId=await file(r,key,{kind:'remove_invitation',target:IVY,reason:'Never accepted'});
 r.now+=86400000;
 const returning=await signInAgain(r,owner,'owner@example.com');
 const expired=await approve(r,returning,expiringId);assert.equal(expired.status,409);
 assert.deepEqual((await activity(r,'agent_proposal_rejected')).at(-1).detail.reason,'expired');
 assert.equal((await person(r,IVY)).status,'invited');
 assert.equal((await (await preparer(r,key)).json()).proposals.find(p=>p.id===expiringId).status,'rejected');
});

test('concurrent approvals run once: two administrators together, and one administrator double-clicking',async t=>{
 const {r,owner,key}=await install(t),ann=await passkeyPerson(r,'ann','ann@example.com','admin');
 for(const [label,first,second,target] of [['two administrators',owner,ann,ADA],['double click',owner,owner,IVY]]) {
  const id=await file(r,key,{kind:target===ADA?'suspend_person':'remove_invitation',target,reason:'Left'});
  const version=(await person(r,target)).version;
  const proofs=[await approvalProof(r,first,id),await approvalProof(r,second,id)],barrier={name:label,size:2};
  // Both pass every check before either commits; only the claim decides.
  const responses=await Promise.all(proofs.map(proof=>r.call('/api/auth/agents/approve',{...proof.request,barrier})));
  assert.deepEqual(responses.map(response=>response.status).sort(),[200,409],label);
  assert.equal((await person(r,target)).version,version+1,`${label}: the change ran once`);
  assert.equal((await activity(r,'agent_proposal_done')).filter(entry=>entry.subject_id===id).length,1,`${label}: one done entry`);
 }
});

test('a revoked key\'s pending proposals stay with people, and no proposal suspends the owner (who is always the last administrator) or its own approver',async t=>{
 const {r,owner,key}=await install(t);
 const ann=await passkeyPerson(r,'ann','ann@example.com','admin'),annKey=await mint(r,ann.cookie,'Ann agent');
 const keep=await file(r,key,{kind:'suspend_person',target:ADA,reason:'Left'}),drop=await file(r,key,{kind:'remove_invitation',target:IVY,reason:'Never accepted'});
 const keyId=(await r.db.prepare("SELECT id FROM auth_agent_keys WHERE label='Directory agent'").first()).id;
 assert.equal((await r.call('/api/auth/agents/revoke',post({keyId},owner.cookie))).status,200);
 assert.equal((await preparer(r,key)).status,401);
 const page=await (await r.call('/api/auth/agents?proposal='+keep,{cookie:owner.cookie})).json();
 assert.ok(page.proposal.key_revoked_at,'the approver sees the key was revoked');assert.equal(page.proposal.unchanged,true);
 assert.equal((await approve(r,owner,keep)).status,200);assert.equal((await person(r,ADA)).status,'inactive');
 assert.equal((await reject(r,owner.cookie,drop)).status,200);assert.equal((await person(r,IVY)).status,'invited');

 // The owner cannot be proposed for suspension at all.
 const owners=await preparer(r,annKey,{method:'POST',data:{kind:'suspend_person',target:'owner@example.com',reason:'x'}});
 assert.equal(owners.status,409);assert.equal((await owners.json()).error,'owner_suspension_requires_transfer');
 // A key proposing its own accountable owner's suspension needs a second administrator.
 const self=await file(r,annKey,{kind:'suspend_person',target:'ann@example.com',reason:'Leaving'});
 const own=await approve(r,ann,self);assert.equal(own.status,403);assert.equal((await own.json()).error,'second_administrator_required');
 assert.equal((await proposal(r,self)).status,'pending','another administrator can still decide');
 assert.equal((await person(r,'ann@example.com')).status,'active');
 assert.equal((await activity(r,'agent_proposal_refused')).at(-1).detail.reason,'second_administrator_required');
 assert.equal((await approve(r,owner,self)).status,200);assert.equal((await person(r,'ann@example.com')).status,'inactive');
 assert.equal((await preparer(r,annKey)).status,401,'her key ends with her administration');
});
