import {legacyBridgeFlow} from './legacy-bridge-flow.mjs';
import {hookServer,verifiedHook} from './hooks-server.mjs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {emailSession,cookieOf} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {requestProof,finishProof,issueClient} from './policy-helpers.mjs';
import {ownerInstall,stage,staged,review,byEmail,admit,count,table,post} from './move-in-helpers.mjs';

const ADA='ada@northwind.example.com',GRACE='grace@northwind.example.com',MOLLY='molly@northwind.example.com';
const person=(r,email)=>r.db.prepare('SELECT * FROM oa_operators WHERE email=?').bind(email).first();

test('admission is the ordinary invitation: administrators only, no proof, right, session or mail, and existing people never rebound',async t=>{
 const {r,cookie}=await ownerInstall(t);
 // An existing person with a passkey and an upstream link whose address the export repeats.
 await r.person('ada',ADA,'member');
 const ada=await register(r,await emailSession(r,ADA));
 await r.db.prepare("INSERT INTO oa_external_identities(issuer,subject,operator_id) VALUES('https://accounts.google.com','ada-google','ada')").run();
 await r.person('member','member@example.com','member');const member=(await register(r,await emailSession(r,'member@example.com'))).cookie;
 const ownerEmailOnly=await emailSession(r,'owner@example.com');
 const batch=await staged(r,cookie,'auth0-users.csv'),all=[0,1,2];
 const snapshot=async()=>({people:await table(r,'oa_operators'),passkeys:await table(r,'auth_passkeys'),links:await table(r,'oa_external_identities'),subjects:await table(r,'auth_former_subjects'),rows:await table(r,'auth_import_rows'),mail:(await r.mails()).length});
 const before=await snapshot();
 for(const [label,session,error] of [['member passkey session',member,'passkey_admin_required'],['owner email-link-only session',ownerEmailOnly,'passkey_admin_required'],['no session',undefined,'sign_in_required']]) {
  const refused=await admit(r,session,batch,all);assert.ok([401,403].includes(refused.status),label);assert.equal((await refused.json()).error,error,label);
 }
 r.now+=11*60000;
 const stale=await admit(r,cookie,batch,all);assert.equal(stale.status,403);assert.equal((await stale.json()).error,'local_email_step_up_required');
 assert.deepEqual(await snapshot(),before,'refusals change nothing');
 const fresh=await finishProof(r,await requestProof(r,'owner@example.com',cookie));assert.equal(fresh.status,200);
 const owner=cookieOf(fresh),mail=(await r.mails()).length,edge=await hookServer(t);r.edges=edge.edges;
 const configured=await r.call('/api/auth/hooks/register',post({point:'user_import',url:'https://hooks.example.com/move-in',allowedFields:['name']},owner));assert.equal(configured.status,201);const hook=await configured.json();
 edge.responses.set('/move-in',{body:{allow:false}});
 assert.equal((await admit(r,owner,batch,all)).status,403);assert.equal(await person(r,GRACE),null);
 edge.responses.set('/move-in',{body:{allow:true}});

 const admitted=await admit(r,owner,batch,all);assert.equal(admitted.status,200);
 const result=await admitted.json();assert.equal(result.admitted,2);assert.ok(edge.received.every(call=>verifiedHook(hook.secret,call)));assert.equal((await r.call('/api/auth/hooks/disable',post({id:hook.id},owner))).status,200);assert.deepEqual(result.skipped,[{email:ADA,reasons:['existing_person']}]);
 assert.equal((await r.mails()).length,mail,'admission sends no mail');
 for(const email of [GRACE,MOLLY]) {
  const p=await person(r,email);assert.deepEqual({role:p.role,status:p.status,version:p.version},{role:'member',status:'invited',version:1});
  for(const name of ['auth_emails','auth_passkeys','auth_sessions','auth_grants'])assert.equal(await count(r,`SELECT count(*) AS n FROM ${name} WHERE person_id=?`,p.id),0,`${email}: no ${name}`);
 }
 assert.deepEqual(await person(r,ADA),before.people.find(p=>p.email===ADA),'a matching email leaves the existing person unchanged');
 assert.deepEqual(await table(r,'auth_passkeys'),before.passkeys);assert.deepEqual(await table(r,'oa_external_identities'),before.links);
 assert.equal(await count(r,"SELECT count(*) AS n FROM auth_former_subjects WHERE person_id='ada'"),0,'no former subject attaches to an existing person');
 assert.equal((await authenticate(r,ada.key)).response.status,200,'the existing passkey still signs in as before');
 // The admitted person needs the email link in their own browser: another browser's link fails.
 const theirs=await requestProof(r,MOLLY),other=await requestProof(r,GRACE);
 assert.equal((await finishProof(r,{binding:other.binding,token:theirs.token})).status,400);
 assert.equal((await person(r,MOLLY)).status,'invited');
 const signedIn=await finishProof(r,theirs);assert.equal(signedIn.status,200);
 const molly=cookieOf(signedIn);assert.equal((await r.call('/api/auth/people',{cookie:molly})).status,403,'no administrator right');
 assert.equal((await r.call('/api/auth/me',{cookie:molly})).status,200);
 // Invitations go out only when the owner chooses, once, to unaccepted invitations from this batch.
 const sent=await r.call('/api/auth/move-in/invite',post({batchId:batch},owner));assert.equal(sent.status,200);assert.equal((await sent.json()).invited,1);
 assert.deepEqual((await r.mails()).slice(-1).map(m=>[m.to,m.subject]),[[GRACE,'You are invited to Auth']]);
 const again=await r.call('/api/auth/move-in/invite',post({batchId:batch},owner));assert.equal((await again.json()).invited,0);
});

test("importing the owner's own address changes nothing",async t=>{
 const {r,cookie}=await ownerInstall(t),batch=await staged(r,cookie,'google-30.json');
 const rows=await review(r,cookie,batch),own=byEmail(rows,'owner@example.com');
 const before={owner:await table(r,'oa_operators'),passkeys:await table(r,'auth_passkeys'),sessions:await table(r,'auth_sessions')};
 const response=await admit(r,cookie,batch,[own.idx]);assert.equal(response.status,200);
 assert.deepEqual(await response.json(),{admitted:0,skipped:[{email:'owner@example.com',reasons:['owner_address']}]});
 assert.deepEqual({owner:await table(r,'oa_operators'),passkeys:await table(r,'auth_passkeys'),sessions:await table(r,'auth_sessions')},before);
 assert.equal((await review(r,cookie,batch)).find(row=>row.idx===own.idx).status,'staged');
});

test('undo removes only the untouched person it admitted and records who was kept',async t=>{
 const {r,cookie}=await ownerInstall(t),batch=await staged(r,cookie,'auth0-users.csv');
 assert.equal((await (await admit(r,cookie,batch,[0,1,2])).json()).admitted,3);
 await emailSession(r,GRACE);
 const molly=await person(r,MOLLY);
 await r.db.prepare("INSERT INTO auth_clients(id,name,origin,sector_id,redirect_uris,jwks,source,created_at) VALUES('crm','CRM','https://crm.example.com','crm-sector','[]','{\"keys\":[]}','owner',?)").bind(r.now).run();
 await r.db.prepare("INSERT INTO auth_grants(client_id,person_id,created_at) VALUES('crm',?,?)").bind(molly.id,r.now).run();
 const ada=await person(r,ADA);
 const undone=await r.call('/api/auth/move-in/undo',post({batchId:batch},cookie));assert.equal(undone.status,200);
 const report=await undone.json();
 assert.deepEqual(report,{removed:[ADA],kept:[{email:GRACE,reasons:['signed_in','status_changed','later_activity']},{email:MOLLY,reasons:['app_grant']}]});
 assert.equal(await person(r,ADA),null);assert.equal(await count(r,'SELECT count(*) AS n FROM auth_former_subjects WHERE person_id=?',ada.id),0);
 assert.ok(await person(r,GRACE));assert.ok(await person(r,MOLLY));
 assert.equal(await count(r,'SELECT count(*) AS n FROM auth_former_subjects WHERE batch_id=?',batch),2,'kept people keep their former subjects');
 const entry=await r.db.prepare("SELECT d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='move_in_undone'").first();
 assert.deepEqual(JSON.parse(entry.detail),report,'the audit entry names who was removed and who was kept');
 assert.equal((await admit(r,cookie,batch,[0])).status,404,'an undone batch admits nothing more');
 const restaged=await stage(r,cookie,'auth0-users.csv');assert.equal(restaged.status,201,'the undone file stages again as a new batch');
 const again=(await restaged.json()).batchId;assert.notEqual(again,batch);
 assert.equal((await (await admit(r,cookie,again,[0])).json()).admitted,1,'and the person undo removed can be admitted from it');
});

test('a former Auth0 subject is data for app owners only: never accepted by a protocol endpoint, never the pairwise subject, and never exported for unadmitted rows',async t=>{
 const {r,cookie}=await ownerInstall(t),batch=await staged(r,cookie,'auth0-users.csv');
 assert.equal((await (await admit(r,cookie,batch,[0,2])).json()).admitted,2);
 const app=await issueClient(r);
 const csv=await r.call('/api/auth/move-in/subjects.csv?batch='+batch,{cookie});assert.equal(csv.status,200);
 assert.match(csv.headers.get('content-type'),/^text\/csv/);
 assert.deepEqual((await csv.text()).trim().split('\r\n'),['former_subject,auth_email,auth_status,source,export_date',`auth0|64f0000000000000000000a1,${ADA},invited,auth0,2026-10-11`,`auth0|64f0000000000000000000a3,${MOLLY},invited,auth0,2026-10-11`],'unadmitted Grace is not in the map');
 assert.equal((await r.call('/api/auth/move-in/subjects.csv?batch='+batch,{cookie:await emailSession(r,'owner@example.com')})).status,403);
 const former='auth0|64f0000000000000000000a3',molly=await emailSession(r,MOLLY);
 const grant=await app.authorize(molly),issued=await app.redeem(grant);assert.equal(issued.status,200);
 const tokens=await issued.json(),claims=JSON.parse(Buffer.from(tokens.id_token.split('.')[1],'base64url'));
 const pairwise=await r.db.prepare("SELECT subject FROM auth_subjects s JOIN oa_operators p ON p.id=s.person_id WHERE p.email=?").bind(MOLLY).first();
 assert.equal(claims.sub,pairwise.subject);assert.notEqual(claims.sub,former);
 assert.equal((await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}})).status,200);
 // The same session presenting the former subject is refused everywhere.
 const session=await r.db.prepare("SELECT s.id FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id WHERE p.email=? ORDER BY s.created_at DESC").bind(MOLLY).first();
 const now=Math.floor(r.now/1000);
 const forged=(await (await r.call('/',{action:'signed-token',claims:{aud:r.origin+'/oidc/userinfo',sub:former,client_id:'policy-app',sid:session.id,scope:'openid email',jti:'former-subject',iat:now,exp:now+60}})).json()).token;
 for(const token of [forged,encodeURIComponent(former)]) {
  const refused=await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+token}});assert.equal(refused.status,401);
 }
 const asCode=await app.redeem({code:former,verifier:grant.verifier});assert.equal(asCode.status,400);assert.equal((await asCode.json()).error,'invalid_grant');
 const hinted=await r.call('/oidc/authorize?'+new URLSearchParams({client_id:'policy-app',redirect_uri:'https://app.example.com/callback',response_type:'code',scope:'openid',state:'s',nonce:'n',code_challenge:'a'.repeat(43),code_challenge_method:'S256',prompt:'none',login_hint:former,id_token_hint:former}));
 assert.equal(new URL(hinted.headers.get('location')).searchParams.get('error'),'login_required','a former subject never signs anyone in');
 assert.equal(await count(r,"SELECT count(*) AS n FROM auth_subjects WHERE subject=?",former),0);
});

test('reviewed custom-directory workers migrate at first legacy login with protected history, exact subject mapping, inherited hooks and permanent bridge shutdown',legacyBridgeFlow);
