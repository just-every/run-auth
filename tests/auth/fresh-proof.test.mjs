import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {generateKeyPair,exportJWK} from 'jose';
import {openRuntime,cookieOf,emailSession} from './runtime.mjs';
import {authenticator,register,authenticate} from './webauthn.mjs';
import {requestProof,finishProof,beginPasskey,finishPasskey,sessionCookie} from './policy-helpers.mjs';
import {mint,file,approve} from './agents-helpers.mjs';

const post=(data={},cookie)=>({method:'POST',data,cookie});
const value=async(r,sql,...args)=>(await r.db.prepare(sql).bind(...args).first())?.v??null;
const passkeys=(r,person)=>value(r,'SELECT count(*) AS v FROM auth_passkeys WHERE person_id=?',person);
async function enroll(r,cookie) {
 const offered=await r.call('/auth/passkeys/register/options',post({},cookie));if(offered.status!==200)return offered;
 const tx=await offered.json();
 return r.call('/auth/passkeys/register/verify',post({transaction:tx.transaction,response:authenticator(r.origin).register(tx.options)},`${cookie}; ${cookieOf(offered)}`));
}

test('every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation',async t=>{
 const r=await openRuntime();t.after(()=>r.close());
 r.upstreamProviders=[{id:'company',preset:'google',clientId:'test-client',tokenAuthMethod:'client_secret_basic',clientSecret:'test-edge-only'}];
 for(const [id,role] of [['owner','owner'],['admin','admin'],['helper','admin'],['member','member'],['target','member'],['newcomer','member'],['leaver','member']])await r.person(id,`${id}@example.com`,role);
 await r.call('/.well-known/openid-configuration');
 const owner=await register(r,await emailSession(r,'owner@example.com')),admin=await register(r,await emailSession(r,'admin@example.com'));
 await register(r,await emailSession(r,'member@example.com'));
 const stale={owner:owner.cookie,admin:admin.cookie,member:await emailSession(r,'member@example.com'),ownerEmail:await emailSession(r,'owner@example.com'),newcomer:await emailSession(r,'newcomer@example.com')};
 const recovery=await (await r.call('/api/auth/recovery/start',post({},stale.member))).json(),token=randomBytes(32).toString('base64url');
 await r.call('/',{action:'recovery-token',token});
 // An agent key and two proposals, made while the proof was fresh.
 const agentKey=await mint(r,admin.cookie),keyId=await value(r,'SELECT id AS v FROM auth_agent_keys');
 const rejectable=await file(r,agentKey,{kind:'invite_person',target:'later@example.com',reason:'New starter'}),approvable=await file(r,agentKey,{kind:'suspend_person',target:'leaver@example.com',reason:'Left'});
 const serviceKeys=await generateKeyPair('ES256'),serviceJwk={...await exportJWK(serviceKeys.publicKey),kid:'admin-service',alg:'ES256',use:'sig'};
 const serviceConfig={name:'Directory reconciler',purpose:'Maintain approved groups',ownerId:'admin',jwks:{keys:[serviceJwk]},scopes:['groups.manage'],expiresAt:r.now+86400000};
 const serviceResponse=await r.call('/api/auth/admin-service-apps/create',post(serviceConfig,admin.cookie));assert.equal(serviceResponse.status,201);const service=await serviceResponse.json();
 r.now+=11*60000;
 const hardware=async(address,cookie)=>{const confirmed=await finishProof(r,await requestProof(r,address,cookie));assert.equal(confirmed.status,200);return sessionCookie(confirmed);};
 const fresh={owner:await hardware('owner@example.com',owner.cookie),admin:await hardware('admin@example.com',admin.cookie),member:await emailSession(r,'member@example.com'),ownerEmail:await emailSession(r,'owner@example.com'),newcomer:await emailSession(r,'newcomer@example.com')};
 const key=()=>value(r,'SELECT kid AS v FROM auth_signing_keys ORDER BY published_at DESC,kid LIMIT 1');
 const actions=[
  ['first passkey enrollment','newcomer',cookie=>enroll(r,cookie),()=>passkeys(r,'newcomer')],
  ['additional passkey enrollment','owner',cookie=>enroll(r,cookie),()=>passkeys(r,'owner')],
  ['recovery approval','admin',cookie=>r.call('/api/auth/recovery/approve',post({id:recovery.id},cookie)),()=>value(r,'SELECT approved_by AS v FROM auth_recoveries WHERE id=?',recovery.id)],
  ['recovery completion','member',cookie=>r.call('/api/auth/recovery/complete',post({id:recovery.id},cookie)),()=>passkeys(r,'member')],
  ['role grant','owner',cookie=>r.call('/api/auth/people/role',post({id:'target',role:'admin'},cookie)),()=>value(r,"SELECT role AS v FROM oa_operators WHERE id='target'")],
  ['role removal','owner',cookie=>r.call('/api/auth/people/role',post({id:'helper',role:'member'},cookie)),()=>value(r,"SELECT role AS v FROM oa_operators WHERE id='helper'")],
  ['suspension','admin',cookie=>r.call('/api/auth/people/suspend',post({personId:'target'},cookie)),()=>value(r,"SELECT status AS v FROM oa_operators WHERE id='target'")],
  ['invitation','admin',cookie=>r.call('/api/auth/people/invite',post({email:'invitee@example.com'},cookie)),()=>value(r,"SELECT count(*) AS v FROM oa_operators WHERE email='invitee@example.com'")],
  ['allowed domain','admin',cookie=>r.call('/api/auth/people/domain',post({domain:'allowed.example'},cookie)),()=>value(r,'SELECT count(*) AS v FROM auth_domains')],
  ['allowed domain alias','admin',cookie=>r.call('/api/auth/domains/add',post({domain:'alias.example'},cookie)),()=>value(r,'SELECT count(*) AS v FROM auth_domains')],
  ['required provider rule','admin',cookie=>r.call('/api/auth/people/domain-rule',post({domain:'company.example',providerId:'company'},cookie)),()=>value(r,'SELECT count(*) AS v FROM oa_domain_rules')],
  ['required provider removal','admin',cookie=>r.call('/api/auth/people/domain-rule',post({domain:'company.example',providerId:''},cookie)),()=>value(r,'SELECT count(*) AS v FROM oa_domain_rules')],
  ['signing key staging','owner',cookie=>r.call('/api/auth/keys/stage',post({},cookie)),()=>value(r,'SELECT count(*) AS v FROM auth_signing_keys')],
  ['staged signing key retirement','owner',async cookie=>r.call('/api/auth/keys/retire',post({kid:await key()},cookie)),()=>value(r,'SELECT count(*) AS v FROM auth_signing_keys WHERE retire_at IS NOT NULL')],
  ['admin service app creation','admin',cookie=>r.call('/api/auth/admin-service-apps/create',post(serviceConfig,cookie)),()=>value(r,'SELECT count(*) AS v FROM auth_admin_service_apps')],
  ['admin service app reassignment','admin',cookie=>r.call('/api/auth/admin-service-apps/reassign',post({id:service.id,ownerId:'owner'},cookie)),()=>value(r,'SELECT revision AS v FROM auth_admin_service_apps WHERE id=?',service.id)],
  ['admin service app revocation','admin',cookie=>r.call('/api/auth/admin-service-apps/revoke',post({id:service.id},cookie)),()=>value(r,'SELECT revoked_at AS v FROM auth_admin_service_apps WHERE id=?',service.id)],
  ['agent key minting','admin',cookie=>r.call('/api/auth/agents/mint',post({label:'Second'},cookie)),()=>value(r,'SELECT count(*) AS v FROM auth_agent_keys')],
  ['agent key renewal','admin',cookie=>r.call('/api/auth/agents/renew',post({keyId},cookie)),()=>value(r,'SELECT expires_at AS v FROM auth_agent_keys WHERE id=?',keyId)],
  ['proposal rejection','admin',cookie=>r.call('/api/auth/agents/reject',post({proposalId:rejectable},cookie)),()=>value(r,'SELECT status AS v FROM auth_agent_proposals WHERE id=?',rejectable)],
  ['proposal approval','admin',cookie=>approve(r,{cookie,key:admin.key},approvable),()=>value(r,"SELECT status AS v FROM oa_operators WHERE id='leaver'")],
  ['agent key revocation','admin',cookie=>r.call('/api/auth/agents/revoke',post({keyId},cookie)),()=>value(r,'SELECT revoked_at AS v FROM auth_agent_keys WHERE id=?',keyId)],
  ['break-glass recovery token','ownerEmail',cookie=>r.call('/api/auth/recovery/token',post({token},cookie)),()=>passkeys(r,'owner')],
 ];
 for(const [name,actor,act,state] of actions) {
  const before=await state(),refused=await act(stale[actor]);
  assert.equal(refused.status,403,name);assert.equal((await refused.json()).error,'local_email_step_up_required',name);
  assert.deepEqual(await state(),before,`${name}: refused without change`);
  const accepted=await act(fresh[actor]);
  assert.ok(accepted.status>=200&&accepted.status<300,`${name}: ${accepted.status} ${await accepted.text()}`);
  assert.notDeepEqual(await state(),before,`${name}: committed`);
 }
});

test('an enrollment challenge belongs to the session that issued it and dies with it',async t=>{
 const r=await openRuntime();t.after(()=>r.close());await r.person('owner','owner@example.com','owner');
 // A second live passkey session of the same person, with its own fresh local proof.
 const owner=await register(r,await emailSession(r,'owner@example.com')),other=await finishPasskey(r,await beginPasskey(r,owner.key,await emailSession(r,'owner@example.com')));
 assert.equal(other.status,200);const otherCookie=sessionCookie(other);
 const begin=async()=>{const offered=await r.call('/auth/passkeys/register/options',post({},owner.cookie));assert.equal(offered.status,200);const tx=await offered.json(),key=authenticator(r.origin);return {key,binding:cookieOf(offered),data:{transaction:tx.transaction,response:key.register(tx.options)}};};
 const submit=(attempt,cookie)=>r.call('/auth/passkeys/register/verify',post(attempt.data,`${cookie}; ${attempt.binding}`));
 const borrowed=await begin(),live=await submit(borrowed,otherCookie);
 assert.equal(live.status,403);assert.equal((await live.json()).error,'enrollment_session_changed');
 const orphaned=await begin(),orphanedAgain=await begin();
 assert.equal((await r.call('/api/auth/signout',post({},owner.cookie))).status,200);
 assert.equal((await submit(orphaned,otherCookie)).status,403);
 assert.equal((await submit(orphanedAgain,owner.cookie)).status,401);
 assert.equal(await passkeys(r,'owner'),1,'zero candidate credential rows');
 for(const attempt of [borrowed,orphaned,orphanedAgain])assert.equal((await authenticate(r,attempt.key)).response.status,400);
});
