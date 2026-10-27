import assert from 'node:assert/strict';
import {ownerInstall,passkeyPerson} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {command,grant,people,operations,identityState,credentialsState} from './session-control-helpers.mjs';

export async function sessionControlAuthority(t) {
 const {r,owner}=await ownerInstall(t);
 const desk=await passkeyPerson(r,'desk','desk@example.com');
 const missing=await passkeyPerson(r,'viewer','viewer@example.com');
 const employee=await passkeyPerson(r,'employee','employee@example.com');
 const outside=await passkeyPerson(r,'outside','outside@example.com');
 const peer=await passkeyPerson(r,'peer','peer@example.com');
 const higher=await passkeyPerson(r,'higher','higher@example.com','admin');
 const deskGrant=await grant(r,owner.cookie,'desk','help-desk',['employee','outside','peer','higher','desk'],['employee','peer','higher','desk']);
 await grant(r,owner.cookie,'peer','help-desk',['employee']);
 await grant(r,owner.cookie,'viewer','manager',['employee']);
 const emailOnly=await emailSession(r,'owner@example.com');
 const foreign=await command(r,owner.cookie,'/api/auth/organizations/create',{name:'Separate employer'},201);
 const model=await (await r.call('/api/auth/roles',{cookie:owner.cookie})).json();
 for(const id of ['owner','identity-administrator','help-desk'])assert.ok(model.builtinRoles.find(role=>role.id===id).permissions.includes('people.sessions.end'),'the permission is published to the applicable built-in role');
 const rows=await people(r,desk.cookie);
 assert.equal(rows.find(p=>p.id==='employee').canEndSessions,true);
 for(const id of ['outside','peer','higher','desk'])assert.equal(rows.find(p=>p.id===id).canEndSessions,false,id+' is fenced in the person inventory');
 const reason='Investigate employee device loss';
 const protectedPeople=[['employee',employee],['outside',outside],['peer',peer],['higher',higher],['desk',desk]];
 const capture=()=>Promise.all(protectedPeople.map(async([id])=>({id,identity:await identityState(r,id),credentials:await credentialsState(r,id),operations:await operations(r,owner.cookie,id)})));
 const unchanged=async(before,label)=>{
  assert.deepEqual(await capture(),before,label+' leaves identity, credentials, logout queues and operation history unchanged');
  for(const [id,who] of protectedPeople)assert.equal((await r.call('/api/auth/me',{cookie:who.cookie})).status,200,label+' preserves '+id+' session');
 };
 const refused=async(label,{cookie=desk.cookie,personId='employee',data={personId,reason},prefix='',status=403,extra={}}={})=>{
  const before=await capture();
  const response=await r.call(prefix+'/api/auth/roles/end-sessions',{method:'POST',cookie,data,...extra});
  assert.equal(response.status,status,label+' '+await response.clone().text());await unchanged(before,label);
 };
 await refused('signed out',{cookie:null,status:401});
 await refused('email-only administrator',{cookie:emailOnly});
 await refused('missing permission',{cookie:missing.cookie});
 await refused('view without edit scope',{personId:'outside'});
 await refused('equal account rank',{personId:'peer'});
 await refused('higher account rank',{personId:'higher'});
 await refused('self target',{personId:'desk'});
 await refused('cross employer',{cookie:owner.cookie,prefix:'/org/'+foreign.id,status:401});
 await refused('missing person',{data:{reason},status:400});
 await refused('blank person',{data:{personId:'   ',reason},status:400});
 await refused('missing reason',{data:{personId:'employee'},status:400});
 await refused('blank reason',{data:{personId:'employee',reason:'   '},status:400});
 const freshAt=r.now;r.now+=660000;
 await refused('expired local email');
 const history=await operations(r,desk.cookie,'employee');assert.deepEqual(history,[],'hardware administrators can read authorized history without fresh email');
 r.now=freshAt;
 for(const cookie of [undefined,emailOnly,missing.cookie])assert.ok([401,403].includes((await r.call('/api/auth/session-control?personId=employee',{cookie})).status),'history independently authorizes its reader');
 assert.equal((await r.call('/api/auth/session-control?personId=outside',{cookie:desk.cookie})).status,403,'history requires current write scope');
 assert.equal((await r.call('/api/auth/session-control?personId=peer',{cookie:desk.cookie})).status,403,'history retains the account rank fence');
 const actorSession=await r.db.prepare("SELECT id,amr,local_email_verified_at FROM auth_sessions WHERE person_id='desk' AND revoked_at IS NULL AND amr LIKE '%hwk%'").first();
 for(const [field,value,label] of [['amr','["email"]','hardware proof lost'],['local_email_verified_at',0,'local email proof lost']]) {
  const before=await credentialsState(r,'employee'),identity=await identityState(r,'employee');
  const response=await r.call('/api/auth/roles/end-sessions',{method:'POST',cookie:desk.cookie,data:{personId:'employee',reason},beforeBatchSql:{sql:`UPDATE auth_sessions SET ${field}=? WHERE id=?`,args:[value,actorSession.id]}});
  assert.equal(response.status,409,label+' '+await response.clone().text());
  assert.deepEqual(await credentialsState(r,'employee'),before,label+' before commit cannot revoke credentials or enqueue logout');
  assert.deepEqual(await identityState(r,'employee'),identity);
  assert.deepEqual(await operations(r,owner.cookie,'employee'),[]);
  assert.equal((await r.call('/api/auth/me',{cookie:employee.cookie})).status,200);
  await r.db.prepare(`UPDATE auth_sessions SET ${field}=? WHERE id=?`).bind(actorSession[field],actorSession.id).run();
 }
 // The request has already built its role state when the worker changes the
 // grant immediately before the first committing batch.
 const before=await credentialsState(r,'employee'),beforeIdentity=await identityState(r,'employee');
 const lost=await r.call('/api/auth/roles/end-sessions',{method:'POST',cookie:desk.cookie,data:{personId:'employee',reason},beforeBatchSql:{sql:'UPDATE auth_role_grants SET revoked_at=? WHERE id=?',args:[r.now,deskGrant.id]}});
 assert.equal(lost.status,409,await lost.clone().text());
 assert.deepEqual(await credentialsState(r,'employee'),before,'commit-time authority loss cannot revoke or enqueue anything');
 assert.deepEqual(await identityState(r,'employee'),beforeIdentity);
 assert.deepEqual(await operations(r,owner.cookie,'employee'),[]);
 assert.equal((await r.call('/api/auth/me',{cookie:employee.cookie})).status,200);
 assert.equal((await r.call('/api/auth/session-control?personId=employee',{cookie:desk.cookie})).status,403,'a revoked administrator grant stops history reads immediately');
}
