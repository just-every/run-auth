import {test} from 'node:test';
import assert from 'node:assert/strict';
import {samlInstall,addApp,browse} from './saml-helpers.mjs';
import {lifecyclePeer} from './lifecycle-peer.mjs';
import {register} from './webauthn.mjs';
import {emailSession} from './runtime.mjs';
import {signInAgain,passkeyPerson} from './agents-helpers.mjs';

const address=n=>['synthetic-auth-'+n,'example.com'].join('@');
const remote=(peer,id)=>[...peer.users.values()].find(user=>user.externalId===id);

test('approved native leaver plans survive interruption and uncertain peers, retain episode history and deny stale authority without claiming full offboarding',async t=>{
 const r=await samlInstall(t);r.tick=()=>{};const ada=await register(r,r.ada);r.ada=ada.cookie;
 const command=async(path,data,status=200,extra={})=>{const response=await r.call('/api/auth/'+path,{method:'POST',data,cookie:r.owner.cookie,...extra});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const history=async(cookie=r.owner.cookie,query='personId=ada')=>{const response=await r.call('/api/auth/lifecycle/plans?'+query,{cookie});assert.equal(response.status,200,await response.clone().text());return (await response.json()).plans;};
 const peers=await Promise.all([lifecyclePeer(t,'synthetic-auth-401'),lifecyclePeer(t,'synthetic-auth-402')]);
 const hosts=['https://lifecycle-a.example.com','https://lifecycle-b.example.com'];r.edges=Object.fromEntries(hosts.map((host,i)=>[host,peers[i].url]));
 const apps=[];
 for(let i=0;i<peers.length;i++){
  apps.push(await addApp(r,{name:'Lifecycle peer '+(i+1),entityId:hosts[i]+'/saml',acsUrl:hosts[i]+'/acs'}));
  await command('provisioning/connect',{appId:apps[i].id,baseUrl:hosts[i]+'/scim/v2',token:peers[i].token,pushGroups:i===0},201);
  assert.equal(remote(peers[i],'ada').active,true);
 }
 const group=await command('groups/create',{name:'Native lifecycle group'},201);await command('groups/add',{groupId:group.id,personId:'ada'});await command('company-apps/assign',{appId:apps[0].id,principalType:'group',principalId:group.id});
 assert.ok([...peers[0].groups.values()].some(remoteGroup=>remoteGroup.members.some(member=>member.value===remote(peers[0],'ada').id)));
 const unsupported=await addApp(r,{name:'Manual resolution required',entityId:'https://lifecycle-manual.example.com/saml',acsUrl:'https://lifecycle-manual.example.com/acs'});
 const client=await command('oidc-apps/create',{name:'Native lifecycle session',authMethod:'client_secret_basic',redirectUris:['https://lifecycle-a.example.com/callback'],backchannelLogoutUri:'https://lifecycle-a.example.com/logout'},201);
 await command('company-apps/assign',{appId:client.id,principalType:'person',principalId:'ada'});
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const authorized=await browse(r,'/oidc/authorize?'+new URLSearchParams({client_id:client.clientId,redirect_uri:hosts[0]+'/callback',response_type:'code',scope:'openid email',state:'synthetic-auth-403'}),{cookie:r.ada});
 const code=new URL(authorized.headers.get('location')).searchParams.get('code');assert.ok(code);
 const tokenResponse=await r.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',code,redirect_uri:hosts[0]+'/callback'},headers:{authorization:'Basic '+Buffer.from(client.clientId+':'+client.clientSecret).toString('base64')}});assert.equal(tokenResponse.status,200);
 const tokens=await tokenResponse.json(),userinfo=()=>r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}});assert.equal((await userinfo()).status,200);
 const edits=[{personId:'ada',state:'terminated'}],preview=(await command('directory/preview',{edits})).plan;
 assert.ok(preview.entries[0].lifecycle.steps.some(step=>step.appId===unsupported.id&&step.kind==='unsupported'));
 assert.equal(preview.entries[0].lifecycle.custodianId,'owner');assert.equal(await r.db.prepare('SELECT 1 FROM auth_lifecycle_plans').first(),null);
 // Wrong digest, weak proof and commit-time authority withdrawal change nothing.
 await command('directory/apply',{edits,digest:'synthetic-auth-stale'},409);
 await command('directory/apply',{edits,digest:preview.digest},403,{cookie:await emailSession(r,(await r.db.prepare("SELECT email FROM oa_operators WHERE id='owner'").first()).email)});
 const ownerSessions=(await r.db.prepare("SELECT id,amr FROM auth_sessions WHERE person_id='owner'").all()).results;
 await command('directory/apply',{edits,digest:preview.digest},403,{factorRace:`UPDATE auth_sessions SET amr='["email"]' WHERE person_id='owner'`});
 for(const session of ownerSessions)await r.db.prepare("UPDATE auth_sessions SET amr=? WHERE id=?").bind(session.amr,session.id).run();
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,200);assert.equal(await r.db.prepare('SELECT 1 FROM auth_lifecycle_plans').first(),null);
 // Inventory drift after review refuses without terminating the employee.
 await command('company-apps/assign',{appId:unsupported.id,principalType:'person',principalId:'bob'});
 await command('directory/apply',{edits,digest:preview.digest},409);
 const approved=(await command('directory/preview',{edits})).plan;
 await assert.rejects(command('directory/apply',{edits,digest:approved.digest},200,{lifecycleFault:true}),/synthetic_lifecycle_commit_interrupted/);
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);assert.equal((await userinfo()).status,401);
 let plans=await history(),first=plans[0];assert.equal(plans.length,1);assert.equal(first.digest,approved.digest);assert.equal(first.custodian,'owner');assert.equal(first.fullyOffboarded,false);
 assert.deepEqual(first.steps.filter(step=>step.kind==='scim').map(step=>step.state),['unstarted','unstarted']);
 assert.equal(first.preview.state.to,'terminated');assert.ok(first.steps.filter(step=>step.kind==='scim').every(step=>step.deadlineAt===first.createdAt+300000&&step.escalateAt===first.createdAt+900000));
 const captured=await r.db.prepare('SELECT plan FROM auth_lifecycle_plans WHERE id=?').bind(first.id).first();assert.deepEqual(JSON.parse(captured.plan),approved.entries[0]);for(const peer of peers){assert.ok(!captured.plan.includes(peer.token));assert.ok(!JSON.stringify(first).includes(peer.token));}
 await r.restart();
 peers[0].lose(503,'PATCH');peers[1].fail(1,503);
 await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 assert.equal(remote(peers[0],'ada').active,false);assert.equal(remote(peers[1],'ada').active,true);
 first=(await history())[0];assert.ok(first.steps.filter(step=>step.kind==='scim').every(step=>step.state==='failed'));assert.equal(first.state,'unresolved');
 assert.equal(peers[0].writes().filter(write=>write.method==='PATCH'&&write.body?.Operations?.[0]?.value?.active===false).length,1);
 const originalWork=first.steps.filter(step=>step.kind==='scim').map(step=>step.workId).sort();
 // Daily drift detection must resume approved work, preserving its backoff and
 // connection fence even when the provider can list but cannot apply a write.
 await r.db.prepare('UPDATE auth_scim_connectors SET last_reconciled_at=? WHERE app_id=?').bind(r.now-86400001,apps[1].id).run();
 peers[1].faults.push({method:'PATCH',status:503});
 assert.equal((await r.call('/',{action:'maintain'})).status,200);
 for(const id of originalWork)assert.equal((await r.db.prepare('SELECT state FROM auth_provisioning WHERE id=?').bind(id).first()).state,'pending','daily reconciliation retains the original approved work');
 peers[1].faults.length=0;
 await r.restart();r.now+=60001;
 await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 first=(await history())[0];assert.ok(first.steps.some(step=>step.kind==='scim_group'&&step.state==='verified'));assert.ok([...peers[0].groups.values()].every(remoteGroup=>!remoteGroup.members.some(member=>member.value===remote(peers[0],'ada').id)));const verified=first.steps.filter(step=>step.kind==='scim');assert.ok(verified.every(step=>step.state==='verified'&&step.verifiedAt>=step.dispatchedAt));assert.deepEqual(verified.map(step=>step.workId).sort(),originalWork);
 assert.equal(peers[0].writes().filter(write=>write.method==='PATCH'&&write.body?.Operations?.[0]?.value?.active===false).length,1,'readback recovers the lost response without repeating a write');
 assert.ok(first.steps.some(step=>step.app==='Manual resolution required'&&step.state==='unknown'));assert.equal(first.fullyOffboarded,false);assert.equal((await userinfo()).status,401);
 // Later ordinary group changes still serve other people after the approved
 // membership removal is verified.
 await r.person('synthetic-auth-419',address(419));
 await command('groups/add',{groupId:group.id,personId:'synthetic-auth-419'});
 assert.ok([...peers[0].groups.values()].some(remoteGroup=>remoteGroup.members.some(member=>member.value===remote(peers[0],'synthetic-auth-419').id)));
 // An approved queue cannot borrow a rotated connector or lose missing work silently.
 await command('company-apps/assign',{appId:apps[1].id,principalType:'person',principalId:'bob'});assert.equal(remote(peers[1],'bob').active,true);
 const bobEdits=[{personId:'bob',state:'terminated'}],bobPreview=(await command('directory/preview',{edits:bobEdits})).plan;
 await assert.rejects(command('directory/apply',{edits:bobEdits,digest:bobPreview.digest},200,{lifecycleFault:true}),/synthetic_lifecycle_commit_interrupted/);
 const callsBeforeRotation=peers[1].log.length;
 await command('provisioning/rotate',{appId:apps[1].id,token:peers[1].token});await r.call('/',{action:'maintain'});
 const blocked=(await history(r.owner.cookie,'personId=bob'))[0];assert.ok(blocked.steps.some(step=>step.outcome==='approved_connector_changed'));assert.equal(remote(peers[1],'bob').active,true);assert.equal(peers[1].log.length,callsBeforeRotation,'changed connection performs no unreviewed request');
 await r.db.prepare('UPDATE auth_scim_connectors SET last_reconciled_at=? WHERE app_id=?').bind(r.now-86400001,apps[1].id).run();
 await r.restart();assert.equal((await r.call('/',{action:'maintain'})).status,200);
 assert.equal(remote(peers[1],'bob').active,true,'daily reconciliation cannot bypass a changed approved connector');
 const afterReconcile=(await history(r.owner.cookie,'personId=bob'))[0];
 assert.equal(afterReconcile.steps.find(step=>step.kind==='scim').workId,blocked.steps.find(step=>step.kind==='scim').workId);
 assert.ok(afterReconcile.steps.some(step=>step.outcome==='approved_connector_changed'));
 const lost=blocked.steps.find(step=>step.kind==='scim');await r.db.prepare('DELETE FROM auth_provisioning WHERE id=?').bind(lost.workId).run();
 assert.ok((await history(r.owner.cookie,'personId=bob'))[0].steps.some(step=>step.outcome==='work_missing'&&step.state==='unknown'));
 // Scoped readers see their person, with hidden apps explicitly unresolved.
 await r.person('reader',address(404));const reader=await register(r,await emailSession(r,address(404)));
 const role=(await command('roles/preview',{kind:'role',role:{name:'Lifecycle reader',rank:10,permissions:['people.view','apps.view']}}));await command('roles/apply',{previewId:role.previewId});
 const granted=await command('roles/preview',{kind:'grant',personId:'reader',roleId:role.plan.role.id,resources:{view:{people:['ada'],apps:[apps[0].id]},edit:{}}});await command('roles/apply',{previewId:granted.previewId});
 const limited=(await history(reader.cookie))[0];assert.ok(limited.hiddenSteps>0);assert.ok(!JSON.stringify(limited).includes('Lifecycle peer 2'));assert.equal(limited.state,'unresolved');
 assert.equal((await r.call('/api/auth/lifecycle/plans?personId=bob',{cookie:reader.cookie})).status,403);
 const grant=await r.db.prepare("SELECT id FROM auth_role_grants WHERE person_id='reader'").first();const revoke=await command('roles/preview',{kind:'revoke',grantId:grant.id});await command('roles/apply',{previewId:revoke.previewId});
 assert.equal((await r.call('/api/auth/lifecycle/plans?personId=ada',{cookie:reader.cookie})).status,403);
 const org=await command('organizations/create',{name:'Independent lifecycle employer'},201);assert.equal((await r.call('/org/'+org.id+'/api/auth/lifecycle/plans?personId=ada',{cookie:r.owner.cookie})).status,401);
 assert.equal((await r.call('/api/auth/lifecycle/plans')).status,401);
 // Existing employers carry pending logout deliveries across the upgrade.
 const employer={origin:r.origin,get now(){return r.now;},tick:()=>{},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+org.id+path,options)};
 const employerOwner=await register(employer,await emailSession(employer,(await r.db.prepare("SELECT email FROM oa_operators WHERE id='owner'").first()).email));
 const employerCommand=async(path,data,status=200)=>{const response=await employer.call('/api/auth/'+path,{method:'POST',data,cookie:employerOwner.cookie});assert.equal(response.status,status,await response.clone().text());return response.json();};
 const employerPerson=(await (await employer.call('/api/auth/me',{cookie:employerOwner.cookie})).json()).user.id;
 const employerApp=await employerCommand('oidc-apps/create',{name:'Employer logout recovery',authMethod:'client_secret_basic',redirectUris:[hosts[0]+'/callback'],backchannelLogoutUri:hosts[0]+'/logout'},201);
 await employerCommand('company-apps/assign',{appId:employerApp.id,principalType:'person',principalId:employerPerson});
 await employer.call('/.well-known/openid-configuration');
 const ns=(await r.db.prepare('SELECT namespace FROM auth_organizations WHERE id=?').bind(org.id).first()).namespace;
 await r.db.prepare('UPDATE '+ns+'auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const employerCode=await browse(employer,'/oidc/authorize?'+new URLSearchParams({client_id:employerApp.clientId,redirect_uri:hosts[0]+'/callback',response_type:'code',scope:'openid',state:'synthetic-auth-430'}),{cookie:employerOwner.cookie});
 const employerGrant=await employer.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',code:new URL(employerCode.headers.get('location')).searchParams.get('code'),redirect_uri:hosts[0]+'/callback'},headers:{authorization:'Basic '+Buffer.from(employerApp.clientId+':'+employerApp.clientSecret).toString('base64')}});
 assert.equal(employerGrant.status,200,await employerGrant.clone().text());
 peers[0].logoutStatus(503);
 const ended=await employer.call('/oidc/logout',{method:'POST',form:{confirm:'yes'},cookie:employerOwner.cookie});assert.equal(ended.status,200,await ended.clone().text());
 const genericPending=await r.db.prepare('SELECT * FROM '+ns+'auth_oidc_logouts WHERE finished_at IS NULL').first();assert.ok(genericPending);assert.equal(genericPending.outcome,'retry_503');
 // A persisted linked-app queue from the older edition shares the upgrade.
 await r.db.prepare('INSERT INTO '+ns+"auth_clients(id,name,origin,sector_id,redirect_uris,jwks,source,created_at,logout_uri) VALUES(?,?,?,?,?,?,?, ?,?)").bind('synthetic-auth-431','Existing employer app',hosts[0],'synthetic-auth-432','[]','{}','token',r.now,peers[0].url+'/logout').run();
 await r.db.prepare('INSERT INTO '+ns+"auth_logout_deliveries(id,client_id,person_id,event,jti,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?)").bind('synthetic-auth-433','synthetic-auth-431',employerPerson,'http://schemas.openid.net/event/backchannel-logout','synthetic-auth-434',r.now,r.now).run();
 // Restore the pre-upgrade columns while preserving the real pending rows.
 for(const table of ['auth_logout_deliveries','auth_oidc_logouts'])for(const column of ['claimed_until','dispatched_at'])await r.db.prepare('ALTER TABLE '+ns+table+' DROP COLUMN '+column).run();
 await r.restart();r.now+=60001;peers[0].logoutStatus(200);
 const maintenance=await r.call('/',{action:'maintain'});assert.equal(maintenance.status,200,await maintenance.clone().text());
 for(const [table,id,jti] of [['auth_logout_deliveries','synthetic-auth-433','synthetic-auth-434'],['auth_oidc_logouts',genericPending.id,genericPending.jti]]) {
  const delivered=await r.db.prepare('SELECT * FROM '+ns+table+' WHERE id=?').bind(id).first();
  assert.equal(delivered.outcome,'delivered');assert.equal(delivered.jti,jti);assert.ok(delivered.finished_at);assert.ok(delivered.dispatched_at);assert.equal(delivered.claimed_until,null);
 }
 const logoutCount=peers[0].logout.length;
 assert.equal((await r.call('/',{action:'maintain'})).status,200);assert.equal(peers[0].logout.length,logoutCount,'opening upgraded employers never replays finished logout');

 // Rehire and terminate preserve identity but never reuse old plan evidence or sessions.
 await command('directory/edit',{personId:'ada',state:'active'});assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);
 const back=(await signInAgain(r,ada,(await r.db.prepare("SELECT email FROM oa_operators WHERE id='ada'").first()).email)).cookie;assert.equal((await r.call('/api/auth/me',{cookie:back})).status,200);
 await command('directory/edit',{personId:'ada',state:'terminated'});plans=await history();assert.equal(plans.length,2);assert.notEqual(plans[0].id,plans[1].id);assert.ok(plans.every(plan=>plan.personId==='ada'));assert.equal((await r.call('/api/auth/me',{cookie:back})).status,401);assert.equal((await userinfo()).status,401);
 // A removed queue cannot make unresolved work completed; erasure removes the private capture.
 const pending=plans[0].steps.find(step=>step.kind==='oidc_logout');if(pending)await r.db.prepare('DELETE FROM auth_oidc_logouts WHERE id=?').bind(pending.workId).run();
 assert.equal((await history())[0].fullyOffboarded,false);
 await command('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const erase=await command('erasure/preview',{kind:'person',target:'ada'});await command('erasure/confirm',{previewId:erase.id,confirmation:'ERASE',destinations:[]});
 assert.equal(await r.db.prepare("SELECT 1 FROM auth_lifecycle_plans WHERE person_id='ada'").first(),null);assert.equal(await r.db.prepare("SELECT 1 FROM auth_lifecycle_steps WHERE person_id='ada'").first(),null);
 await r.restart();assert.equal((await r.call('/api/auth/me',{cookie:back})).status,401);assert.ok((await history(r.owner.cookie,'')).every(plan=>plan.personId!=='ada'));
 assert.equal(await r.db.prepare("SELECT 1 FROM auth_lifecycle_person_epoch WHERE person_id='ada'").first(),null);
 // Erasing an approver removes their provenance, not another person's plan.
 const approver=await passkeyPerson(r,'synthetic-auth-420',address(420),'admin');
 await r.person('synthetic-auth-421',address(421));
 await command('directory/edit',{personId:'synthetic-auth-421',state:'terminated'},200,{cookie:approver.cookie});
 const retained=(await history(r.owner.cookie,'personId=synthetic-auth-421'))[0];
 const retainedSteps=retained.steps;
 const eraseApprover=await command('erasure/preview',{kind:'person',target:'synthetic-auth-420'});
 await command('erasure/confirm',{previewId:eraseApprover.id,confirmation:'ERASE',destinations:[]});
 const afterErasure=await history(r.owner.cookie,'personId=synthetic-auth-421');
 assert.equal(afterErasure.length,1,'erasing an approver preserves the other person’s retained plan');
 assert.equal(afterErasure[0].id,retained.id);assert.deepEqual(afterErasure[0].steps,retainedSteps);
 assert.equal(afterErasure[0].actor,'Restricted administrator');assert.equal(afterErasure[0].custodian,'Restricted administrator');
 const retainedCapture=await r.db.prepare('SELECT * FROM auth_lifecycle_plans WHERE id=?').bind(retained.id).first();
 assert.ok(!JSON.stringify(retainedCapture).includes('synthetic-auth-420'),'erased approver references leave the retained capture');
 assert.ok(await r.db.prepare("SELECT 1 FROM oa_operators WHERE id='synthetic-auth-421'").first());
 await r.restart();assert.equal((await history(r.owner.cookie,'personId=synthetic-auth-421'))[0].id,retained.id);
 const eraseRetained=await command('erasure/preview',{kind:'person',target:'synthetic-auth-421'});
 await command('erasure/confirm',{previewId:eraseRetained.id,confirmation:'ERASE',destinations:[]});
 assert.equal(await r.db.prepare('SELECT 1 FROM auth_lifecycle_plans WHERE id=?').bind(retained.id).first(),null);
 assert.equal(await r.db.prepare('SELECT 1 FROM auth_lifecycle_steps WHERE plan_id=?').bind(retained.id).first(),null);
 // Bulk approval keeps each person's exact inventory while earlier rows commit.
 await command('directory/edit',{personId:'bob',state:'active'});
 const bulkEdits=[{personId:'bob',state:'terminated'},{personId:'reader',state:'terminated'}],bulk=(await command('directory/preview',{edits:bulkEdits})).plan;
 const committed=await command('directory/apply',{edits:bulkEdits,digest:bulk.digest});assert.equal(committed.results.filter(row=>row.changed).length,2);
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM oa_operators WHERE id IN ('bob','reader') AND status='inactive'").first()).n,2);
});
