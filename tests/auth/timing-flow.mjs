import assert from 'node:assert/strict';
import {ownerInstall,passkeyPerson,post,signInAgain} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';
import {scimServer} from './scim-server.mjs';
const address=id=>id+'@'+'example.com';
const json=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
const iso=at=>new Date(at).toISOString();

export async function timingFlow(t) {
 const {r,owner:initialOwner}=await ownerInstall(t),start=r.now-1000,edge=await scimServer(t,'synthetic-auth-201');r.scimServer=edge.url;
 let owner=initialOwner;
 const write=async(path,data,status=200,extra={})=>json(await r.call('/api/auth/'+path,{...post(data,owner.cookie),...extra}),status);
 const read=async(suffix='',cookie=owner.cookie)=>json(await r.call('/api/auth/reports/joiner-leaver-timeliness'+suffix,{cookie}));
 // Use a fixed clock, with an end strictly after every event and no future as-of.
 const report=async(extra='')=>{r.now++;return read('?'+new URLSearchParams({start:iso(start),end:iso(r.now),asOf:iso(r.now)})+extra);};
 const app=await write('company-apps/create',{name:'Measured payroll',entityId:'https://timing.example.com',acsUrl:'https://timing.example.com/acs'},201);
 await write('provisioning/connect',{appId:app.id,baseUrl:'https://scim.example.com/scim/v2',token:edge.token,pushGroups:false},201);
 const workers=new Map();
 for(const id of ['synthetic-auth-202','synthetic-auth-203','synthetic-auth-204','synthetic-auth-208','synthetic-auth-209']){
  workers.set(id,await passkeyPerson(r,id,address(id),'member'));
  await write('company-apps/assign',{appId:app.id,principalType:'person',principalId:id});
 }
 const terminate=id=>write('directory/edit',{personId:id,source:'hr',state:'terminated'});
 const [complete,interrupted,held,late,overdue]=workers.keys();
 r.now+=1000;const completeAt=r.now;await terminate(complete);
 let measured=await report(),row=measured.rows.find(row=>row.personId===complete);
 assert.equal(row.localDenialAt,iso(completeAt));assert.equal(row.leaverEventAt,iso(completeAt));
 assert.equal(row.apps[0].dispatchedAt,iso(completeAt));assert.equal(row.apps[0].remoteVerifiedAt,iso(completeAt));
 assert.equal(row.observedDeprovisionAt,iso(completeAt));assert.equal(row.fullDeprovisionAt,'unknown');
 assert.equal(measured.summary.nativeWithinOneHour,1);assert.equal(measured.summary.nativeWithin24Hours,1);
 assert.equal(measured.summary.fullyDeprovisionedWithinOneHour,'unknown');
 assert.equal((await r.call('/api/auth/me',{cookie:workers.get(complete).cookie})).status,401);
 assert.equal((await r.call('/api/auth/launcher',{cookie:workers.get(complete).cookie})).status,401);
 const audit=(await r.db.prepare("SELECT d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='directory_person_updated' OR a.event='person_terminated'").all()).results;
 assert.ok(audit.some(row=>JSON.parse(row.detail).state?.kind==='terminate'));
 // Interrupt after the real guarded inactive-state transaction, before effects.
 r.now+=1000;const interruptedAt=r.now;
 const failed=await r.call('/api/auth/directory/edit',{...post({personId:interrupted,source:'hr',state:'terminated'},owner.cookie),roleNoticeFault:'after_termination'});
 assert.equal(failed.status,500);
 assert.equal((await r.call('/api/auth/me',{cookie:workers.get(interrupted).cookie})).status,401);
 measured=await report();row=measured.rows.find(row=>row.personId===interrupted);
 assert.equal(row.localDenialAt,iso(interruptedAt));assert.equal(row.remoteVerifiedAt,'unknown');
 const interruptedEpisode=row.episodeId,snapshotAt=r.now;
 await r.restart();r.now+=2000;
 await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 measured=await report();row=measured.rows.find(row=>row.episodeId===interruptedEpisode);
 assert.notEqual(row.remoteVerifiedAt,'unknown');assert.ok(Date.parse(row.remoteVerifiedAt)>interruptedAt);
 const historical=await read('?'+new URLSearchParams({start:iso(start),end:iso(snapshotAt),asOf:iso(snapshotAt)}));
 assert.equal(historical.rows.find(row=>row.episodeId===interruptedEpisode).remoteVerifiedAt,'unknown','later observations cannot enter an earlier snapshot');
 assert.equal(historical.summary.nativeWithinOneHour,1);
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_timing_episodes WHERE person_id=?').bind(interrupted).first()).n,1);
 await terminate(interrupted);
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_timing_episodes WHERE person_id=?').bind(interrupted).first()).n,1,'repeating the termination does not create an episode');
 // Fail at the network edge. Profile edits and connector removal cannot erase
 // the original app inventory or invent a remote readback.
 const unsupported=await write('company-apps/create',{name:'Unobserved expense app',entityId:'https://unobserved.example.com',acsUrl:'https://unobserved.example.com/acs'},201);
 await write('company-apps/assign',{appId:unsupported.id,principalType:'person',principalId:held});
 edge.fail(30,503);r.now+=1000;await terminate(held);
 measured=await report();const firstHeld=measured.rows.find(row=>row.personId===held);
 assert.deepEqual(firstHeld.unresolvedApps.sort(),['Measured payroll','Unobserved expense app']);
 assert.notEqual(firstHeld.apps.find(row=>row.appId===app.id).dispatchedAt,'unknown');
 // No managed remote account is not a verified absence. The existing
 // queue may finish its no-op, while the native report keeps coverage unknown.
 const unobserved='synthetic-auth-207';await r.person(unobserved,address(unobserved));
 await write('company-apps/assign',{appId:app.id,principalType:'person',principalId:unobserved});
 await terminate(unobserved);
 const noAccount=(await report()).rows.find(row=>row.personId===unobserved);
 assert.equal(noAccount.remoteVerifiedAt,'unknown');assert.equal(noAccount.observedDeprovisionAt,'unknown');assert.deepEqual(noAccount.unresolvedApps,['Measured payroll']);
 const noOp=await r.db.prepare("SELECT state,operation FROM auth_provisioning WHERE subject_id=? AND state!='superseded' ORDER BY event_at DESC LIMIT 1").bind(unobserved).first();assert.equal(noOp.state,'verified');assert.equal(noOp.operation,'none');
 await write('directory/edit',{personId:held,source:'hr',set:{name:'Revised former worker'}});
 await r.restart();await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 assert.equal((await report()).rows.find(row=>row.episodeId===firstHeld.episodeId).remoteVerifiedAt,'unknown');
 await write('directory/edit',{personId:held,source:'hr',state:'active'});
 edge.faults.length=0;await write('provisioning/sync',{appId:app.id});
 r.now+=1000;edge.beforeRequest=({method,path})=>{if(method==='GET'&&path.includes('/Users/')){const user=[...edge.users.values()].find(user=>user.externalId===held);if(user)user.active=true;}};await terminate(held);
 measured=await report();assert.equal(measured.rows.find(row=>row.personId===held&&row.episodeId!==firstHeld.episodeId).remoteVerifiedAt,'unknown','a successful PATCH is not readback proof');
 edge.beforeRequest=null;await write('provisioning/sync',{appId:app.id});
 measured=await report();const episodes=measured.rows.filter(row=>row.personId===held);
 assert.equal(episodes.length,2);assert.equal(episodes.find(row=>row.episodeId===firstHeld.episodeId).apps.find(row=>row.appId===app.id).remoteVerifiedAt,'unknown','a later leaver episode cannot close the first outage');
 assert.notEqual(episodes.find(row=>row.episodeId!==firstHeld.episodeId).apps.find(row=>row.appId===app.id).remoteVerifiedAt,'unknown');
 // Exercise both completion buckets using real delayed network readback.
 for(const [id,elapsed] of [[late,2*3600000],[overdue,25*3600000]]){
  edge.fail(1,503);r.now+=1000;await terminate(id);const at=r.now;
  r.now+=elapsed;owner=await signInAgain(r,owner,address('owner'));
  await r.call('/',{action:'maintain'});
  const delayed=(await report()).rows.find(row=>row.personId===id);
  assert.equal(Date.parse(delayed.observedDeprovisionAt)-at,elapsed);
 }
 await write('provisioning/disconnect',{appId:app.id});
 await write('company-apps/remove',{id:app.id});
 measured=await report();assert.deepEqual(measured.rows.find(row=>row.episodeId===firstHeld.episodeId).unresolvedApps.sort(),['Measured payroll','Unobserved expense app']);
 assert.equal(measured.summary.nativeObservedComplete,4);assert.equal(measured.summary.nativeWithinOneHour,2);assert.equal(measured.summary.nativeWithin24Hours,3);assert.equal(measured.summary.unknownEpisodes,3);
 // A pre-migration termination has no invented episode or denial timestamp.
 const legacy='synthetic-auth-205';await r.person(legacy,address(legacy));
 await r.db.prepare("UPDATE oa_operators SET status='inactive' WHERE id=?").bind(legacy).run();
 await r.db.prepare('INSERT INTO auth_people(person_id,terminated_at) VALUES(?,?)').bind(legacy,start+1).run();
 measured=await report();const legacyRow=measured.rows.find(row=>row.personId===legacy);
 assert.equal(legacyRow.localDenialAt,'unknown');assert.equal(legacyRow.episodeId,'unknown');assert.equal(measured.summary.unknownEpisodes,4);
 assert.equal(measured.directoryCount,7);assert.equal(measured.rowCount,8);
 const outside=await read('?'+new URLSearchParams({start:iso(start-5000),end:iso(start),asOf:iso(r.now)}));assert.equal(outside.rowCount,0);assert.equal(outside.summary.nativeShareWithinOneHour,'unknown');
 for(const query of ['start=bad','start='+iso(start)+'&end='+iso(start),'asOf='+iso(r.now+1000),'start='+iso(start-400*86400000),'end='+iso(r.now)+'&end='+iso(r.now)])assert.equal((await r.call('/api/auth/reports/joiner-leaver-timeliness?'+query,{cookie:owner.cookie})).status,400);
 const trail=await json(await r.call('/api/auth/audit?limit=100',{cookie:owner.cookie}));
 const details=trail.events.filter(event=>event.event==='lifecycle_timing_observed').map(event=>JSON.parse(event.detail));
 const completeRow=measured.rows.find(row=>row.personId===complete);
 const receipt=details.find(detail=>detail.episodeId===completeRow.episodeId&&detail.remoteVerifiedAt!==null);
 assert.ok(receipt);assert.equal(iso(receipt.eventAt),completeRow.leaverEventAt);assert.equal(iso(receipt.localDenialAt),completeRow.localDenialAt);
 assert.equal(iso(receipt.dispatchedAt),completeRow.apps[0].dispatchedAt);assert.equal(iso(receipt.remoteVerifiedAt),completeRow.apps[0].remoteVerifiedAt);
 const committed=trail.events.find(event=>event.event==='lifecycle_timing_committed'&&JSON.parse(event.detail).episodeId===interruptedEpisode);assert.ok(committed);
 const csv=await r.call('/api/auth/reports/joiner-leaver-timeliness?format=csv',{cookie:owner.cookie});assert.equal(csv.status,200);const text=await csv.text();assert.ok(text.includes('nativeWithinOneHour'));assert.ok(text.includes(firstHeld.episodeId));assert.equal(Number(csv.headers.get('x-auth-report-count')),8);
 const reader=await passkeyPerson(r,'synthetic-auth-206',address('synthetic-auth-206'),'member');
 const change=async data=>{const preview=await write('roles/preview',data);return write('roles/apply',{previewId:preview.previewId});};
 const role=await change({kind:'role',role:{name:'Timing reader',rank:4,permissions:['audit.view']}});
 const grant=await change({kind:'grant',personId:'synthetic-auth-206',roleId:role.plan.role.id,resources:{view:{people:[complete],apps:[],groups:[],cases:[]},edit:{}}});
 const scoped=await read('',reader.cookie);assert.equal(scoped.rowCount,1);assert.deepEqual(scoped.rows[0].apps,[]);assert.equal(scoped.rows[0].unresolvedOutsideScope,'unknown');assert.equal(scoped.summary.nativeObservedComplete,0);assert.ok(!JSON.stringify(scoped).includes(app.id));assert.ok(!JSON.stringify(scoped).includes('Measured payroll'));
 assert.equal((await r.call('/api/auth/reports/joiner-leaver-timeliness?format=csv',{cookie:reader.cookie})).status,403);
 assert.equal((await r.call('/api/auth/reports/joiner-leaver-timeliness',{cookie:await emailSession(r,address('synthetic-auth-206'))})).status,403);
 await change({kind:'revoke',grantId:grant.plan.id});assert.equal((await r.call('/api/auth/reports/joiner-leaver-timeliness',{cookie:reader.cookie})).status,403);
 assert.equal((await r.call('/api/auth/reports/joiner-leaver-timeliness')).status,401);
 const revokedRead=await r.call('/api/auth/reports/joiner-leaver-timeliness',{cookie:owner.cookie,factorRace:`UPDATE auth_sessions SET revoked_at=${r.now} WHERE person_id='owner'`});
 assert.equal(revokedRead.status,409,'authority loss during capture refuses the read');owner=await signInAgain(r,owner,address('owner'));
 const beforeExport=(await r.db.prepare("SELECT count(*) AS n FROM auth_role_operations WHERE permission='reports.export'").first()).n;
 const expiredExport=await r.call('/api/auth/reports/joiner-leaver-timeliness?format=csv',{cookie:owner.cookie,factorRace:"UPDATE auth_sessions SET local_email_verified_at=0 WHERE person_id='owner'"});
 assert.equal(expiredExport.status,409,'fresh export authority is rechecked at commit');
 assert.equal((await r.db.prepare("SELECT count(*) AS n FROM auth_role_operations WHERE permission='reports.export'").first()).n,beforeExport);
 owner=await signInAgain(r,owner,address('owner'));
 const org=await write('organizations/create',{name:'Isolated timing employer'},201);
 const foreign={call:(path,options)=>r.call('/org/'+org.id+path,options),mails:()=>r.mails()};
 const foreignOwner=await register(foreign,await emailSession(foreign,address('owner')));
 assert.equal((await json(await foreign.call('/api/auth/reports/joiner-leaver-timeliness',{cookie:foreignOwner.cookie}))).rowCount,0);
 assert.equal((await foreign.call('/api/auth/reports/joiner-leaver-timeliness',{cookie:owner.cookie})).status,401);
 await write('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const appErasure=await write('erasure/preview',{kind:'app',target:unsupported.id});await write('erasure/confirm',{previewId:appErasure.id,confirmation:'ERASE',destinations:[]});
 const afterAppErasure=(await report()).rows.find(row=>row.personId===held&&row.episodeId!==firstHeld.episodeId);
 assert.equal(afterAppErasure.observedDeprovisionAt,'unknown','erasing an unobserved app cannot complete a smaller inventory');assert.equal(afterAppErasure.inventoryCoverage,'unknown after evidence erasure');
 const erased=await write('erasure/preview',{kind:'person',target:held});await write('erasure/confirm',{previewId:erased.id,confirmation:'ERASE',destinations:[]});
 await r.restart();await r.call('/',{action:'maintain'});
 assert.ok(!(await report()).rows.some(row=>row.personId===held));
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_timing_episodes WHERE person_id=?').bind(held).first()).n,0);
 assert.ok(!JSON.stringify(await report()).includes(edge.token));
}
