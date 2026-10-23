import assert from 'node:assert/strict';
import {ownerInstall, passkeyPerson, post} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {scimServer} from './scim-server.mjs';
const result = async(response, status=200) => { assert.equal(response.status,status,await response.clone().text()); return response.json(); };
const change = async(r, owner, data) => {
 const preview=await result(await r.call('/api/auth/roles/preview',post(data,owner.cookie)));
 return result(await r.call('/api/auth/roles/apply',post({previewId:preview.previewId},owner.cookie)));
};
const allResources={view:{people:['*'],groups:['*'],apps:['*'],cases:['*']},edit:{people:['*'],groups:['*'],apps:['*'],cases:['*']}};

export async function mfaReportFlow(t) {
 const {r,owner}=await ownerInstall(t), group=await result(await r.call('/api/auth/groups/create',post({name:'Reconciled workforce'},owner.cookie)),201);
 const command=async(path,data,status=200)=>result(await r.call('/api/auth/'+path,post(data,owner.cookie)),status);
 const ids=[];
 for(let i=0;i<20;i++) {
  const id='synthetic-auth-'+(110+i),email=id+'@example.com';ids.push(id);
  if(i<15)await passkeyPerson(r,id,email,'member');else await r.person(id,email);
  await command('groups/add',{groupId:group.id,personId:id});
  await command('directory/edit',{personId:id,source:'hr',set:{department:i===19?'Support':'Engineering'}});
 }
 const query='?group='+group.id, read=(suffix='',cookie=owner.cookie)=>r.call('/api/auth/reports/mfa-enrollment'+query+suffix,{cookie});
 const report=await result(await read());
 assert.equal(report.rowCount,20);assert.equal(report.directoryCount,20);
 assert.deepEqual(report.rows.map(row=>row.personId).sort(),ids.sort());
 assert.equal(report.rows.filter(row=>row.factorTypes.includes('passkey')).length,15);
 assert.equal(report.rows.filter(row=>row.mfaCompliant===false).length,5);
 assert.equal(report.rows.filter(row=>row.mfaCompliant==='unknown').length,15,'unknown employer policy never becomes a compliance claim');
 assert.ok(report.rows.every(row=>row.passwordOnly==='unknown'),'unbuilt password state is never inferred');
 const directory=await result(await r.call('/api/auth/directory?group='+group.id,{cookie:owner.cookie}));
 assert.deepEqual(report.rows.map(row=>row.personId).sort(),directory.people.map(row=>row.id).sort());
 const exportReply=await read('&format=csv');assert.equal(exportReply.status,200);assert.equal(exportReply.headers.get('x-auth-report-count'),'20');
 assert.equal((await exportReply.text()).trim().split('\r\n').length,21);
 assert.ok((await result(await read('&department=Support'))).rowCount===1);
 assert.equal((await read('',await emailSession(r,'synthetic-auth-110@example.com'))).status,403,'email session cannot read administrative factor facts');
 const reader=await passkeyPerson(r,'report-reader','synthetic-auth-130@example.com','member');
 const role=await change(r,owner,{kind:'role',role:{name:'Scoped report reader',rank:4,permissions:['audit.view']}});
 await change(r,owner,{kind:'grant',personId:'report-reader',roleId:role.plan.role.id,resources:{view:{people:['synthetic-auth-110'],groups:[]},edit:{}}});
 const scoped=await result(await r.call('/api/auth/reports/mfa-enrollment',{cookie:reader.cookie}));assert.equal(scoped.rowCount,1);assert.equal(scoped.rows[0].personId,'synthetic-auth-110');
 assert.equal((await read('',reader.cookie)).status,403,'a group filter also needs that group in view scope');
 assert.equal((await r.call('/api/auth/reports/mfa-enrollment?format=csv',{cookie:reader.cookie})).status,403,'view permission cannot export');
 const audit=await r.db.prepare("SELECT detail FROM auth_role_operations WHERE permission='reports.export'").all();
 assert.ok(audit.results.some(row=>JSON.parse(row.detail).rowCount===20));
 assert.equal((await r.call('/api/auth/reports/mfa-enrollment?department=Engineering&department=Support',{cookie:owner.cookie})).status,400);
}
export async function administratorsReportFlow(t) {
 const {r,owner}=await ownerInstall(t);await passkeyPerson(r,'custom-admin','synthetic-auth-131@example.com','member');
 const role=await change(r,owner,{kind:'role',role:{name:'Published custom auditor',rank:7,permissions:['audit.view']}});
 const grant=await change(r,owner,{kind:'grant',personId:'custom-admin',roleId:role.plan.role.id,resources:allResources});
 const read=async()=>result(await r.call('/api/auth/reports/administrators',{cookie:owner.cookie}));
 assert.equal((await read()).rows.find(row=>row.personId==='custom-admin').grants[0].role,'Published custom auditor');
 await change(r,owner,{kind:'revoke',grantId:grant.plan.id});
 assert.ok(!(await read()).rows.some(row=>row.personId==='custom-admin'));
}
export async function dormantReportFlow(t) {
 const {r,owner}=await ownerInstall(t),now=r.now;r.now-=91*86400000;
 await passkeyPerson(r,'dormant','synthetic-auth-132@example.com','member');r.now=now;
 await passkeyPerson(r,'recent','synthetic-auth-133@example.com','member');
 const report=await result(await r.call('/api/auth/reports/dormant-accounts',{cookie:owner.cookie}));
 assert.ok(report.rows.some(row=>row.personId==='dormant'&&row.lastSignInAt!=='unknown'));
 assert.ok(!report.rows.some(row=>row.personId==='recent'));
 assert.equal(report.directoryCount,report.rowCount);
 assert.equal((await r.call('/api/auth/reports/dormant-accounts?dormantDays=0',{cookie:owner.cookie})).status,400);
}
export async function terminatedReportFlow(t) {
 const {r,owner}=await ownerInstall(t),token='synthetic-auth-134',edge=await scimServer(t,token);r.scimServer=edge.url;
 const command=async(path,data,status=200)=>result(await r.call('/api/auth/'+path,post(data,owner.cookie)),status);
 for(const [id,email] of [['left','synthetic-auth-135@example.com'],['held','synthetic-auth-136@example.com']])await passkeyPerson(r,id,email,'member');
 const app=await command('company-apps/create',{name:'Unresolved payroll access',entityId:'https://payroll.example.com',acsUrl:'https://payroll.example.com/acs'},201);
 for(const id of ['left','held'])await command('company-apps/assign',{appId:app.id,principalType:'person',principalId:id});
 await command('provisioning/connect',{appId:app.id,baseUrl:'https://scim.example.com/scim/v2',token,pushGroups:false},201);
 await command('provisioning/sync',{appId:app.id});
 await command('directory/edit',{personId:'left',source:'hr',state:'terminated'});
 await command('provisioning/sync',{appId:app.id});
 edge.fail(20,503);
 await command('directory/edit',{personId:'held',source:'hr',state:'terminated'});
 await command('provisioning/sync',{appId:app.id});
 const report=await result(await r.call('/api/auth/reports/terminated-people',{cookie:owner.cookie}));
 assert.equal(report.rowCount,2);assert.equal(report.directoryCount,2);
 const held=report.rows.find(row=>row.personId==='held'),left=report.rows.find(row=>row.personId==='left');
 assert.deepEqual(held.unresolvedApps,['Unresolved payroll access']);assert.equal(held.fullDeprovisionAt,'unknown');
 assert.equal(held.localDenialAt,'unknown','unqualified timing is explicit, never fabricated from a queue');
 assert.deepEqual(left.unresolvedApps,[]);assert.notEqual(left.remoteVerifiedAt,'unknown');
 const health=await result(await r.call('/api/auth/reports/connector-health',{cookie:owner.cookie}));
 assert.equal(health.rows[0].status,'unhealthy');assert.ok(health.rows[0].openFailures>0);
 await command('directory/edit',{personId:'held',source:'hr',set:{name:'Held worker profile revised'}});
 const revised=await result(await r.call('/api/auth/reports/terminated-people',{cookie:owner.cookie}));
 const residual=revised.rows.find(row=>row.personId==='held');assert.deepEqual(residual.unresolvedApps,['Unresolved payroll access']);assert.equal(residual.remoteVerifiedAt,'unknown','superseding an old leaver queue never fabricates remote completion');
 assert.ok(!JSON.stringify([report,health,revised]).includes(token));
}
