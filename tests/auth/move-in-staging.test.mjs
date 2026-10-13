import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ownerInstall,stage,staged,review,byEmail,count,table,post} from './move-in-helpers.mjs';

const ADA='ada@northwind.example.com',GRACE='grace@northwind.example.com',MOLLY='molly@northwind.example.com';
// Every source reads into the same staged shape.
async function expectSource(t,files,expected) {
 const {r,cookie}=await ownerInstall(t);
 for(const file of files) {
  const response=await stage(r,cookie,file);assert.equal(response.status,201,`${file}: ${await response.clone().text()}`);
  const {batchId,source}=await response.json();assert.equal(source,expected.system,file);
  const rows=await review(r,cookie,batchId);
  assert.deepEqual(rows.map(row=>row.email),[ADA,GRACE,MOLLY],file);
  assert.deepEqual(rows.map(row=>row.displayName),expected.names??['Ada Lovelace','Grace Hopper','Mary Jackson'],file);
  assert.deepEqual(rows.map(row=>row.disabled),expected.disabled[file]??expected.disabled.all,file);
  assert.ok(rows.every(row=>expected.ids?typeof row.sourceId==='string'&&row.sourceId.length>0:row.sourceId===null),`${file}: source ids`);
  if(expected.context)assert.deepEqual(rows[0].groups,[expected.context],file);
  const batch=await r.db.prepare('SELECT * FROM auth_import_batches WHERE id=?').bind(batchId).first();
  assert.equal(batch.source_system,expected.system);assert.equal(batch.export_date,'2026-10-11');assert.equal(batch.file_name,file);
  if(expected.verify)await expected.verify(rows);
 }
}

test('Google Workspace JSON export stages through the route',t=>expectSource(t,['google-users.json'],{system:'google',ids:true,context:'Org unit /Engineering',disabled:{all:[false,true,true]}}));
test('Microsoft Entra CSV stages through the route',t=>expectSource(t,['entra-users.csv'],{system:'microsoft',ids:true,context:'Department Engineering',disabled:{all:[false,true,false]}}));
test('Auth0 CSV and NDJSON exports stage through the route',t=>expectSource(t,['auth0-users.csv','auth0-users.ndjson'],{system:'auth0',ids:true,
 disabled:{'auth0-users.csv':[false,true,false],'auth0-users.ndjson':[false,true,null]},
 verify:rows=>assert.deepEqual(rows.map(row=>row.sourceId),['auth0|64f0000000000000000000a1','google-oauth2|10000000000000000002','auth0|64f0000000000000000000a3'])}));
test('Okta Users API list stages through the route',t=>expectSource(t,['okta-users.json'],{system:'okta',ids:true,context:'Department Engineering',disabled:{all:[false,true,false]}}));
test('JumpCloud CSV and JSON exports stage through the route',t=>expectSource(t,['jcuserlist_20261011.csv','jcuserlist_20261011.json'],{system:'jumpcloud',ids:true,context:'Department Engineering',disabled:{all:[false,true,false]}}));

// The Google CSV fixture carries an unconfirmed Status column marking Grace suspended: it is read as absent.
test('Google Workspace CSV export stages through the route without a source id or disabled state',t=>expectSource(t,['google-users.csv'],{system:'google',ids:false,context:'Org unit /Engineering',
 names:['Ada Lovelace','Grace Hopper','Mary "Molly" Jackson'],disabled:{all:[null,null,null]},verify:rows=>assert.ok(!byEmail(rows,GRACE).reasons.includes('disabled_at_source'))}));

test('hostile files: formula cells, bad addresses, duplicates, lookalike domains, oversize and unknown files',async t=>{
 const {r,cookie}=await ownerInstall(t),rows=await review(r,cookie,await staged(r,cookie,'hostile-entra.csv'));
 const reasons=Object.fromEntries(rows.map(row=>[row.sourceId.slice(-2),row.reasons]));
 assert.deepEqual(reasons['01'],['formula_text'],'formula name is flagged and starts unselected');
 assert.equal(rows[0].selected,false);assert.equal(rows[0].admittable,true);
 for(const id of ['02','03'])assert.deepEqual(reasons[id],['invalid_email','formula_text'],`row ${id}: an address starting with + or - is refused and its formula name flagged`);
 assert.deepEqual(reasons['04'],['invalid_email'],'a row without a valid address is refused');
 for(const id of ['05','06','07'])assert.deepEqual(reasons[id],['duplicate_in_file'],`row ${id}: case and plus-address duplicates are flagged`);
 assert.equal(rows[4].email,rows[5].email,'mixed-case duplicates fold to one address');
 assert.deepEqual(reasons['08'],['refused_domain'],'lookalike Unicode domain is refused');
 assert.ok(rows.filter(row=>!row.admittable).every(row=>!row.selected));
 const people=await table(r,'oa_operators'),batches=await count(r,'SELECT count(*) AS n FROM auth_import_batches');
 const large=await stage(r,cookie,'big.csv',{text:'userPrincipalName,objectId,mail\n'+'x'.repeat(1024*1024)});
 assert.equal(large.status,413);assert.equal((await large.json()).error,'file_too_large');
 const unknown=await stage(r,cookie,'other.csv',{text:'Name,Address\nAda,ada@northwind.example.com\n'});
 assert.equal(unknown.status,400);const refusal=await unknown.json();assert.equal(refusal.error,'file_not_recognised');assert.ok(refusal.message.length>0);
 const broken=await stage(r,cookie,'broken.json',{text:'[{"primaryEmail":'});assert.equal(broken.status,400);
 const wide=await stage(r,cookie,'wide.csv',{text:['userPrincipalName,objectId,mail',...Array.from({length:300},(_,i)=>'extra'+i)].join(',')+'\nada@northwind.example.com,1,ada@northwind.example.com\n'});
 assert.equal(wide.status,400);assert.equal((await wide.json()).error,'too_many_columns','a file far wider than any export is refused before its rows are read');
 assert.equal(await count(r,'SELECT count(*) AS n FROM auth_import_batches'),batches,'refused files stage nothing');
 assert.deepEqual(await table(r,'oa_operators'),people);
});

test('staging is separate from people: no person, grant, session or mail, one activity entry, and a repeat upload adds nothing',async t=>{
 const {r,cookie}=await ownerInstall(t);
 const before={people:await table(r,'oa_operators'),grants:await table(r,'auth_grants'),sessions:await table(r,'auth_sessions'),mail:(await r.mails()).length,activity:await table(r,'auth_activity')};
 const first=await stage(r,cookie,'google-30.json');assert.equal(first.status,201);const {batchId}=await first.json();
 assert.deepEqual(await table(r,'oa_operators'),before.people);assert.deepEqual(await table(r,'auth_grants'),before.grants);
 assert.deepEqual(await table(r,'auth_sessions'),before.sessions);assert.equal((await r.mails()).length,before.mail);
 const activity=await table(r,'auth_activity');assert.equal(activity.length,before.activity.length+1);
 assert.deepEqual({event:activity.at(-1).event,subject:activity.at(-1).subject_id,actor:activity.at(-1).actor_id},{event:'move_in_staged',subject:batchId,actor:'owner'});
 const listed=await(await r.call('/api/auth/people',{cookie})).json();assert.deepEqual(listed.map(p=>p.email),['owner@example.com'],'staged rows are on no People list');
 const again=await stage(r,cookie,'google-30.json');assert.equal(again.status,200);assert.deepEqual(await again.json(),{batchId,duplicate:true});
 assert.equal(await count(r,'SELECT count(*) AS n FROM auth_import_rows'),30);assert.equal((await table(r,'auth_activity')).length,activity.length);
 // A staged row can sign in to nothing and receives no mail: a sign-in request for it is the uniform unknown-address answer.
 const mail=(await r.mails()).length;
 const requested=await r.call('/auth/identity/email/request',post({email:'amara.okafor@northwind.example.com'}));assert.equal(requested.status,202);
 assert.equal((await r.mails()).length,mail);assert.deepEqual(await table(r,'oa_operators'),before.people);
});

test('review flags every conflict class; disabled-at-source rows start unselected and groups stay context',async t=>{
 const {r,cookie}=await ownerInstall(t);
 await r.db.prepare("INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES('existing','existing@northwind.example.com','Esme','member','active',1,?)").bind(r.now).run();
 const rows=await review(r,cookie,await staged(r,cookie,'google-30.json'));
 const of=email=>byEmail(rows,email);
 assert.deepEqual(of('amara.okafor@northwind.example.com').reasons,[]);assert.equal(of('amara.okafor@northwind.example.com').selected,true);
 assert.deepEqual(of('owner@example.com').reasons,['owner_address']);
 assert.deepEqual(of('existing@northwind.example.com').reasons,['existing_person']);
 assert.deepEqual(rows.filter(row=>row.email==='sam.lee@northwind.example.com').map(row=>row.reasons),[['duplicate_in_file'],['duplicate_in_file']]);
 for(const email of ['left.company@northwind.example.com','archived.person@northwind.example.com'])assert.deepEqual([of(email).reasons,of(email).selected,of(email).admittable],[['disabled_at_source'],false,true]);
 assert.deepEqual(rows.find(row=>row.displayName==='Pat Lookalike').reasons,['refused_domain']);
 assert.deepEqual(rows.find(row=>row.displayName==='No Address').reasons,['invalid_email']);
 assert.equal(rows.filter(row=>row.reasons.length===0).length,22);
 assert.deepEqual(of('chen.wei@northwind.example.com').groups,['Org unit /Engineering']);
});
