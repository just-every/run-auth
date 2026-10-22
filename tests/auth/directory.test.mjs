import {test} from 'node:test';
import assert from 'node:assert/strict';
import {samlInstall,addApp} from './saml-helpers.mjs';

const get=async(r,path)=>(await r.call('/api/auth/'+path,{cookie:r.owner.cookie})).json();
const person=async(r,email)=>(await get(r,'directory?q='+encodeURIComponent(email))).people.find(p=>p.email===email);
const admin=async(r,path,data,status=200)=>{const response=await r.admin(path,data);assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};

test('onboard, rename, transfer, bulk preview, dynamic groups, suspend and rehire keep one stable account per person',async t=>{
 const r=await samlInstall(t);
 // Dynamic group: US engineers. Static group: Everyone.
 const engineers=await admin(r,'groups/create',{name:'US engineers'},201);
 const preview=await admin(r,'groups/rule',{groupId:engineers.id,preview:true,rule:{match:'all',conditions:[{field:'department',op:'eq',value:'Engineering'},{field:'location',op:'eq',value:'US'}]}});
 assert.deepEqual(preview.added,[]);
 await admin(r,'groups/rule',{groupId:engineers.id,rule:{match:'all',conditions:[{field:'department',op:'eq',value:'Engineering'},{field:'location',op:'eq',value:'US'}]}});
 const wiki=await addApp(r,{entityId:'https://wiki.example.com',acsUrl:'https://wiki.example.com/acs',assign:[]});
 await admin(r,'company-apps/assign',{appId:wiki.id,principalType:'group',principalId:engineers.id,role:'editor'});
 // A W-2 employee and a contractor are onboarded as invited members with their values and one invitation each.
 const mails=(await r.mails()).length;
 const erin=await admin(r,'directory/onboard',{email:'Erin@Corp.example.com',name:'Erin Park',kind:'employee',set:{employment_type:'w2',title:'Engineer',department:'Engineering',location:'US',start_date:'2026-03-02'}},201);
 const cole=await admin(r,'directory/onboard',{email:'cole@contractors.example.com',name:'Cole Reed',kind:'contractor',set:{employment_type:'1099',department:'Engineering',location:'UK',end_date:'2026-12-31'}},201);
 assert.equal((await r.mails()).length,mails+2);
 assert.equal((await person(r,'erin@corp.example.com')).state,'invited');
 assert.deepEqual(erin.plan.groups.added.map(g=>g.name),['US engineers']);assert.deepEqual(cole.plan.groups.added,[]);
 const robot=await admin(r,'directory/onboard',{email:'ci-bot@corp.example.com',name:'CI bot',kind:'service',invite:false,set:{department:'Engineering',location:'US'}},201);
 assert.equal((await r.mails()).length,mails+2,'no invitation was sent for the service identity');
 const filtered=await get(r,'directory?state=invited&f.kind=service');assert.deepEqual(filtered.people.map(p=>p.id),[robot.id]);assert.equal(filtered.total,1);
 assert.deepEqual((await get(r,'directory?q=Cole')).people.map(p=>p.id),[cole.id]);assert.equal((await get(r,'directory?group='+engineers.id)).total,2);
 const mapped=(await get(r,'directory/groups')).groups.find(g=>g.id===engineers.id);assert.deepEqual(mapped.apps,[{appId:wiki.id,app:mapped.apps[0].app,role:'editor'}]);
 // Neither a second onboarding nor an email change can create a duplicate or merge by email.
 const dupe=await r.admin('directory/onboard',{email:'erin@corp.example.com',name:'Erin Again'});assert.equal(dupe.status,409);
 assert.deepEqual(await dupe.json(),{error:'onboard_refused',refusals:['person_exists'],personId:erin.id});
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM oa_operators WHERE email LIKE 'erin@%'").first()).n,1);
 const merge=await r.admin('directory/edit',{personId:cole.id,email:'erin@corp.example.com'});assert.equal(merge.status,409);assert.match(JSON.stringify(await merge.json()),/email_in_use/);
 // Rename and transfer one (Cole) with a single edit: same id, the name and the new values, a group gained, an app gained once he is active.
 await r.db.prepare("UPDATE oa_operators SET status='active' WHERE id=?").bind(cole.id).run();
 const moved=await admin(r,'directory/edit',{personId:cole.id,set:{name:'Colette Reed',location:'US'}});
 assert.deepEqual(moved.entry.groups.added.map(g=>g.name),['US engineers']);assert.deepEqual(moved.entry.apps.gained.map(a=>[a.appId,a.role]),[[wiki.id,'editor']]);
 const colette=await person(r,'cole@contractors.example.com');
 assert.equal(colette.id,cole.id);assert.equal(colette.name,'Colette Reed');assert.equal(colette.fields.location.value,'US');assert.equal(colette.fields.kind.value,'contractor');
 assert.deepEqual(colette.groups.map(g=>[g.name,g.via]),[['US engineers','rule']]);
 // Bulk preview by filter: nothing changes until the exact preview is applied.
 const bulk={filter:{fields:{department:'Engineering'}},set:{department:'Platform'}};
 const planned=(await admin(r,'directory/preview',bulk)).plan;
 assert.equal(planned.summary.people,3);assert.equal(planned.summary.groupsLost,3);assert.deepEqual(planned.entries.flatMap(e=>e.groups.removed.map(g=>g.name)),['US engineers','US engineers','US engineers']);
 assert.equal((await person(r,'erin@corp.example.com')).fields.department.value,'Engineering');
 assert.equal((await r.admin('directory/apply',bulk)).status,400);
 assert.equal((await r.admin('directory/apply',{...bulk,digest:'stale'})).status,409);
 assert.equal((await person(r,'erin@corp.example.com')).fields.department.value,'Engineering');
 await admin(r,'directory/apply',{...bulk,digest:planned.digest});
 assert.equal((await person(r,'erin@corp.example.com')).fields.department.value,'Platform');
 assert.deepEqual((await person(r,'erin@corp.example.com')).groups,[]);
 // Evaluated again: moving Erin back puts her in the dynamic group again.
 await admin(r,'directory/edit',{personId:erin.id,set:{department:'Engineering'}});
 assert.deepEqual((await person(r,'erin@corp.example.com')).groups.map(g=>g.name),['US engineers']);
 // Suspend and rehire Ada, who is signed in: access ends at once, her account and id are the same afterwards, with no duplicate.
 const adaId=(await person(r,'ada@example.com')).id;
 await admin(r,'directory/edit',{personId:adaId,set:{department:'Engineering',location:'US'}});
 assert.deepEqual((await (await r.call('/api/auth/launcher',{cookie:r.ada})).json()).apps.map(a=>a.id),[wiki.id]);
 const leaving=await admin(r,'directory/preview',{edits:[{personId:adaId,state:'terminated'}]});
 assert.deepEqual(leaving.plan.entries[0].apps.lost.map(a=>a.appId),[wiki.id]);assert.equal(leaving.plan.summary.destructive,1);
 await admin(r,'directory/edit',{personId:adaId,state:'terminated'});
 assert.equal((await r.call('/api/auth/launcher',{cookie:r.ada})).status,401);
 const gone=await person(r,'ada@example.com');assert.equal(gone.state,'terminated');assert.deepEqual(gone.apps,[]);assert.deepEqual(gone.groups.map(g=>g.name),['US engineers']);
 assert.equal((await admin(r,'directory/edit',{personId:adaId,state:'active'})).entry.state.kind,'rehire');
 const back=await person(r,'ada@example.com');assert.equal(back.id,adaId);assert.equal(back.state,'active');assert.deepEqual(back.apps.map(a=>[a.appId,a.role]),[[wiki.id,'editor']]);
 r.ada=await (await import('./runtime.mjs')).emailSession(r,'ada@example.com');
 assert.deepEqual((await (await r.call('/api/auth/launcher',{cookie:r.ada})).json()).apps.map(a=>a.id),[wiki.id]);
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM oa_operators WHERE email='ada@example.com'").first()).n,1);
 // The returning worker's address belongs to the former record: onboarding refuses and names it for a rehire review.
 await admin(r,'directory/edit',{personId:adaId,state:'terminated'});
 const again=await r.admin('directory/onboard',{email:'ada@example.com',name:'Ada Again'});assert.equal(again.status,409);assert.deepEqual(await again.json(),{error:'onboard_refused',refusals:['rehire_review_required'],personId:adaId});
 await admin(r,'directory/edit',{personId:adaId,state:'active'});
 // Invited people, the owner and the acting administrator cannot be suspended through the directory.
 for(const [id,code] of [[erin.id,'invitation_not_accepted'],['owner','owner_state_fixed']]){const refused=await r.admin('directory/edit',{personId:id,state:'suspended'});assert.equal(refused.status,409);assert.match(JSON.stringify(await refused.json()),new RegExp(code));}
});


test('source precedence, manual overrides and conflicts are visible; a source finds people by its own id, never by email; an email change keeps the same person, sessions end and apps follow',async t=>{
 const r=await samlInstall(t),{emailSession}=await import('./runtime.mjs'),{scimServer}=await import('./scim-server.mjs');
 const sales=await admin(r,'groups/create',{name:'Sales'},201);
 await admin(r,'groups/rule',{groupId:sales.id,rule:{match:'any',conditions:[{field:'department',op:'in',values:['Sales','Support']}]}});
 const ada=(await person(r,'ada@example.com')).id;
 await admin(r,'directory/edit',{personId:ada,set:{department:'Engineering',title:'Engineer'}});
 // The HR system's record has an id Auth has not seen, and an email that matches Ada: it waits for review and changes nothing.
 const record={sourceId:'W-1001',email:'ada@example.com',fields:{department:'Sales',title:'Engineer'}};
 const waiting=await admin(r,'directory/source',{source:'hr',records:[record]});
 assert.deepEqual(waiting.outcomes,[{sourceId:'W-1001',outcome:'review_required',candidate:{personId:ada,email:'ada@example.com',state:'active'}}]);
 assert.equal(waiting.applied,0);assert.equal((await person(r,'ada@example.com')).fields.department.value,'Engineering');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_person_sources').first()).n,0);
 // The administrator names the person: the id is bound for good. HR's department loses to the manual value, and the conflict is explicit.
 const bound=await admin(r,'directory/source',{source:'hr',records:[{...record,personId:ada}]});
 assert.deepEqual(bound.conflicts.map(c=>[c.personId,c.field,c.effective.source,c.effective.value,c.others.map(o=>o.source+':'+o.value)]),[[ada,'department','manual','Engineering',['hr:Sales']]]);
 const listed=await get(r,'directory?conflicts=1');assert.deepEqual(listed.people.map(p=>p.id),[ada]);
 assert.deepEqual(listed.people[0].fields.department,{value:'Engineering',source:'manual',also:[{source:'hr',value:'Sales'}]});
 assert.deepEqual(listed.people[0].sourceIds,{hr:'W-1001'});assert.deepEqual(listed.people[0].groups,[]);
 // Another person cannot take the id, and Ada's id cannot change.
 const bob=(await person(r,'bob@example.com')).id;
 const taken=await admin(r,'directory/source',{source:'hr',records:[{sourceId:'W-1001',personId:bob,fields:{title:'x'}}]});
 assert.deepEqual(taken.outcomes,[{sourceId:'W-1001',outcome:'refused',refusals:['source_id_in_use']}]);
 assert.equal((await person(r,'bob@example.com')).fields.title,undefined);assert.equal((await person(r,'ada@example.com')).fields.title.source,'manual');
 await admin(r,'directory/source',{source:'hr',records:[{sourceId:'W-2002',personId:bob,fields:{title:'Analyst'}}]});
 const changed=await admin(r,'directory/source',{source:'hr',records:[{sourceId:'W-3003',personId:bob,fields:{title:'Lead'}}]});
 assert.deepEqual(changed.outcomes.map(o=>[o.outcome,o.refusals]),[['refused',['source_id_immutable']]]);assert.equal(changed.applied,0);
 assert.equal((await person(r,'bob@example.com')).fields.title.value,'Analyst');
 // Accepting the source's value ends the override: HR's department is effective and the dynamic group follows.
 await admin(r,'directory/resolve',{personId:ada,field:'department',keep:'hr'});
 const accepted=await person(r,'ada@example.com');assert.deepEqual(accepted.fields.department,{value:'Sales',source:'hr',also:[]});assert.deepEqual(accepted.conflicts,[]);assert.deepEqual(accepted.groups.map(g=>g.name),['Sales']);
 assert.equal((await r.admin('directory/resolve',{personId:ada,field:'department',keep:'hr'})).status,409);
 // The directory feed ranks below HR: its different value is a conflict, never applied. HR names the person: the employee can no longer edit it.
 await admin(r,'directory/source',{source:'directory',records:[{sourceId:'D-9',personId:ada,fields:{department:'Support',name:'Ada L.'}}]});
 const ranked=await person(r,'ada@example.com');assert.equal(ranked.fields.department.value,'Sales');assert.deepEqual(ranked.conflicts.map(c=>c.field),['department']);
 assert.equal(ranked.name,'Ada L.');
 // An email change is the same person: same id, no duplicate, sessions end until the new address is proved, and a taken address is refused.
 const scim=await scimServer(t);r.scimServer=scim.url;
 const crm=await addApp(r,{entityId:'https://crm.example.com',acsUrl:'https://crm.example.com/acs',assign:['ada']});
 await admin(r,'provisioning/connect',{appId:crm.id,baseUrl:'https://scim.example.com/scim/v2',token:scim.token,pushGroups:false},201);
 const remote=()=>[...scim.users.values()].find(u=>u.externalId===ada),remoteId=remote().id;
 assert.equal(remote().userName,'ada@example.com');
 assert.match(JSON.stringify(await (await r.admin('directory/edit',{personId:ada,email:'bob@example.com'})).json()),/email_in_use/);
 assert.match(JSON.stringify(await (await r.admin('directory/edit',{personId:ada,email:'ada@example.com'})).json()),/"changed":false/);
 await admin(r,'directory/edit',{personId:ada,email:'Ada.Lovelace@Example.com'});
 assert.equal((await r.call('/api/auth/launcher',{cookie:r.ada})).status,401);
 assert.equal(remote().userName,'ada.lovelace@example.com');assert.equal(remote().id,remoteId);assert.equal(scim.users.size,1);
 const renamed=await person(r,'ada.lovelace@example.com');assert.equal(renamed.id,ada);assert.equal(await person(r,'ada@example.com'),undefined);
 assert.equal(await r.db.prepare('SELECT 1 FROM auth_emails WHERE person_id=?').bind(ada).first(),null);
 r.ada=await emailSession(r,'ada.lovelace@example.com');assert.equal((await r.call('/api/auth/launcher',{cookie:r.ada})).status,200);
 // Everything above is in the audit trail with who and what.
 const trail=(await r.db.prepare("SELECT event FROM auth_activity WHERE event LIKE 'directory_%' OR event LIKE 'group_rule%'").all()).results.map(x=>x.event);
 assert.ok(['directory_person_updated','directory_conflict_resolved','group_rule_set'].every(e=>trail.includes(e)));
});

test('directory doors need a passkey administrator with fresh email proof; attributes are typed; groups explain each member, keep owners and honour exclusions',async t=>{
 const r=await samlInstall(t);
 const ada=(await person(r,'ada@example.com')).id,bob=(await person(r,'bob@example.com')).id;
 // Members and signed-out callers read and write nothing; a stale email proof reads and previews but writes nothing.
 for(const cookie of [r.ada,undefined]){
  const read=await r.call('/api/auth/directory',{cookie}),write=await r.call('/api/auth/directory/edit',{method:'POST',data:{personId:bob,set:{title:'x'}},cookie});
  assert.deepEqual([read.status,write.status],cookie?[403,403]:[401,401]);
 }
 r.now=Date.now()+11*60000;
 assert.equal((await r.call('/api/auth/directory',{cookie:r.owner.cookie})).status,200);
 assert.equal((await r.call('/api/auth/directory/preview',{method:'POST',data:{edits:[{personId:bob,set:{title:'x'}}]},cookie:r.owner.cookie})).status,200);
 const stale=await r.call('/api/auth/directory/edit',{method:'POST',data:{personId:bob,set:{title:'x'}},cookie:r.owner.cookie});
 assert.equal(stale.status,403);assert.equal((await stale.json()).error,'local_email_step_up_required');
 r.now=Date.now();
 // Typed attributes with visibility: a bad value or an unknown field refuses the whole edit, nothing is half-applied.
 assert.equal((await r.admin('directory/attributes',{name:'Bad Name',label:'x'})).status,400);
 await admin(r,'directory/attributes',{name:'level',label:'Level',type:'number',visibility:'admin'},201);
 await admin(r,'directory/attributes',{name:'badge',label:'Badge',type:'choice',choices:['red','blue'],employeeEditable:true},201);
 assert.equal((await r.admin('directory/attributes',{name:'level',label:'Level',type:'text'})).status,409);
 const refused=await r.admin('directory/edit',{personId:bob,set:{'x.level':'high',title:'Analyst','x.nope':'1',start_date:'2026-02-30'}});
 assert.equal(refused.status,409);assert.deepEqual((await refused.json()).refusals,['bob@example.com: invalid_value:x.level','bob@example.com: unknown_field:x.nope','bob@example.com: invalid_value:start_date']);
 assert.equal((await person(r,'bob@example.com')).fields.title,undefined);
 await admin(r,'directory/edit',{personId:bob,set:{'x.level':'7','x.badge':'Blue',manager:ada}});
 const typed=(await person(r,'bob@example.com')).fields;assert.deepEqual([typed['x.level'].value,typed['x.badge'].value,typed.manager.value],['7','blue',ada]);
 assert.match(JSON.stringify(await (await r.admin('directory/edit',{personId:ada,set:{manager:bob}})).json()),/manager_cycle:manager/);
 assert.match(JSON.stringify(await (await r.admin('directory/edit',{personId:ada,set:{manager:'nobody'}})).json()),/manager_not_found:manager/);
 // Groups: a manual member and a rule's members are told apart; a removed rule member stays out; an addition lifts that.
 const everyone=await admin(r,'groups/create',{name:'Contractors'},201);
 await admin(r,'directory/edit',{personId:bob,set:{kind:'contractor'}});
 await admin(r,'groups/add',{groupId:everyone.id,personId:ada});
 await admin(r,'groups/rule',{groupId:everyone.id,rule:{match:'all',conditions:[{field:'kind',op:'eq',value:'contractor'}]}});
 await admin(r,'groups/owners/add',{groupId:everyone.id,personId:ada});
 let group=(await get(r,'directory/groups')).groups.find(g=>g.id===everyone.id);
 assert.deepEqual(group.members.map(m=>[m.id,m.via,m.matchesRule,m.why??null]).sort(),[[ada,'manual',false,null],[bob,'rule',true,['kind is contractor']]]);
 assert.deepEqual(group.owners.map(o=>o.id),[ada]);assert.equal(group.members.find(m=>m.id===ada).addedBy,'owner@example.com');
 await admin(r,'groups/remove',{groupId:everyone.id,personId:bob,reason:'engaged as employee'});
 await admin(r,'directory/edit',{personId:bob,set:{title:'Analyst'}});
 group=(await get(r,'directory/groups')).groups.find(g=>g.id===everyone.id);
 assert.deepEqual(group.members.map(m=>m.id),[ada]);assert.deepEqual(group.excluded.map(x=>[x.id,x.reason,x.by]),[[bob,'engaged as employee','owner@example.com']]);
 await admin(r,'groups/add',{groupId:everyone.id,personId:bob});
 group=(await get(r,'directory/groups')).groups.find(g=>g.id===everyone.id);assert.deepEqual(group.excluded,[]);assert.equal(group.members.find(m=>m.id===bob).via,'manual');
 // Clearing the rule keeps manual members; the preview names who leaves. Deleting the group leaves no owners or exclusions behind.
 const cleared=await admin(r,'groups/rule',{groupId:everyone.id,rule:null,preview:true});assert.deepEqual(cleared.removed,[]);
 await admin(r,'groups/remove',{groupId:everyone.id,personId:bob});await admin(r,'groups/delete',{id:everyone.id});
 for(const table of ['auth_group_owners','auth_group_exclusions','auth_group_members'])assert.equal((await r.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first()).n,0,table);
 // Someone invited outside the directory is put in a rule's group when they activate.
 const staff=await admin(r,'groups/create',{name:'All employees'},201);
 await admin(r,'groups/rule',{groupId:staff.id,rule:{match:'all',conditions:[{field:'kind',op:'eq',value:'employee'}]}});
 await admin(r,'people/invite',{email:'newhire@example.com',name:'New Hire'},201);
 const members=async()=>(await get(r,'directory/groups')).groups.find(g=>g.id===staff.id).members.map(m=>m.email);
 assert.equal((await members()).includes('newhire@example.com'),false,'access and membership wait for activation');
 await (await import('./runtime.mjs')).emailSession(r,'newhire@example.com');
 assert.equal((await members()).includes('newhire@example.com'),true);
});


test('scoped help desk separates view and edit, refuses privileged and out-of-group people, and follows live membership',async t=>{
 const r=await samlInstall(t);
 const {register}=await import('./webauthn.mjs'),{emailSession}=await import('./runtime.mjs');
 await r.person('helper','helper@example.com');const helper=await register(r,await emailSession(r,'helper@example.com'));
 const a=await admin(r,'groups/create',{name:'Support scope A'},201),b=await admin(r,'groups/create',{name:'Read-only scope B'},201);
 await admin(r,'directory/edit',{personId:'ada',set:{location:'US'}});await admin(r,'groups/rule',{groupId:a.id,rule:{match:'all',conditions:[{field:'location',op:'eq',value:'US'}]}});await admin(r,'groups/add',{groupId:b.id,personId:'bob'});
 const ada=await register(r,r.ada);const bob=await register(r,r.bob);
 const plan=async(data,cookie=r.owner.cookie)=>{
  const response=await r.call('/api/auth/roles/preview',{method:'POST',cookie,data});assert.equal(response.status,200,await response.clone().text());
  const preview=await response.json(),saved=await r.call('/api/auth/roles/apply',{method:'POST',cookie,data:{previewId:preview.previewId}});assert.equal(saved.status,200,await saved.clone().text());assert.deepEqual((await saved.json()).plan,preview.plan);return preview.plan;
 };
 const refusedPlan=async(data,cookie,status,error)=>{
  const response=await r.call('/api/auth/roles/preview',{method:'POST',cookie,data});assert.equal(response.status,status,await response.clone().text());assert.equal((await response.json()).error,error);
 };
 for(const rank of [90,100])await refusedPlan({kind:'role',role:{name:'Too powerful',rank,permissions:['people.view']}},r.owner.cookie,400,'invalid_role');
 const role=await plan({kind:'role',role:{name:'Regional recovery specialists',rank:25,permissions:['roles.view','roles.grant','people.view','people.factors.reset','groups.view','cases.view','cases.open','cases.verify']}});
 const resources={view:{groups:[a.id,b.id]},edit:{groups:[a.id]}};
 const granted=await plan({kind:'grant',personId:'helper',roleId:role.role.id,resources});
 const action=(permission,resourceId,resourceKind='people')=>({permission,...(resourceId?{resourceKind,resourceId}:{})});
 const ordered=actions=>actions.map(a=>JSON.stringify(a)).sort();
 assert.equal(granted.effects.length,1);assert.equal(granted.effects[0].personId,'helper');assert.equal(granted.effects[0].email,'helper@example.com');
 assert.deepEqual(granted.effects[0].lost,[]);
 assert.deepEqual(ordered(granted.effects[0].gained),ordered([action('roles.view'),action('roles.grant'),action('people.view','ada'),action('people.view','bob'),action('people.factors.reset','ada'),action('groups.view',a.id,'groups'),action('groups.view',b.id,'groups')]),'preview names the exact recipient, permissions and resources gained');
 const command=async(data)=>r.call('/api/auth/roles/reset-factors',{method:'POST',cookie:helper.cookie,data:{reason:'Employee requested a verified factor reset',...data}});
 const visible=await (await r.call('/api/auth/roles/people',{cookie:helper.cookie})).json();assert.deepEqual(visible.people.map(p=>p.id).sort(),['ada','bob']);
 assert.equal((await r.call('/api/auth/roles/people?personId=bob',{cookie:helper.cookie})).status,200,'view B succeeds');
 assert.equal((await command({personId:'bob'})).status,403);assert.equal((await r.call('/api/auth/roles/export',{cookie:helper.cookie})).status,403);
 for(const path of ['people','directory','move-in/subjects.csv?batch=foreign'])assert.equal((await r.call('/api/auth/'+path,{cookie:helper.cookie})).status,403,'legacy unscoped read/export remains closed');
 assert.equal((await r.call('/api/auth/people/suspend',{method:'POST',cookie:helper.cookie,data:{personId:'bob'}})).status,403,'direct legacy write closed');
 assert.equal((await r.call('/api/auth/roles/preview',{method:'POST',cookie:helper.cookie,data:{kind:'grant',personId:'bob',roleId:'help-desk',resources:{view:{groups:['*']},edit:{groups:['*']}}}})).status,403,'cannot delegate a wider resource set');
 assert.equal((await command({personId:'ada'})).status,200);assert.equal((await r.call('/api/auth/me',{cookie:ada.cookie})).status,401);
 // A fresh factor for Ada, followed by membership change, affects the next decision.
 const adaAgain=await register(r,await emailSession(r,'ada@example.com'));
 await admin(r,'groups/add',{groupId:b.id,personId:'ada'});
 assert.equal((await command({personId:'ada'})).status,403,'membership outside edit scope refuses even when still in A');
 await admin(r,'groups/remove',{groupId:b.id,personId:'ada'});
 assert.equal((await command({personId:'ada'})).status,200);
 assert.equal((await r.call('/api/auth/me',{cookie:adaAgain.cookie})).status,401);
 await r.person('senior','senior@example.com','admin');await admin(r,'groups/add',{groupId:a.id,personId:'senior'});
 assert.equal((await command({personId:'senior'})).status,403,'administrator in A cannot be reset');
 await admin(r,'directory/edit',{personId:'ada',set:{location:'UK'}});assert.equal((await command({personId:'ada'})).status,403,'attribute-driven group departure changes the next decision');
 const trail=await (await r.call('/api/auth/activity',{cookie:r.owner.cookie})).json();assert.ok(trail.some(e=>e.event==='roles.factors.reset'));
 const noEmail=await r.call('/api/auth/roles/reset-factors',{method:'POST',cookie:helper.cookie,data:{personId:'bob',reason:'Still refused'}});assert.equal(noEmail.status,403);
 // Revocation is live, rather than a session-embedded permission.
 const revoked=await plan({kind:'revoke',grantId:granted.id});assert.equal((await r.call('/api/auth/roles/people',{cookie:helper.cookie})).status,403);
 assert.equal(revoked.effects.length,1);assert.equal(revoked.effects[0].personId,'helper');assert.equal(revoked.effects[0].email,'helper@example.com');assert.deepEqual(revoked.effects[0].gained,[]);
 assert.deepEqual(ordered(revoked.effects[0].lost),ordered([action('roles.view'),action('roles.grant'),action('people.view','bob'),action('people.view','senior'),action('groups.view',a.id,'groups'),action('groups.view',b.id,'groups')]),'revocation preview names current actions lost after live membership changed');
 assert.equal((await r.call('/api/auth/me',{cookie:bob.cookie})).status,200);
 // Legacy administrators cannot create their equal or a higher rank. A scoped
 // holder cannot author roles even when explicitly delegated roles.edit.
 const senior=await register(r,await emailSession(r,'senior@example.com'));
 for(const rank of [90,91])await refusedPlan({kind:'role',role:{name:'At or above chooser',rank,permissions:['people.view']}},senior.cookie,400,'invalid_role');
 const author=await plan({kind:'role',role:{name:'Delegated role author',rank:5,permissions:['roles.view','roles.edit']}});
 const all={view:{people:['*'],groups:['*'],apps:['*'],cases:['*']},edit:{people:['*'],groups:['*'],apps:['*'],cases:['*']}};
 await plan({kind:'grant',personId:'helper',roleId:author.role.id,resources:all});
 await refusedPlan({kind:'role',role:{name:'Unauthorized custom role',rank:1,permissions:['roles.view']}},helper.cookie,403,'owner_admin_required');
 // Security/policy administration can delegate a rank-79 subset, but not an
 // otherwise identical rank-80 role. Rank alone supplies no extra permission.
 const lower=await plan({kind:'role',role:{name:'Lower directory reviewer',rank:79,permissions:['roles.view','people.view']}}),equal=await plan({kind:'role',role:{name:'Equal directory reviewer',rank:80,permissions:['roles.view','people.view']}});
 await plan({kind:'grant',personId:'helper',roleId:'security-policy-administrator',resources:all});
 await plan({kind:'grant',personId:'ada',roleId:lower.role.id,resources:all},helper.cookie);
 await refusedPlan({kind:'grant',personId:'bob',roleId:equal.role.id,resources:all},helper.cookie,403,'role_grant_wider_than_holder');
 assert.equal((await r.call('/api/auth/roles/reset-factors',{method:'POST',cookie:helper.cookie,data:{personId:'bob',reason:'Policy rank does not grant recovery'}})).status,403);
 // The auditor can view higher administrators and export a rank-9 person;
 // exporting a peer auditor at rank 10 remains an account-administration fence.
 await r.person('junior-reviewer','junior-reviewer@example.com');await r.person('peer-auditor','peer-auditor@example.com');
 const junior=await plan({kind:'role',role:{name:'Junior reviewer',rank:9,permissions:['people.view']}});
 await plan({kind:'grant',personId:'junior-reviewer',roleId:junior.role.id,resources:all});
 await plan({kind:'grant',personId:'peer-auditor',roleId:'auditor',resources:all});
 await plan({kind:'grant',personId:'bob',roleId:'auditor',resources:all});
 for(const personId of ['senior','helper']){
  const read=await r.call('/api/auth/roles/people?personId='+personId,{cookie:bob.cookie});assert.equal(read.status,200);assert.deepEqual((await read.json()).people.map(p=>p.id),[personId],'auditor views a higher administrator');
 }
 const exported=await r.call('/api/auth/roles/export?personId=junior-reviewer',{cookie:bob.cookie});assert.equal(exported.status,200);assert.deepEqual((await exported.json()).people.map(p=>p.id),['junior-reviewer']);
 assert.equal((await r.call('/api/auth/roles/export?personId=peer-auditor',{cookie:bob.cookie})).status,403,'auditor cannot export an equal administrator');
});

import {accessDecisionsFlow,requestDecisionsFlow,accessReviewsFlow} from './access-decisions-flow.mjs';
import {retentionFlow} from './retention-flow.mjs';
test('group owners confirm exact ordinary decisions without email and lose stale or privileged authority',accessDecisionsFlow);
test('independent request decisions bind the current approver and temporary access expires without claiming remote removal',requestDecisionsFlow);
test('quarterly access snapshots retain delegation, drift, overdue escalation and verified remediation',accessReviewsFlow);
test('retention previews export before expiry and preserve held classes and unfinished work across restart',retentionFlow);
