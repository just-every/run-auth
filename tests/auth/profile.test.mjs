import {test} from 'node:test';
import assert from 'node:assert/strict';
import {jwtVerify,createLocalJWKSet} from 'jose';
import {samlInstall} from './saml-helpers.mjs';
import {fixture} from './protocol-helpers.mjs';

const admin=async(r,path,data,status=200)=>{const response=await r.admin(path,data);assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
const profile=async(r,cookie)=>(await r.call('/api/auth/profile',{cookie})).json();
const update=(r,cookie,fields)=>r.call('/api/auth/profile/update',{method:'POST',data:{fields},cookie});
const field=(view,key)=>view.fields.find(f=>f.key===key);

test('an employee edits only permitted profile fields; fields held by HR or an administrator are protected and say who holds them; hidden fields stay hidden; groups follow',async t=>{
 const r=await samlInstall(t);
 const ada=(await (await r.call('/api/auth/directory?q=ada@example.com',{cookie:r.owner.cookie})).json()).people[0].id;
 await admin(r,'directory/attributes',{name:'pronouns',label:'Pronouns',type:'choice',choices:['she/her','he/him','they/them'],employeeEditable:true},201);
 await admin(r,'directory/attributes',{name:'level',label:'Level',type:'number',visibility:'admin'},201);
 await admin(r,'directory/attributes',{name:'badge',label:'Badge',type:'text',employeeEditable:true},201);
 const group=await admin(r,'groups/create',{name:'Gold badge'},201);
 await admin(r,'groups/rule',{groupId:group.id,rule:{match:'all',conditions:[{field:'x.badge',op:'eq',value:'gold'}]}});
 await admin(r,'directory/edit',{personId:ada,set:{department:'Engineering','x.level':'5'}});
 // Reading: her own values, which she may edit, and nothing an administrator keeps to themselves.
 let view=await profile(r,r.ada);
 assert.deepEqual(view.person,{id:ada,email:'ada@example.com',name:'ada'});
 assert.equal(field(view,'name').editable,true);assert.equal(field(view,'x.pronouns').editable,true);
 assert.deepEqual([field(view,'department').editable,field(view,'department').protectedBy,field(view,'department').value],[false,'manual','Engineering']);
 assert.equal(field(view,'x.level'),undefined);assert.equal(field(view,'email'),undefined);
 assert.equal((await r.call('/api/auth/profile')).status,401);
 // Writing: a permitted edit changes her name everywhere; a protected, hidden, unknown or malformed edit refuses everything.
 assert.equal((await update(r,r.ada,{name:'Ada Lovelace','x.pronouns':'she/her','x.badge':'gold'})).status,200);
 view=await profile(r,r.ada);assert.equal(view.person.name,'Ada Lovelace');assert.equal(field(view,'x.pronouns').value,'she/her');
 const record=(await (await r.call('/api/auth/directory?q=ada@example.com',{cookie:r.owner.cookie})).json()).people[0];
 assert.equal(record.name,'Ada Lovelace');assert.equal(record.fields.name.source,'self');assert.deepEqual(record.groups.map(g=>g.name),['Gold badge']);
 for(const [fields,status,error] of [[{department:'Sales'},403,'field_protected'],[{'x.level':'9'},404,'unknown_field'],[{email:'a@b.example'},404,'unknown_field'],[{role:'owner'},404,'unknown_field']]) {
  const refused=await update(r,r.ada,{name:'Changed',...fields});assert.equal(refused.status,status);assert.equal((await refused.json()).error,error);
 }
 const bad=await update(r,r.ada,{'x.pronouns':'robot'});assert.equal(bad.status,409);assert.match(JSON.stringify(await bad.json()),/invalid_value:x\.pronouns/);
 assert.equal((await profile(r,r.ada)).person.name,'Ada Lovelace');
 assert.equal((await update(r,r.bob,{name:'Bob'})).status,200);assert.equal((await profile(r,r.ada)).person.name,'Ada Lovelace');
 // Her edit moves her through dynamic groups like any directory change.
 assert.equal((await update(r,r.ada,{'x.badge':'silver'})).status,200);
 assert.deepEqual((await (await r.call('/api/auth/directory?q=ada@example.com',{cookie:r.owner.cookie})).json()).people[0].groups,[]);
 // The HR system takes the name: she can no longer overwrite it, and her page says whose it is.
 await admin(r,'directory/source',{source:'hr',records:[{sourceId:'E-7',personId:ada,fields:{name:'Ada King-Noel'}}]});
 view=await profile(r,r.ada);assert.deepEqual([view.person.name,field(view,'name').editable,field(view,'name').protectedBy],['Ada King-Noel',false,'hr']);
 let held=await update(r,r.ada,{name:'Ada L.'});assert.equal(held.status,403);assert.equal((await held.json()).error,'field_owned_by_source');
 // An administrator's value on an employee-editable field also holds against her.
 await admin(r,'directory/edit',{personId:ada,set:{'x.pronouns':'they/them'}});
 held=await update(r,r.ada,{'x.pronouns':'she/her'});assert.equal(held.status,403);assert.equal((await held.json()).error,'field_set_by_administrator');
 assert.equal(field(await profile(r,r.ada),'x.pronouns').value,'they/them');
 // Self-service never writes anyone else's row, and the administrator door never writes hers.
 assert.equal((await r.admin('directory/edit',{personId:ada,source:'self',set:{'x.badge':'gold'}})).status,409);
 const audit=(await r.db.prepare("SELECT event,actor_id FROM auth_activity WHERE event='directory_person_updated' AND actor_id=?").bind(ada).all()).results;assert.ok(audit.length>=2);
});

test('apps receive the edited name only under the profile scope, and never a custom or hidden field',async t=>{
 const r=await fixture(t);
 await r.db.prepare("INSERT INTO auth_attribute_defs(name,label,type,visibility,employee_editable,created_by,created_at) VALUES('badge','Badge','text','employee',1,'owner',?)").bind(r.now).run();
 await r.db.prepare("INSERT INTO auth_person_fields(person_id,field,source,value,set_at) VALUES('owner','x.badge','self','gold',?)").bind(r.now).run();
 const changed=await r.call('/api/auth/profile/update',{method:'POST',data:{fields:{name:'Owner Renamed'}},cookie:r.cookie});assert.equal(changed.status,200);
 const claims=async scope=>{
  const grant=await r.authorize({scope}),tokens=await (await r.redeem(grant)).json();
  const keys=createLocalJWKSet(await (await r.call('/oidc/jwks')).json()),id=await jwtVerify(tokens.id_token,keys,{issuer:r.origin,audience:'app',currentDate:new Date(r.now)});
  const info=await (await r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}})).json();
  return {id:id.payload,info};
 };
 const full=await claims('openid email profile');assert.equal(full.info.name,'Owner Renamed');assert.equal(full.id.name,'Owner Renamed');
 const narrow=await claims('openid email');assert.equal(narrow.info.name,undefined);assert.equal(narrow.id.name,undefined);assert.equal(narrow.info.email,'owner@example.com');
 for(const body of [full.info,full.id,narrow.info,narrow.id])assert.equal(Object.keys(body).some(k=>/badge|x\./.test(k)),false);
});
