import assert from 'node:assert/strict';
import {samlInstall,addApp} from './saml-helpers.mjs';
import {passkeyPerson,post,signInAgain} from './agents-helpers.mjs';
import {authenticate} from './webauthn.mjs';
import {cookieOf,emailSession} from './runtime.mjs';

const result=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
export async function reviewScopeFlow(t) {
 const r=await samlInstall(t),manager=await passkeyPerson(r,'manager','synthetic-auth-40@example.com','member');
 const included=await addApp(r,{name:'Synthetic scoped review app',entityId:'https://synthetic-auth-41.example.com',acsUrl:'https://synthetic-auth-41.example.com/acs',assign:['ada']}),excluded=await addApp(r,{name:'Synthetic excluded review app',entityId:'https://synthetic-auth-42.example.com',acsUrl:'https://synthetic-auth-42.example.com/acs',assign:['bob']});
 const change=async data=>{const preview=await result(await r.call('/api/auth/roles/preview',post(data,r.owner.cookie)));return result(await r.call('/api/auth/roles/apply',post({previewId:preview.previewId},r.owner.cookie)));};
 const definition=await change({kind:'role',role:{name:'Synthetic review coordinator',rank:12,permissions:['reviews.view','reviews.manage','reviews.export']}});
 const scope={view:{people:['ada','manager'],groups:[],apps:[included.id],cases:[]},edit:{people:['ada','manager'],groups:[],apps:[included.id],cases:[]}};
 const grant=await change({kind:'grant',personId:'manager',roleId:definition.plan.role.id,resources:scope});
 const create=(actor,reviewerId='manager')=>r.call('/api/auth/reviews/create',post({name:'Synthetic scoped quarterly review',reviewerId,periodStart:r.now-86400000,periodEnd:r.now,dueAt:r.now+3600000,intervalMonths:3},actor.cookie));
 const ordinary={...manager,cookie:cookieOf((await authenticate(r,manager.key)).response)};
 assert.equal((await create(ordinary)).status,403,'scoped review management requires session-local fresh email');
 const review=await result(await create(manager),201),model=await result(await r.call('/api/auth/reviews',{cookie:manager.cookie}));
 assert.equal(model.canManage,true);assert.deepEqual(model.apps.map(a=>a.id),[included.id]);assert.deepEqual(model.people.map(p=>p.id).sort(),['ada','manager']);
 const own=model.reviews.find(r=>r.id===review.id);assert.deepEqual(own.items.map(i=>[i.subject_id,i.app_id]),[['ada',included.id]]);
 assert.equal((await create(manager,'bob')).status,403,'a scoped coordinator cannot assign an out-of-scope reviewer');
 const global=await result(await create(r.owner,'owner'),201);
 assert.equal((await r.call('/api/auth/reviews/export?id='+global.id,{cookie:manager.cookie})).status,403,'export cannot hide the out-of-scope half of a campaign');
 const visible=(await result(await r.call('/api/auth/reviews',{cookie:manager.cookie}))).reviews.find(x=>x.id===global.id);
 assert.equal(visible.items.some(i=>i.app_id===excluded.id),false);
 const hidden=(await result(await r.call('/api/auth/reviews',{cookie:r.owner.cookie}))).reviews.find(x=>x.id===global.id).items.find(i=>i.app_id===excluded.id);
 assert.equal((await r.call('/api/auth/reviews/delegate',post({itemId:hidden.id,reviewerId:'ada',reason:'Outside scope'},manager.cookie))).status,403);
 const exported=await result(await r.call('/api/auth/reviews/export?id='+review.id,{cookie:manager.cookie}));assert.equal(exported.review.items.length,1);assert.equal(exported.review.items[0].app_id,included.id);
 const schedule=await r.db.prepare('SELECT * FROM auth_review_schedules WHERE id=?').bind(own.schedule_id).first();
 r.now=schedule.next_at;await r.call('/',{action:'maintain'});await r.restart();await r.call('/',{action:'maintain'});
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_reviews WHERE schedule_id=?').bind(schedule.id).first()).n,2,'scoped recurring campaigns survive restart without duplicates');
 await emailSession(r,'owner@example.com');r.owner=await signInAgain(r,r.owner,'owner@example.com');
 await change({kind:'revoke',grantId:grant.plan.id});
 r.now+=100*86400000;await r.call('/',{action:'maintain'});
 assert.equal((await r.db.prepare('SELECT enabled FROM auth_review_schedules WHERE id=?').bind(schedule.id).first()).enabled,0,'losing review authority stops the next snapshot');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_reviews WHERE schedule_id=?').bind(schedule.id).first()).n,2);
}
