import assert from 'node:assert/strict';
import ssh2 from 'ssh2';
import {createHash} from 'node:crypto';
import {openRuntime} from './runtime.mjs';
import {passkeyPerson,signInAgain,post} from './agents-helpers.mjs';
import {submitRequest,decide} from './access-decisions-flow.mjs';
const checked=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};

export async function followupDecisionsFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-06T14:00:00Z');
 let owner=await passkeyPerson(r,'synthetic-auth-401','synthetic-auth-401@example.com','owner');
 let decider=await passkeyPerson(r,'synthetic-auth-402','synthetic-auth-402@example.com','member');
 let employee=await passkeyPerson(r,'synthetic-auth-403','synthetic-auth-403@example.com','member');
 let alternate=await passkeyPerson(r,'synthetic-auth-405','synthetic-auth-405@example.com','member');
 const fresh=async()=>{owner=await signInAgain(r,owner,'synthetic-auth-401@example.com');};
 const admin=async(path,data,status=200)=>checked(await r.call('/api/auth'+path,post(data,owner.cookie)),status);
 const read=async actor=>checked(await r.call('/api/auth/followup',{cookie:(actor??owner).cookie}));
 const maintain=()=>r.call('/',{action:'maintain'}).then(checked);
 const messages=async()=>(await r.mails()).filter(m=>m.subject.startsWith('Auth follow-up')||m.subject.startsWith('Auth access review'));
 const app=await admin('/company-apps/create',{name:'Business approval fixture',entityId:'https://approval.example.com',acsUrl:'https://approval.example.com/acs'},201);
 await admin('/decisions/privilege',{kind:'app',targetId:app.id,privileged:false});
 await admin('/requests/policy',{appId:app.id,deciderId:'synthetic-auth-402',maxDurationMs:3600000});
 const request=await checked(await submitRequest(r,employee,{appId:app.id,purpose:'Time-limited project work',role:'reader',durationMs:3600000}),201);
 const cancelled=await checked(await submitRequest(r,alternate,{appId:app.id,purpose:'Alternate shift request',role:'reader',durationMs:3600000}),201);
 await admin('/company-apps/assign',{appId:app.id,principalType:'person',principalId:'synthetic-auth-403',role:'reader'});
 const review=await admin('/reviews/create',{name:'Weekend access review',reviewerId:'synthetic-auth-402',periodStart:r.now-86400000,periodEnd:r.now,dueAt:Date.parse('2026-03-06T16:00:00Z')},201);
 const target=(await checked(await r.call('/api/auth/reviews',{cookie:owner.cookie}))).reviews.find(v=>v.id===review.id).items[0];
 const key=ssh2.utils.generateKeyPairSync('ed25519');
 const fingerprint='SHA256:'+createHash('sha256').update(ssh2.utils.parseKey(key.public).getPublicSSH()).digest('base64').replace(/=+$/,'');
 const feed=await admin('/hr-feeds/create',{name:'Freshness follow-up fixture',schedule:'hourly',fingerprint,mapping:{sourceId:'ID',email:'Email',state:'State',effectiveAt:'Effective'},confirm:true},201);
 const settings={confirm:true,enabled:true,calendar:{timezone:['America','New_York'].join('/'),weekdays:[1,2,3,4,5],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:2,recipients:['decider'],escalationRecipients:['synthetic-auth-401'],escalation:'repeat_until_resolved'};
 await admin('/followup/settings',settings);
 r.now=Date.parse('2026-03-06T17:00:00Z');await fresh();let view=await read();
 const hr=view.obligations.find(v=>v.kind==='hr_file_feed'),req=view.obligations.find(v=>v.source_id==='access-request:'+request.id),rev=view.obligations.find(v=>v.source_id==='review-item:'+target.id);
 assert.ok(hr&&req&&rev);assert.equal((await checked(await r.call('/api/auth/reviews',{cookie:owner.cookie}))).reviews.find(v=>v.id===review.id).overdue,true,'review is already overdue before the weekend and restart');assert.equal(hr.canSend,false,'source registration supplies no outbound reminder consent');
 assert.deepEqual((await read(employee)).obligations.filter(v=>['access_request','review_item'].includes(v.kind)),[],'request subjects cannot read the decider follow-up or history');
 r.now=Date.parse('2026-03-07T14:00:00Z');await maintain();assert.deepEqual(await messages(),[]);
 r.now=Date.parse('2026-03-09T12:59:00Z');await r.restart();await maintain();assert.deepEqual(await messages(),[]);
 r.now+=60000;await Promise.all([maintain(),maintain()]);
 let sent=await messages();assert.equal(sent.filter(m=>m.to==='synthetic-auth-402@example.com').length,2,'both pending requests remind their current decider once');
 assert.equal(sent.filter(m=>m.to==='synthetic-auth-401@example.com').length,1,'the overdue review escalates to the approved owner');assert.equal(sent.filter(m=>m.text.includes(hr.id)).length,0,'stale source never inherits reviewer or administrator reminder consent');
 await fresh();await admin('/followup/settings',{...settings,recipients:['decider','source_owner']});await maintain();
 sent=await messages();assert.equal(sent.filter(m=>m.text.includes(hr.id)).length,1,'explicit source-owner duty permits exactly one freshness reminder');
 await r.restart();await maintain();assert.equal((await messages()).length,sent.length,'restart retains each consumed occurrence');
 r.now=Date.parse('2026-03-10T13:00:00Z');await fresh();await maintain();
 view=await read();for(const id of [req.id,rev.id,hr.id])assert.ok(view.history.some(e=>e.obligation_id===id&&['escalation_accepted','review_escalation_accepted'].includes(e.event)),'each overdue source retains escalation evidence');
 // Complete, cancel and refresh through the source doors. A reminder never
 // changes access or substitutes for the decision proof.
 decider=await signInAgain(r,decider,'synthetic-auth-402@example.com');employee=await signInAgain(r,employee,'synthetic-auth-403@example.com');
 await checked(await decide(r,decider,{kind:'request',targetId:request.id,operation:'deny',reason:'Project access is no longer needed'}));
 await checked(await r.call('/api/auth/requests/cancel',post({id:cancelled.id},(await signInAgain(r,alternate,'synthetic-auth-405@example.com')).cookie)));
 await checked(await decide(r,decider,{kind:'review',targetId:target.id,operation:'certify',reason:'The standing read access remains required'}));
 await admin('/hr-feeds/upload',{feedId:feed.id,fileName:'fresh.csv',text:'ID,Email,State,Effective\nsynthetic-auth-404,synthetic-auth-404@example.com,active,'+new Date(r.now-1000).toISOString()+'\n'},202);
 view=await read();assert.equal(view.obligations.find(v=>v.id===req.id).state,'completed');assert.equal(view.obligations.find(v=>v.id===rev.id).state,'completed');assert.equal(view.obligations.find(v=>v.id===hr.id).state,'completed');assert.equal(view.obligations.find(v=>v.source_id==='access-request:'+cancelled.id).state,'cancelled');
 const before=(await messages()).length;await r.restart();await maintain();assert.equal((await messages()).length,before,'resolved sources remain silent after restart');
 for(const id of [req.id,rev.id,hr.id])assert.ok(view.history.some(e=>e.obligation_id===id&&e.event==='completed'));
 // Early review send consumes one scheduled occurrence, even if requested
 // again before its due date. Other holders gain no reminder authority.
 await fresh();const early=await admin('/reviews/create',{name:'Early review reminder',reviewerId:'synthetic-auth-402',periodStart:r.now-86400000,periodEnd:r.now,dueAt:r.now+14*86400000},201);
 const earlyItem=(await checked(await r.call('/api/auth/reviews',{cookie:owner.cookie}))).reviews.find(v=>v.id===early.id).items[0];
 const earlyOb=(await read(decider)).obligations.find(v=>v.source_id==='review-item:'+earlyItem.id);assert.equal(earlyOb.canSend,true);
 await checked(await r.call('/api/auth/followup/send',post({id:earlyOb.id},employee.cookie)),403);
 const earlyMessages=async()=>(await messages()).filter(m=>m.text.includes(early.id));
 await checked(await r.call('/api/auth/followup/send',post({id:earlyOb.id},decider.cookie)));
 assert.equal((await earlyMessages()).length,1);await checked(await r.call('/api/auth/followup/send',post({id:earlyOb.id},decider.cookie)));assert.equal((await earlyMessages()).length,1);
 await r.restart();await maintain();assert.equal((await earlyMessages()).length,1);
 r.now=Date.parse('2026-03-11T13:00:00Z');await maintain();assert.equal((await earlyMessages()).length,1,'early review occurrence is not repeated when due');
 // A changed request policy expires the previous approval authority. A
 // source holder who loses administration receives no freshness mail.
 await fresh();employee=await signInAgain(r,employee,'synthetic-auth-403@example.com');
 const staleRequest=await checked(await submitRequest(r,employee,{appId:app.id,purpose:'Changed approval policy',role:'reader',durationMs:3600000}),201);
 const staleOb=(await read()).obligations.find(v=>v.source_id==='access-request:'+staleRequest.id);
 await admin('/requests/policy',{appId:app.id,deciderId:'synthetic-auth-401',maxDurationMs:3600000});
 assert.equal((await read()).obligations.find(v=>v.id===staleOb.id).state,'expired');
 const custodian=await passkeyPerson(r,'synthetic-auth-406','synthetic-auth-406@example.com','admin');
 const held=await checked(await r.call('/api/auth/hr-feeds/create',post({name:'Scoped source custodian',schedule:'hourly',fingerprint,mapping:{sourceId:'ID',email:'Email',state:'State',effectiveAt:'Effective'},confirm:true},custodian.cookie)),201);
 r.now+=3*3600000;await fresh();
 const heldOb=(await read()).obligations.find(v=>v.source_id.startsWith('hr-feed:'+held.id+':'));
 assert.ok(heldOb);await admin('/people/role',{personId:'synthetic-auth-406',role:'member'});
 r.now=Date.parse('2026-03-12T13:00:00Z');await r.restart();await maintain();await fresh();
 const lost=(await read()).history.filter(v=>v.obligation_id===heldOb.id);
 assert.ok(lost.some(v=>v.event==='recipient_recheck_failed'));assert.ok(lost.some(v=>v.event==='escalation_accepted'));
 assert.equal((await messages()).filter(m=>m.to==='synthetic-auth-406@example.com').length,0);
 for(const mail of await messages())assert.doesNotMatch(mail.text,/access_token|client_assertion|[?&]token=|[?&]code=/i);
}
