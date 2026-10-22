import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {openRuntime} from './runtime.mjs';
import {passkeyPerson,signInAgain,post} from './agents-helpers.mjs';
import {decide} from './access-decisions-flow.mjs';

const checked=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
const isReminder=m=>m.subject.startsWith('Auth access review');

export async function reviewRemindersFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-06T14:00:00Z');
 const ids={owner:'synthetic-auth-201',reviewer:'synthetic-auth-202',subject:'synthetic-auth-203',alternate:'synthetic-auth-204',admin:'synthetic-auth-205'};
 const address=id=>id+'@example.com';
 let owner=await passkeyPerson(r,ids.owner,address(ids.owner),'owner');
 let reviewer=await passkeyPerson(r,ids.reviewer,address(ids.reviewer),'member');
 await passkeyPerson(r,ids.subject,address(ids.subject),'member');
 let alternate=await passkeyPerson(r,ids.alternate,address(ids.alternate),'member');
 await passkeyPerson(r,ids.admin,address(ids.admin),'admin');
 const admin=async(path,data,status=200)=>checked(await r.call('/api/auth/'+path,post(data,owner.cookie)),status);
 const fresh=async()=>{owner=await signInAgain(r,owner,address(ids.owner));};
 const maintain=()=>r.call('/',{action:'maintain'}).then(response=>checked(response));
 const read=()=>r.call('/api/auth/reviews',{cookie:owner.cookie}).then(response=>checked(response));
 const mails=async()=>(await r.mails()).filter(isReminder);
 const app=await admin('company-apps/create',{name:'Review reminder fixture',entityId:'https://review.example.com',acsUrl:'https://review.example.com/acs'},201);
 await admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:ids.subject,role:'reader'});
 const create=async(name,dueAt)=>admin('reviews/create',{name,reviewerId:ids.reviewer,periodStart:r.now-86400000,periodEnd:r.now,dueAt},201);
 const item=async id=>(await read()).reviews.find(review=>review.id===id).items[0];
 const certify=async(actor,target)=>checked(await decide(r,actor,{kind:'review',targetId:target.id,operation:'certify',reason:'The assigned access is still required'}));
 const settings={confirm:true,enabled:true,calendar:{timezone:'America/New_York',weekdays:[1,2,3,4,5],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:5,recipients:['decider'],escalationRecipients:[ids.owner,ids.admin],escalation:'repeat_until_resolved'};

 const silent=await create('Without consent',r.now+14*86400000),silentItem=await item(silent.id);
 // Age only the source fixture; all consent, delegation and decisions use
 // their normal authenticated public handlers.
 await r.db.prepare('UPDATE auth_reviews SET created_at=? WHERE id=?').bind(r.now-3*86400000,silent.id).run();
 await maintain();assert.deepEqual(await mails(),[],'a due open review has no implicit reminder consent');
 await admin('followup/settings',{...settings,enabled:false});await maintain();
 assert.deepEqual(await mails(),[],'a saved disabled parent policy remains silent');
 await certify(reviewer,silentItem);
 const review=await create('Weekend and DST review',Date.parse('2026-03-12T13:00:00Z'));
 const target=await item(review.id);
 await admin('followup/settings',settings);
 r.now=Date.parse('2026-03-07T14:00:00Z');await maintain();assert.deepEqual(await mails(),[],'weekend has no business reminder');
 r.now=Date.parse('2026-03-09T12:59:00Z');await r.restart();await maintain();assert.deepEqual(await mails(),[],'DST-adjusted Monday 09:00 has not arrived');
 r.now+=60000;await Promise.all([maintain(),maintain()]);
 let sent=await mails();assert.deepEqual(sent.map(m=>m.to),[address(ids.reviewer)],'the current reviewer receives one reminder at Monday 09:00 EDT');
 await r.restart();await maintain();assert.equal((await mails()).length,1,'a persisted occurrence cannot duplicate across concurrent cron or restart');
 await fresh();await admin('reviews/delegate',{itemId:target.id,reviewerId:ids.alternate,reason:'Alternate now holds the decision'});
 await maintain();assert.equal((await mails()).length,1,'delegation does not replay the consumed business occurrence');
 r.now=Date.parse('2026-03-10T13:00:00Z');await fresh();
 await admin('followup/settings',{...settings,recipients:[ids.owner]});await maintain();
 assert.equal((await mails()).length,1,'named administrator consent does not silently authorize reviewer reminders');
 await admin('followup/settings',settings);await maintain();
 assert.deepEqual((await mails()).map(m=>m.to),[address(ids.reviewer),address(ids.alternate)],'the next occurrence follows the live delegated reviewer');

 await fresh();await admin('people/suspend',{personId:ids.alternate});
 await admin('people/role',{personId:ids.admin,role:'member'});
 r.now=Date.parse('2026-03-11T13:00:00Z');await maintain();
 sent=await mails();assert.deepEqual(sent.slice(2).map(m=>[m.to,m.subject]),[[address(ids.owner),'Auth access review reviewer unavailable']],'suspension and lost administrator role exclude both former recipients');
 await fresh();await admin('people/role',{personId:ids.admin,role:'admin'});
 await admin('followup/settings',{...settings,escalationRecipients:[ids.admin]});
 r.now=Date.parse('2026-03-12T13:00:00Z');await maintain();
 sent=await mails();assert.deepEqual(sent.slice(3).map(m=>[m.to,m.subject]),[[address(ids.admin),'Auth access review is overdue']],'overdue escalation uses only currently approved active administrators');
 await fresh();const pending=await item(review.id);assert.equal(pending.decision,null,'mail provider acknowledgment does not decide the review');
 await fresh();await admin('reviews/delegate',{itemId:target.id,reviewerId:ids.reviewer,reason:'Active reviewer will complete the review'});
 reviewer=await signInAgain(r,reviewer,address(ids.reviewer));await certify(reviewer,target);
 const completedCount=(await mails()).length;r.now=Date.parse('2026-03-13T13:00:00Z');await r.restart();await maintain();
 assert.equal((await mails()).length,completedCount,'a completed decision remains silent after restart');
 await fresh();
 const exported=await checked(await r.call('/api/auth/reviews/export?id='+review.id,{cookie:owner.cookie}));
 assert.ok(exported.events.some(e=>e.event==='review_reminder_accepted'));
 assert.ok(exported.events.some(e=>e.event==='review_escalation_accepted'));
 for(const event of exported.events.filter(e=>e.event.startsWith('review_')))assert.doesNotMatch(event.detail,/@|access_token|[?&]token=|[?&]code=/i,'reminder history stores no addresses or credentials');
 for(const message of await mails()) {
  assert.doesNotMatch(message.text,/authprep_|client_assertion|access_token|[?&]token=|[?&]code=/i);
  assert.deepEqual(message.text.match(/https?:\/\/\S+/g),[r.origin+(message.to===address(ids.owner)||message.to===address(ids.admin)?'/app/activity':'/app/account')]);
 }

 // Hold the actual mail network edge after accepting a reminder, dispose the
 // Worker before an ACK, and prove the uncertain occurrence is never retried.
 await fresh();await admin('followup/settings',{...settings,escalationRecipients:[ids.owner]});
 const uncertain=await create('Interrupted transport',r.now+14*86400000);
 let arrived,handle;const accepted=new Promise(resolve=>{arrived=resolve;});
 const transported=[];
 const server=createServer(async(request,response)=>{
  try {let body='';for await(const chunk of request)body+=chunk;await handle(JSON.parse(body),response);}
  catch {response.statusCode=500;response.end('edge failure');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 r.mailEdge='http://127.0.0.1:'+server.address().port;
 handle=async(message,response)=>{if(!isReminder(message)){response.end('accepted');return;}transported.push(message);arrived();};
 r.now=Date.parse('2026-03-16T13:00:00Z');const interrupted=maintain().catch(()=>null);await accepted;
 await r.restart();await interrupted;
 handle=async(message,response)=>{if(isReminder(message))transported.push(message);response.end('accepted');};
 await maintain();assert.equal(transported.length,1,'transport accepted without ACK is never retried after Worker restart');
 await fresh();
 const uncertainExport=await checked(await r.call('/api/auth/reviews/export?id='+uncertain.id,{cookie:owner.cookie}));
 assert.ok(uncertainExport.events.some(e=>e.event==='review_reminder_dispatching'));
 assert.equal(uncertainExport.review.items[0].decision,null);
}
