import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
import {samlInstall,addApp} from './saml-helpers.mjs';
import {emailSession} from './runtime.mjs';
import {signInAgain} from './agents-helpers.mjs';

const HOOK='https://hooks.example.com';
// The subscriber's endpoint at the network edge: scripted answers, then 200.
async function subscriber(t,r) {
 const received=[],script=[];
 const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  const step=script.shift();
  if(step==='hang')return;
  received.push({path:req.url,headers:req.headers,body,status:step?.status??200});
  res.writeHead(step?.status??200,step?.retryAfter?{'retry-after':String(step.retryAfter)}:{});res.end();
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 r.edges={[HOOK]:`http://127.0.0.1:${server.address().port}`};
 return {received,script,delivered:(path='/auth')=>received.filter(x=>x.status===200&&x.path.startsWith(path)).map(x=>JSON.parse(x.body))};
}
// Standard Webhooks verification, as a subscriber does it.
const verify=(secret,{headers,body})=>headers['webhook-signature'].split(' ').some(sig=>sig==='v1,'+createHmac('sha256',Buffer.from(secret.slice(6),'base64')).update(`${headers['webhook-id']}.${headers['webhook-timestamp']}.${body}`).digest('base64'));

test('joiner, mover and leaver events reach a subscriber signed, in order and once each, through 429, a timeout and an outage; rotation, replay and the cursor rebuild the history',async t=>{
 const r=await samlInstall(t),hook=await subscriber(t,r);
 for(const url of ['http://10.0.0.5/hook','https://127.0.0.1/hook','https://intranet.internal/hook'])assert.equal((await r.admin('events/subscribe',{url})).status,400);
 const created=await r.admin('events/subscribe',{url:`${HOOK}/auth?tenant=1`});assert.equal(created.status,201);
 const sub=await created.json();assert.match(sub.secret,/^whsec_/);
 const narrow=await (await r.admin('events/subscribe',{url:`${HOOK}/people`,types:['person.suspended']})).json();
 // Joiner: invited, then signs in.
 assert.equal((await r.admin('people/invite',{email:'dana@example.com',name:'Dana Day'})).status,201);
 await emailSession(r,'dana@example.com');
 // Mover: into a group that is assigned an app.
 const app=await addApp(r,{entityId:'https://crm.example.com',acsUrl:'https://crm.example.com/acs',assign:[]});
 const group=await (await r.admin('groups/create',{name:'Sales'})).json();
 await r.admin('groups/add',{groupId:group.id,email:'dana@example.com'});
 await r.admin('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id,role:'rep'});
 // Leaver: the first attempt meets a 429 with Retry-After.
 hook.script.push({status:429,retryAfter:60});
 const dana=await r.db.prepare("SELECT id FROM oa_operators WHERE email='dana@example.com'").first();
 assert.equal((await r.admin('people/suspend',{personId:dana.id})).status,200);
 const beforeInvite=(await r.mails()).length,invitedAudit=await r.db.prepare("SELECT count(*) AS n FROM auth_activity WHERE event='person_invited'").first();
 const repeated=await r.admin('people/invite',{email:'dana@example.com',name:'Dana Day'});assert.equal(repeated.status,409);assert.equal((await repeated.json()).error,'person_already_exists');
 assert.equal((await r.mails()).length,beforeInvite);assert.deepEqual(await r.db.prepare("SELECT count(*) AS n FROM auth_activity WHERE event='person_invited'").first(),invitedAudit);
 assert.equal((await r.db.prepare('SELECT status FROM oa_operators WHERE id=?').bind(dana.id).first()).status,'inactive');
 const types=()=>hook.delivered().filter(e=>e.subject.email==='dana@example.com'||e.type==='app.assigned').map(e=>e.type);
 assert.deepEqual(types(),['person.invited','person.activated','group.member_added','app.assigned']);
 const maintain=()=>r.call('/',{action:'maintain'});
 r.now+=61000;await maintain();
 assert.ok(types().includes('person.suspended'));
 for(const delivery of hook.received)assert.ok(verify(sub.secret,delivery)||verify(narrow.secret,delivery),'every delivery is signed');
 const leaver=hook.received.filter(x=>JSON.parse(x.body).type==='person.suspended');
 assert.equal(new Set(leaver.map(x=>x.headers['webhook-id'])).size,1,'a retry keeps the event ID');
 assert.ok(leaver.some(x=>x.status===429)&&leaver.filter(x=>x.status===200).length===2,'the narrow subscriber and the retry both arrived');
 // A timeout and an outage: the event waits, then arrives.
 hook.script.push('hang',{status:503},{status:503});
 await r.admin('groups/remove',{groupId:group.id,personId:dana.id});
 assert.ok(!types().includes('group.member_removed'));
 for(let i=0;i<3&&!types().includes('group.member_removed');i++){r.now+=86400000;await maintain();}
 assert.ok(types().includes('group.member_removed'));
 // Rotation: both secrets sign during the overlap, then only the new one.
 const rotated=await (await r.admin('events/rotate-secret',{id:sub.id,overlapHours:1})).json();
 await r.admin('groups/add',{groupId:group.id,personId:'ada'});
 const during=hook.received.at(-1);assert.ok(verify(sub.secret,during)&&verify(rotated.secret,during));
 // An hour later the owner proves their email again and makes another change.
 r.tick=()=>{r.now=Date.now()+3600001;};r.tick();r.owner=await signInAgain(r,r.owner,'owner@example.com');
 await r.admin('groups/remove',{groupId:group.id,personId:'ada'});
 const after=hook.received.at(-1);assert.ok(verify(rotated.secret,after));assert.ok(!verify(sub.secret,after));
 // The cursor: every event of the subscription's types, in order, resumable; the narrow key sees only its type.
 const read=(key,after=0,limit=100)=>r.call(`/api/auth/events?after=${after}&limit=${limit}`,{headers:{authorization:'Bearer '+key}});
 const all=await (await read(sub.readKey)).json();
 assert.deepEqual(all.events.map(e=>e.seq),[...all.events.map(e=>e.seq)].sort((a,b)=>a-b));
 assert.ok(all.events.every(e=>e.version===1&&e.id.startsWith('evt_')));
 const firstTwo=await (await read(sub.readKey,0,2)).json();assert.equal(firstTwo.hasMore,true);
 const rest=await (await read(sub.readKey,firstTwo.next)).json();
 assert.deepEqual([...firstTwo.events,...rest.events].map(e=>e.id),all.events.map(e=>e.id));
 assert.deepEqual((await (await read(narrow.readKey)).json()).events.map(e=>e.type),['person.suspended']);
 assert.equal((await read('evr_'+'x'.repeat(43))).status,401);
 assert.equal((await r.call('/api/auth/events',{cookie:r.owner.cookie})).status,401,'a session is not a read key');
 // Replay: the same event, with its original ID, again.
 const joined=all.events.find(e=>e.type==='person.invited');
 assert.equal((await r.admin('events/replay',{id:sub.id,seq:joined.seq})).status,200);
 const replayed=hook.received.at(-1);assert.equal(replayed.headers['webhook-id'],joined.id);assert.equal(JSON.parse(replayed.body).seq,joined.seq);
 // A stopped subscription receives nothing more, and its read key stops.
 assert.equal((await r.admin('events/disable',{id:sub.id})).status,200);const count=hook.received.length;
 await r.admin('groups/add',{groupId:group.id,personId:'bob'});
 assert.equal(hook.received.length,count);assert.equal((await read(sub.readKey)).status,401);
});
