import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {generateKeyPairSync,sign} from 'node:crypto';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {passkeyPerson} from './agents-helpers.mjs';

async function deliveryRuntime(t) {
 const r=await openRuntime();t.after(()=>r.close());r.mailProvider='development';
 const owner=await passkeyPerson(r,'synthetic-auth-1','owner@example.com','owner');
 await r.person('synthetic-auth-2','employee@example.com');
 const member=await emailSession(r,'employee@example.com'),sent=[];
 const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 r.sendgridWebhookKey=keys.publicKey.export({type:'spki',format:'der'}).toString('base64');
 r.mailProvider='sendgrid';r.transportStatus='accepted';
 const server=createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;sent.push(JSON.parse(body));if(r.transportStatus==='unavailable'){res.writeHead(503);res.end();}else{res.setHeader('content-type','application/json');res.end(JSON.stringify({status:r.transportStatus,provider:'sendgrid'}));}});
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 r.mailEdge='http://127.0.0.1:'+server.address().port;
 const read=async()=>{const response=await r.call('/api/auth/delivery',{cookie:owner.cookie});assert.equal(response.status,200,await response.clone().text());return response.json();};
 const request=async(address='employee@example.com')=>r.call('/auth/identity/email/request',{method:'POST',data:{email:address}});
 const webhook=async(events,{bad=false,path='/api/auth/delivery/sendgrid'}={})=>{
  const body=JSON.stringify(events),timestamp=String(Math.floor(r.now/1000)),signature=sign('sha256',Buffer.from(timestamp+body),keys.privateKey).toString('base64');
  return r.call(path,{method:'POST',form:undefined,data:events,headers:{'x-twilio-email-event-webhook-timestamp':timestamp,'x-twilio-email-event-webhook-signature':bad?'invalid':signature}});
 };
 const event=(message,type,id)=>({event:type,sg_event_id:id,email:message.to,timestamp:Math.floor(r.now/1000),rer_delivery_id:message.deliveryId,rer_product:'auth'});
 return {r,owner,member,sent,read,request,webhook,event};
}

export async function deliveryReconciliation(t) {
 const {r,owner,member,sent,read,request,webhook,event}=await deliveryRuntime(t);
 assert.equal((await r.call('/api/auth/delivery')).status,401);
 assert.equal((await r.call('/api/auth/delivery',{cookie:member})).status,403);
 assert.equal((await request()).status,202);assert.equal(sent.length,1);
 const message=sent[0],accepted=(await read()).attempts.find(item=>item.id===message.deliveryId);assert.equal(accepted.state,'accepted');
 assert.equal((await r.call('/api/auth/me')).status,401,'provider acceptance never creates identity proof');
 const delivered=event(message,'delivered','synthetic-auth-1');
 assert.equal((await webhook([delivered],{bad:true})).status,401);
 assert.equal((await read()).attempts.find(item=>item.id===message.deliveryId).state,'accepted');
 assert.equal((await webhook([delivered,{sg_event_id:'synthetic-auth-2',timestamp:-1}])).status,400,'whole invalid batch refuses before writes');
 assert.equal((await read()).attempts.find(item=>item.id===message.deliveryId).state,'accepted');
 const organization=await r.call('/api/auth/organizations/create',{method:'POST',cookie:owner.cookie,data:{name:'Other employer'}});assert.equal(organization.status,201);
 const orgId=(await organization.json()).id;
 assert.equal((await webhook([delivered],{path:'/org/'+orgId+'/api/auth/delivery/sendgrid'})).status,200);
 assert.equal((await read()).attempts.find(item=>item.id===message.deliveryId).state,'accepted','other employer cannot reconcile this claim');
 assert.equal((await webhook([{...delivered,email:'other@example.com'}])).status,200);
 assert.equal((await read()).attempts.find(item=>item.id===message.deliveryId).state,'accepted','wrong recipient cannot reconcile a claim');
 assert.equal((await webhook([delivered])).status,200);assert.equal((await webhook([delivered])).status,200);
 assert.equal((await read()).attempts.find(item=>item.id===message.deliveryId).state,'delivered');
 assert.equal((await webhook([{...delivered,event:'bounce'}])).status,409,'event identity cannot be repurposed');
 // A delayed bounce can omit the provider message ID. The opaque delivery
 // claim and exact recipient remain sufficient authenticated attribution.
 const bounce=event(message,'bounce','synthetic-auth-3');
 assert.equal((await webhook([bounce])).status,200);
 assert.equal((await webhook([event(message,'processed','synthetic-auth-4')])).status,200);
 let state=await read();assert.equal(state.attempts.find(item=>item.id===message.deliveryId).state,'bounced');assert.equal(state.suppressed,1);
 await r.restart();assert.equal((await request()).status,202);assert.equal(sent.length,1,'durable suppression prevents another external send');
 state=await read();assert.equal(state.attempts[0].state,'suppressed');
 const token=new URL(message.text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 for(const path of ['/api/auth/delivery','/api/auth/activity','/api/auth/reports/mfa-enrollment?format=csv']) {
  const response=await r.call(path,{cookie:owner.cookie});assert.equal(response.status,200);
  const text=await response.text();assert.ok(!text.includes(token));assert.ok(!text.includes(message.text));assert.ok(!text.includes(r.sendgridWebhookKey));
 }
 // Delivery records participate in the existing authorized person erasure,
 // including the keyed suppression digest and all provider event evidence.
 const erase=async(path,data)=>{const response=await r.call('/api/auth/erasure/'+path,{method:'POST',cookie:owner.cookie,data});assert.equal(response.status,200,await response.clone().text());return response.json();};
 await erase('policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const preview=await erase('preview',{kind:'person',target:'synthetic-auth-2'});
 for(const store of ['auth_mail_deliveries','auth_mail_events','auth_mail_suppressions'])assert.ok(preview.stores.some(item=>item.store===store&&item.deleted>0),'person erasure includes '+store);
 const erased=await erase('confirm',{previewId:preview.id,confirmation:'ERASE',destinations:[]});assert.equal(erased.local,'complete');
 const afterErasure=await read();assert.equal(afterErasure.suppressed,0);assert.ok(afterErasure.attempts.every(item=>item.id!==message.deliveryId));
 assert.equal((await webhook([bounce])).status,200);assert.equal((await read()).suppressed,0,'late evidence cannot recreate erased person data');

}

export async function deliveryFailures(t) {
 const {r,owner,sent,read,request}=await deliveryRuntime(t);
 const post=(path,data)=>r.call('/api/auth/'+path,{method:'POST',cookie:owner.cookie,data});
 const invited=await post('organizations/invite',{email:'hire@example.com',name:'New employee'});assert.equal(invited.status,201);
 const personId=(await invited.json()).id;
 for(const [status,expected] of [['rate_limited','rate_limited'],['rejected','rejected'],['uncertain','uncertain'],['unavailable','uncertain']]) {
  r.now+=60001;r.transportStatus=status;
  assert.equal((await request('hire@example.com')).status,202,'sign-in keeps its non-enumerating answer');
  const message=sent.at(-1),state=(await read()).attempts.find(item=>item.id===message.deliveryId);assert.equal(state.state,expected);
  assert.equal((await r.call('/api/auth/me')).status,401);
  const obligations=await(await r.call('/api/auth/followup',{cookie:owner.cookie})).json();
  assert.ok(obligations.obligations.some(item=>item.source_id===personId&&item.state==='open'),'mail failure never completes employee enrollment');
 }
 // Reissuing an invitation exercises the common recipient throttle through
 // its real administrative door, independent of sign-in's tighter limiter.
 r.transportStatus='accepted';r.now+=60001;let limited=false;
 for(let i=0;i<100;i++) {
  const before=sent.length,response=await post('organizations/invite',{email:'limit@example.com',name:'Invited employee'});
  if(response.status===503) {
   assert.equal(sent.length,before,'local refusal never reaches the provider');
   const state=await read();assert.equal(state.attempts[0].state,'rate_limited');
   assert.equal(state.attempts[0].error,'local_rate_limit');limited=true;break;
  }
  assert.equal(response.status,201,await response.clone().text());
 }
 assert.ok(limited,'repeated invitation sends reach a durable local limit');
 const before=sent.length;await r.restart();await r.call('/',{action:'maintain'});assert.equal(sent.length,before,'unknown sends are never replayed on restart');
}
