import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
import {post} from './agents-helpers.mjs';

// A security owner's explicitly subscribed receiver is the network edge.
// Auth's real event queue, signing, cursor and replay remain in the product.
export async function securityReceiver(t,r,owner) {
 const attempts=[];let failing=true;
 const server=createServer(async(request,response)=>{
  let body='';for await(const part of request)body+=part;
  attempts.push({headers:request.headers,body,delivered:!failing});response.writeHead(failing?503:200);response.end();
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));
 t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 const endpoint='https://security.example.com';r.edges={[endpoint]:`http://127.0.0.1:${server.address().port}`};
 const response=await r.call('/api/auth/events/subscribe',post({url:endpoint+'/recovery',types:['recovery.requested','recovery.approved','recovery.cancelled','recovery.completed']},owner.cookie));
 assert.equal(response.status,201);const subscription=await response.json();
 const events=async()=>{
  const response=await r.call('/api/auth/events',{headers:{authorization:'Bearer '+subscription.readKey}});assert.equal(response.status,200);return (await response.json()).events;
 };
 return {
  events,
  async resume(recoveryId) {
   const event=(await events()).find(e=>e.type==='recovery.requested'&&e.data.recovery===recoveryId);assert.ok(event,'the security-owner notice survives restart in its public cursor');
   failing=false;
   assert.equal((await r.call('/api/auth/events/replay',post({id:subscription.id,seq:event.seq},owner.cookie))).status,200);
   const delivered=attempts.filter(a=>a.delivered&&a.headers['webhook-id']===event.id);assert.equal(delivered.length,1);
  },
  async assertDelivered(recoveryId,types) {
   const delivered=attempts.filter(a=>a.delivered),events=delivered.map(a=>JSON.parse(a.body));
   for(const type of types)assert.ok(events.some(e=>e.type===type&&e.data.recovery===recoveryId),'security owner receives '+type);
   for(const attempt of delivered) {
    const signature='v1,'+createHmac('sha256',Buffer.from(subscription.secret.slice(6),'base64')).update(`${attempt.headers['webhook-id']}.${attempt.headers['webhook-timestamp']}.${attempt.body}`).digest('base64');
    assert.ok(attempt.headers['webhook-signature'].split(' ').includes(signature),'security notifications are signed');
    for(const credential of [subscription.secret,subscription.readKey,owner.cookie])assert.equal(attempt.body.includes(credential),false,'notifications contain no credentials');
   }
  },
 };
}
