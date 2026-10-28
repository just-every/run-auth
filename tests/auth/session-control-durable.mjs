import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createLocalJWKSet,jwtVerify,decodeJwt} from 'jose';
import {samlInstall} from './saml-helpers.mjs';
import {command,operations,credentialsState,identityState} from './session-control-helpers.mjs';
import {client} from './session-control-clients.mjs';
import {signInAgain} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';

export async function durableSessionControl(t) {
 const r=await samlInstall(t),received=[];let retryStatus=503;
 const edge=createServer(async(req,res)=>{
  let body='';for await(const part of req)body+=part;
  received.push({path:req.url,token:new URLSearchParams(body).get('logout_token')});
  res.writeHead(req.url==='/retry'?retryStatus:req.url==='/refused'?400:200);res.end();
 });
 await new Promise(done=>edge.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>edge.close(done)));
 r.edges={'https://sessions.example.com':`http://127.0.0.1:${edge.address().port}`};
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const offline=await client(r,r.owner.cookie,r.ada,'Field devices',{logout:'retry',offline:true});
 const first=await offline.connect('Employee phone'),second=await offline.connect('Employee tablet');
 const unavailable=await client(r,r.owner.cookie,r.ada,'Offline-only client',{offline:true});
 const third=await unavailable.connect('No logout endpoint');
 const refused=await client(r,r.owner.cookie,r.ada,'Refusing relying party',{logout:'refused'});
 const delivered=await client(r,r.owner.cookie,r.ada,'Acknowledging relying party',{logout:'accepted'});
 const userinfo=app=>r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+app.tokens.access_token}});
 for(const app of [refused,delivered])assert.equal((await userinfo(app)).status,200);
 for(const device of [first,second,third])assert.equal((await device.check()).allowed,true);
 const beforeIdentity=await identityState(r,'ada'),before=await credentialsState(r,'ada');
 const reason='Employee asked help desk to end access on lost devices';
 // A storage failure after the queue inserts must leave no partial operation,
 // revocation or delivery. The next real requests must still work.
 await r.db.exec("CREATE TRIGGER synthetic_auth_session_control_failure BEFORE UPDATE ON auth_refresh_families WHEN OLD.person_id='ada' BEGIN SELECT RAISE(ABORT,'synthetic-auth-1'); END;");
 const failed=await r.call('/api/auth/roles/end-sessions',{method:'POST',cookie:r.owner.cookie,data:{personId:'ada',reason}});
 assert.equal(failed.status,500,await failed.clone().text());
 assert.deepEqual(await credentialsState(r,'ada'),before,'transaction failure rolls back sessions, families and both delivery queues');
 assert.deepEqual(await operations(r,r.owner.cookie,'ada'),[]);assert.equal(received.length,0,'rollback never starts a remote delivery');
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,200);
 for(const device of [first,second,third])assert.equal((await device.check()).allowed,true);
 await r.db.exec('DROP TRIGGER synthetic_auth_session_control_failure');
 // A current refresh token is live immediately before the successful action.
 const live=await first.sdk.refresh();assert.notEqual(live.refresh_token,first.tokens.refresh_token);
 const result=await command(r,r.owner.cookie,'/api/auth/roles/end-sessions',{personId:'ada',reason});
 assert.equal(result.ok,true);assert.equal(result.refreshGrantsEnded,3);assert.ok(result.nativeSessionsEnded>0);
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);
 for(const app of [refused,delivered])assert.equal((await userinfo(app)).status,401,'the next UserInfo request refuses its old token');
 for(const device of [first,second,third]) {
  await assert.rejects(device.check(),error=>error.status===401,'the next resource request refuses ended offline authority');
  await assert.rejects(device.sdk.refresh(),error=>error.status===400||error.status===401,'the next token request refuses every ended refresh family');
 }
 assert.deepEqual(await identityState(r,'ada'),beforeIdentity,'ending refresh sessions preserves app assignments and active person state');
 const receipt=(await operations(r,r.owner.cookie,'ada')).find(op=>op.id===result.operationId);
 assert.equal(receipt.actorId,'owner');assert.equal(receipt.reason,reason);
 assert.equal(receipt.refreshGrantsEnded,result.refreshGrantsEnded);assert.equal(receipt.nativeSessionsEnded,result.nativeSessionsEnded);
 assert.ok(receipt.logout.pending>0,'5xx deliveries remain pending for retry');
 assert.ok(receipt.logout.failed>0,'a permanent remote refusal remains failed');
 assert.ok(receipt.logout.delivered>0,'a successful remote acknowledgment is reported as delivered');
 assert.ok(receipt.logout.unavailable>0,'an app without a logout endpoint is explicit');
 const keys=createLocalJWKSet(await (await r.call('/oidc/jwks')).json());
 for(const {token,path} of received) {
  const {payload,protectedHeader}=await jwtVerify(token,keys,{issuer:r.origin,currentDate:new Date(r.now)});
  assert.equal(protectedHeader.typ,'logout+jwt');assert.ok(payload.sid);assert.ok(payload.events['http://schemas.openid.net/event/backchannel-logout']);
  assert.equal(payload.aud,path==='/retry'?offline.clientId:path==='/refused'?refused.clientId:delivered.clientId);
 }
 const retryTokens=received.filter(item=>item.path==='/retry').map(item=>decodeJwt(item.token));
 for(const id of [first.tokens.grant_id,second.tokens.grant_id])assert.ok(retryTokens.some(payload=>payload.sid===id),'each offline device has a family-bound logout');
 await r.restart();
 const restarted=(await operations(r,r.owner.cookie,'ada')).find(op=>op.id===result.operationId);
 assert.deepEqual(restarted,receipt,'restart preserves the accountable operation and each delivery outcome');
 assert.equal((await r.call('/api/auth/me',{cookie:r.ada})).status,401);
 const pendingCount=receipt.logout.pending,retryJtis=new Set(retryTokens.map(token=>token.jti));
 retryStatus=200;r.now+=61000;
 const maintenance=await r.call('/',{action:'maintain'});assert.equal(maintenance.status,200,await maintenance.clone().text());
 const retried=(await operations(r,r.owner.cookie,'ada')).find(op=>op.id===result.operationId);
 assert.equal(retried.logout.pending,0);assert.equal(retried.logout.delivered,receipt.logout.delivered+pendingCount);
 assert.equal(retried.logout.failed,receipt.logout.failed);assert.equal(retried.logout.unavailable,receipt.logout.unavailable);
 for(const item of received.filter(item=>item.path==='/retry').slice(retryTokens.length))assert.ok(retryJtis.has(decodeJwt(item.token).jti),'durable retries keep each delivery identity');
 // Authentication queues can expire before the accountable operation. Run the
 // actual consent, preview and scheduled cleanup, then read the retained receipt.
 const day=86400000,classes=Object.fromEntries(['profiles','sourceSnapshots','authentication','decisions','provisioning','audit','modelTraces','erasureReceipts'].map(name=>[name,{unit:'days',value:name==='authentication'?90:2555}]));
 // Age the actual completed deliveries independently of unrelated session stores.
 await r.db.prepare('UPDATE auth_oidc_logouts SET finished_at=? WHERE id LIKE ? AND finished_at IS NOT NULL').bind(r.now-91*day,result.operationId+':%').run();
 await command(r,r.owner.cookie,'/api/auth/retention/settings',{confirm:true,classes});
 const preview=await command(r,r.owner.cookie,'/api/auth/retention/preview',{});
 assert.ok(preview.run.summary.authentication.stores.auth_oidc_logouts>0,'completed logout deliveries are selected for expiry');
 r.now+=8*day;await r.restart();
 const cleanupResponse=await r.call('/',{action:'maintain'});assert.equal(cleanupResponse.status,200,await cleanupResponse.clone().text());
 await emailSession(r,'owner@example.com');r.owner=await signInAgain(r,r.owner,'owner@example.com');
 const retention=await(await r.call('/api/auth/retention',{cookie:r.owner.cookie})).json();
 const cleanup=retention.runs.find(run=>run.id===preview.run.id);
 assert.equal(cleanup.status,'completed');assert.ok(cleanup.result['auth_oidc_logouts:authentication']>0,'the completed delivery evidence was really deleted');
 const retained=(await operations(r,r.owner.cookie,'ada')).find(op=>op.id===result.operationId);
 assert.equal(retained.logout.failed,retried.logout.failed,'retention must not silently clear failed logout history');
 assert.deepEqual(retained,retried,'retained delivery counts survive shorter queue retention');
 await r.restart();await r.call('/',{action:'maintain'});
 assert.deepEqual((await operations(r,r.owner.cookie,'ada')).find(op=>op.id===result.operationId),retried,'restart and repeated maintenance never lose or double-count outcomes');
}
