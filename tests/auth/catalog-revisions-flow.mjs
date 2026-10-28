import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {register} from './webauthn.mjs';
import {samlInstall,idpCertificates,serviceProvider,signIn,posted} from './saml-helpers.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';

const address=who=>[who,'example.com'].join('@');
const post=(r,cookie,path,data,extra={})=>r.call('/api/auth/catalog/'+path,{method:'POST',cookie,data,...extra});
async function success(response,status=200) {assert.equal(response.status,status,await response.clone().text());return response.json();}
const snapshot=async(r,id)=>({app:await r.db.prepare('SELECT * FROM auth_apps WHERE id=?').bind(id).first(),assignments:(await r.db.prepare('SELECT * FROM auth_app_assignments WHERE app_id=?').bind(id).all()).results,connector:await r.db.prepare('SELECT * FROM auth_scim_connectors WHERE app_id=?').bind(id).first(),revisions:(await r.db.prepare('SELECT * FROM auth_app_revisions WHERE app_id=?').bind(id).all()).results,events:(await r.db.prepare("SELECT * FROM auth_activity WHERE event='catalog.configuration.approved'").all()).results});

export async function configurationLifecycle(t) {
 const r=await samlInstall(t),cookie=r.owner.cookie;
 const added=await success(await r.admin('/api/auth/catalog/add',{recipe:'slack',workspace:'synthetic-auth-1',token:'synthetic-auth-901'}),201);
 let outbound=0;
 const edge=createServer((req,res)=>{outbound++;res.writeHead(503);res.end();});await new Promise(done=>edge.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>edge.close(done)));
 r.edges={'https://api.slack.com':`http://127.0.0.1:${edge.address().port}`};
 await success(await r.admin('/api/auth/company-apps/assign',{appId:added.id,principalType:'person',principalId:'ada',role:'editor'}));
 const beforeOutbound=outbound;assert.ok(beforeOutbound>0,'assignment uses the test-owned connector edge');
 const certs=await idpCertificates(r);
 const peer=()=>{const sp=serviceProvider(r,{entity:'https://slack.com',idpCerts:certs,assertion:false,format:null});sp.options.callbackUrl='https://synthetic-auth-1.slack.com/sso/saml';return sp;};
 const login=async expected=>{const sp=peer(),out=await posted(await signIn(r,sp,r.ada));const {profile}=await sp.validatePostResponseAsync({SAMLResponse:out.SAMLResponse});assert.equal(profile.UserEmail,undefined);assert.equal(profile['User.Email'],address('ada'));assert.equal(profile.full_name,expected);return profile.nameID;};
 const original=await login(undefined),before=await snapshot(r,added.id);
 const preview=await success(await post(r,cookie,'preview',{appId:added.id,version:1,settings:{attributes:'User.Email=email\nfull_name=name',nameIdFormat:'emailAddress',token:'synthetic-auth-ignored'}}));
 assert.deepEqual(await snapshot(r,added.id),before,'preview writes neither settings, history nor audit');
 assert.equal(outbound,beforeOutbound,'preview makes no outbound call');
 assert.equal(preview.proposed.nameIdFormat,'emailAddress');assert.ok(!JSON.stringify(preview).includes('synthetic-auth-ignored'));
 assert.equal(await login(undefined),original,'preview did not alter SAML');
 assert.equal((await post(r,cookie,'approve',{appId:added.id,preview:preview.preview})).status,400);
 const approve={appId:added.id,preview:preview.preview,confirm:true};
 const concurrent=await Promise.all([1,2].map(()=>post(r,cookie,'approve',approve,{barrier:{name:'synthetic-auth-catalog-1',size:2}})));
 assert.deepEqual(concurrent.map(res=>res.status).sort(),[200,409]);
 assert.equal(await login('ada'),address('ada'));
 const after=await snapshot(r,added.id);assert.deepEqual(after.assignments,before.assignments);assert.deepEqual(after.connector,before.connector);assert.equal(after.revisions.length,2);assert.equal(after.events.length,1);
 assert.equal((await post(r,cookie,'approve',approve)).status,409);
 await r.restart();assert.equal(await login('ada'),address('ada'));
 const history=await success(await post(r,cookie,'history',{appId:added.id}));assert.deepEqual(history.revisions.map(v=>v.version),[2,1]);assert.equal(history.configuration.nameIdFormat,'emailAddress');
 const rollback=await success(await post(r,cookie,'preview',{appId:added.id,version:2,targetVersion:1}));
 assert.equal(await login('ada'),address('ada'));
 await success(await post(r,cookie,'approve',{appId:added.id,preview:rollback.preview,confirm:true}));
 assert.equal(await login(undefined),original,'rollback restores native SAML behaviour');
 const restored=await snapshot(r,added.id);assert.equal(restored.app.version,3);assert.equal(restored.revisions.length,3);assert.equal(restored.revisions.find(v=>v.version===3).rolled_back_from,1);assert.deepEqual(restored.assignments,before.assignments);assert.deepEqual(restored.connector,before.connector);
 const projected=JSON.stringify({history:await success(await post(r,cookie,'history',{appId:added.id})),events:(await r.db.prepare("SELECT detail FROM auth_activity_details WHERE activity_id IN (SELECT id FROM auth_activity WHERE event='catalog.configuration.approved')").all()).results});
 assert.ok(!projected.includes(before.connector.sealed_token));assert.ok(!projected.includes('synthetic-auth-ignored'));assert.ok(!projected.includes('sealed_token'));assert.ok(!projected.includes('synthetic-auth-901'));assert.equal(outbound,beforeOutbound,'approval and rollback do not dispatch provisioning');
 const oldWrite=await r.admin('/api/auth/company-apps/update',{id:added.id,version:3,entityId:'https://slack.com',acsUrl:'https://synthetic-auth-1.slack.com/sso/saml'});assert.equal(oldWrite.status,409);
 await r.restart();assert.equal(await login(undefined),original);
}

export async function configurationAuthority(t) {
 const r=await samlInstall(t),cookie=r.owner.cookie;
 const added=await success(await r.admin('/api/auth/catalog/add',{recipe:'zoom',vanity:'synthetic-auth-2'}),201),appId=added.id;
 const prepare=()=>post(r,cookie,'preview',{appId,version:1,settings:{name:'Reviewed app'}});
 const review=await success(await prepare()),approved={appId,preview:review.preview,confirm:true};
 const isolated=await success(await r.admin('/api/auth/organizations/create',{name:'Separate catalog employer'}),201);
 for(const [path,data] of [['preview',{appId,version:1}],['approve',approved],['history',{appId}]])assert.equal((await r.call('/org/'+isolated.id+'/api/auth/catalog/'+path,{method:'POST',cookie,data})).status,401);
 const org={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+isolated.id+path,options)};
 const foreignOwner=await register(org,await emailSession(org,address('owner')));
 for(const [path,data] of [['preview',{appId,version:1}],['approve',approved],['history',{appId}]])assert.equal((await org.call('/api/auth/catalog/'+path,{method:'POST',cookie:foreignOwner.cookie,data})).status,404);
 let before=await snapshot(r,appId),version=1;
 const emailOnly=await emailSession(r,address('owner'));
 for(const actor of [undefined,emailOnly,r.ada])for(const [path,data] of [['preview',{appId,version:1}],['approve',approved],['history',{appId}]])assert.ok([401,403].includes((await post(r,actor,path,data)).status));
 assert.equal((await post(r,cookie,'preview',{appId,version:0})).status,409);
 assert.equal((await post(r,cookie,'preview',{appId,version:1,targetVersion:700})).status,404);
 assert.equal((await post(r,cookie,'preview',{appId,version:1,settings:{metadata:'invalid'}})).status,400);
 assert.equal((await post(r,cookie,'approve',{...approved,preview:review.preview+'x'})).status,409);
 r.now+=11*60000;assert.equal((await post(r,cookie,'approve',approved)).status,403);r.tick();
 assert.deepEqual(await snapshot(r,appId),before);
 // Grant real scoped authority through the ordinary reviewed role door.
 const holder=await passkeyPerson(r,'synthetic-auth-3',address('synthetic-auth-3'),'member');
 const change=async data=>{const proposed=await success(await r.admin('/api/auth/roles/preview',data));return success(await r.admin('/api/auth/roles/apply',{previewId:proposed.previewId}));};
 const role=await change({kind:'role',role:{name:'App custodian',rank:20,permissions:['apps.edit','apps.view','roles.view']}});
 const scope={people:[],groups:[],apps:[appId],cases:[]};
 await change({kind:'grant',personId:'synthetic-auth-3',roleId:role.plan.role.id,resources:{view:scope,edit:scope}});
 let scoped=await success(await post(r,holder.cookie,'preview',{appId,version:1,settings:{name:'Scoped app'}}));
 const foreign=await success(await r.admin('/api/auth/catalog/add',{recipe:'zoom',vanity:'synthetic-auth-4'}),201);
 assert.equal((await post(r,holder.cookie,'preview',{appId:foreign.id,version:1})).status,403);
 assert.equal((await post(r,holder.cookie,'approve',approved)).status,409,'another session cannot approve a captured preview');
 await success(await r.call('/api/auth/roles/command',{method:'POST',cookie:holder.cookie,data:{action:'/catalog/approve',params:{appId,preview:scoped.preview,confirm:true}}}));
 const rollback=await success(await post(r,holder.cookie,'preview',{appId,version:2,targetVersion:1}));
 await success(await post(r,holder.cookie,'approve',{appId,preview:rollback.preview,confirm:true}));
 version=3;before=await snapshot(r,appId);
 scoped=await success(await post(r,holder.cookie,'preview',{appId,version,settings:{name:'Must refuse'}}));
 const lose=(sql,preview=scoped.preview)=>post(r,holder.cookie,'approve',{appId,preview,confirm:true},{factorRace:sql});
 assert.ok([403,409].includes((await lose("UPDATE auth_role_grants SET revoked_at=1 WHERE person_id='synthetic-auth-3'")).status));
 assert.deepEqual(await snapshot(r,appId),before);
 // Hardware and fresh email are rechecked at the actual transaction boundary.
 for(const sql of ["UPDATE auth_sessions SET amr='[\"email\"]' WHERE person_id='owner'","UPDATE auth_sessions SET local_email_verified_at=0 WHERE person_id='owner'"]) {
  const owner=await signInAgain(r,r.owner,address('owner'));r.owner=owner;
  const prepared=await success(await post(r,owner.cookie,'preview',{appId,version,settings:{name:'Must refuse'}}));
  assert.ok([403,409].includes((await post(r,owner.cookie,'approve',{appId,preview:prepared.preview,confirm:true},{factorRace:sql})).status));
  assert.deepEqual(await snapshot(r,appId),before);
 }
 r.owner=await signInAgain(r,r.owner,address('owner'));
 await success(await r.admin('/api/auth/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true}));
 const erase=await success(await r.admin('/api/auth/erasure/preview',{kind:'person',target:'synthetic-auth-3'}));
 await success(await r.admin('/api/auth/erasure/confirm',{previewId:erase.id,confirmation:'ERASE',destinations:[]}));
 assert.equal((await post(r,holder.cookie,'approve',{appId,preview:scoped.preview,confirm:true})).status,401,'erased actors cannot replay a capture');
 assert.equal((await snapshot(r,appId)).app.version,version);
 const removed=await success(await post(r,r.owner.cookie,'preview',{appId,version}));
 await success(await r.admin('/api/auth/company-apps/remove',{id:appId}));
 assert.equal((await post(r,r.owner.cookie,'approve',{appId,preview:removed.preview,confirm:true})).status,404);
 assert.equal((await post(r,r.owner.cookie,'history',{appId})).status,404);
}
