import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {passkeyPerson,post} from './agents-helpers.mjs';
import {register,authenticate} from './webauthn.mjs';

const result=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
export async function directorySourceFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());
 const owner=await passkeyPerson(r,'owner','synthetic-auth-180@example.com','owner');
 const admin=await passkeyPerson(r,'source-custodian','synthetic-auth-181@example.com','admin');
 let users=[{id:'external-a',status:'ACTIVE',profile:{email:'synthetic-auth-182@example.com',displayName:'Synthetic first',department:'Engineering'}},{id:'external-b',status:'ACTIVE',profile:{email:'synthetic-auth-183@example.com',displayName:'Synthetic second',department:'Support'}}];
 let groups=[{id:'team',profile:{name:'Engineering'}}],members=['external-a'],failGroups=false,foreignPage=false;const requests=[];
 const tenant='11111111-2222-3333-4444-555555555555';
 const server=createServer(async(req,res)=>{
  const url=new URL(req.url,'https://edge.example.com');let body='';for await(const chunk of req)body+=chunk;
  requests.push({path:url.pathname,query:url.search,authorization:req.headers.authorization,body});
  const send=(value,status=200,headers={})=>{res.writeHead(status,{'content-type':'application/json',...headers});res.end(JSON.stringify(value));};
  if(url.pathname==='/dns-query')return send({Status:0,Answer:url.searchParams.get('type')==='AAAA'?[]:[{type:1,name:url.searchParams.get('name'),data:'93.184.216.34'}]});
  if(url.pathname==='/api/v1/users'){
   if(foreignPage)return send(users,200,{link:'<https://foreign.example.com/api/v1/users?after=x>; rel="next"'});
   if(!url.searchParams.has('after')&&users.length>1)return send(users.slice(0,1),200,{link:'<https://okta.example.com/api/v1/users?after=second>; rel="next"'});
   return send(url.searchParams.has('after')?users.slice(1):users);
  }
  if(url.pathname==='/api/v1/groups')return send(groups,failGroups?503:200);
  if(url.pathname==='/api/v1/groups/team/users')return send(users.filter(row=>members.includes(row.id)));
  if(url.pathname===`/${tenant}/oauth2/v2.0/token`){const values=new URLSearchParams(body);assert.equal(values.get('grant_type'),'client_credentials');assert.equal(values.get('scope'),'https://graph.microsoft.com/.default');return send({token_type:'Bearer',access_token:'synthetic-auth-184',expires_in:3600});}
  if(url.pathname==='/v1.0/organization')return send({value:[{id:tenant}]});
  if(url.pathname==='/v1.0/users')return send({value:[{id:'entra-user',mail:'synthetic-auth-185@example.com',displayName:'Synthetic Entra',accountEnabled:true}]});
  if(url.pathname==='/v1.0/groups')return send({value:[]});
  if(url.pathname==='/admin/directory/v1/customers/my_customer')return send({kind:'admin#directory#customer',id:'Csynthetic186'});
  if(url.pathname==='/admin/directory/v1/users')return send({kind:'directory#users',users:[{id:'google-user',customerId:'Csynthetic186',primaryEmail:'synthetic-auth-186@example.com',name:{fullName:'Synthetic Google'},suspended:false}]});
  if(url.pathname==='/admin/directory/v1/groups')return send({kind:'directory#groups',groups:[]});
  if(url.pathname==='/scim/Users')return send({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:1,startIndex:1,itemsPerPage:1,Resources:[{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],id:'scim-user',userName:'synthetic-auth-187@example.com',displayName:'Synthetic SCIM',active:true}]});
  if(url.pathname==='/scim/Groups')return send({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:0,startIndex:1,itemsPerPage:0,Resources:[]});
  return send({},404);
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 const edge=`http://127.0.0.1:${server.address().port}`;
 r.edges=Object.fromEntries(['https://okta.example.com','https://cloudflare-dns.com','https://graph.microsoft.com','https://login.microsoftonline.com','https://admin.googleapis.com','https://scim-pull.example.com'].map(origin=>[origin,edge]));
 const write=(action,data,status=200,actor=owner)=>r.call('/api/auth/directory-sources/'+action,post(data,actor.cookie)).then(response=>result(response,status));
 const create=extra=>write('create',{kind:'okta',name:'Synthetic directory',baseUrl:'https://okta.example.com',organizationBinding:'https://okta.example.com',credential:'synthetic-auth-188',fields:['name','department'],confirm:true,...extra},201);
 const read=()=>r.call('/api/auth/directory-sources',{cookie:owner.cookie}).then(response=>result(response));
 const preview=(source,snapshotId=source.snapshotId)=>write('preview',{sourceId:source.sourceId,snapshotId});
 const approve=async(source,options={})=>{const p=await preview(source);return write('approve',{sourceId:source.sourceId,snapshotId:source.snapshotId,digest:p.digest,confirm:true,...options});};
 const person=address=>r.db.prepare('SELECT * FROM oa_operators WHERE email=?').bind(address).first();
 assert.equal((await r.call('/api/auth/directory-sources')).status,401);
 const source=await create();assert.equal(source.state,'staged');assert.equal(await person(users[0].profile.email),null,'credential registration cannot create native people');
 assert.ok(!JSON.stringify(await read()).includes('synthetic-auth-188'),'read model cannot disclose source credentials');
 let p=await preview(source);assert.ok(p.ok);assert.ok(p.changes.some(change=>change.kind==='group_create'));
 await write('approve',{sourceId:source.sourceId,snapshotId:source.snapshotId,digest:p.digest,confirm:false},403);
 await write('approve',{sourceId:source.sourceId,snapshotId:source.snapshotId,digest:'changed',confirm:true},409);
 const noEmail={cookie:cookieOf((await authenticate(r,owner.key)).response)};
 await write('approve',{sourceId:source.sourceId,snapshotId:source.snapshotId,digest:p.digest,confirm:true},403,noEmail);
 // Directory drift invalidates an otherwise exact preview before any imported effect.
 await r.call('/api/auth/directory/onboard',post({email:'synthetic-auth-189@example.com',name:'Synthetic unrelated',invite:false},owner.cookie)).then(response=>result(response,201));
 await write('approve',{sourceId:source.sourceId,snapshotId:source.snapshotId,digest:p.digest,confirm:true},409);
 assert.equal(await person(users[0].profile.email),null);
 p=await preview(source);r.now+=1000;await write('pull',{sourceId:source.sourceId},202);
 const applied=await write('approve',{sourceId:source.sourceId,snapshotId:source.snapshotId,digest:p.digest,confirm:true});assert.equal(applied.state,'completed','liveness-only refresh preserves approval of the same exact content');
 const first=await person(users[0].profile.email),second=await person(users[1].profile.email);assert.ok(first&&second);assert.equal(first.status,'invited');
 assert.equal((await r.db.prepare("SELECT value FROM auth_person_fields WHERE person_id=? AND field='name' AND source='directory'").bind(first.id).first()).value,users[0].profile.displayName);
 const binding=await r.db.prepare("SELECT source_id FROM auth_person_sources WHERE source='directory' AND person_id=?").bind(first.id).first();assert.ok(binding.source_id.startsWith(source.sourceId+':'));
 const owned=await r.db.prepare('SELECT group_id FROM auth_directory_source_groups WHERE source_id=?').bind(source.sourceId).first();
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_group_members WHERE group_id=? AND person_id=?').bind(owned.group_id,first.id).first()).n,1);
 assert.equal((await write('pull',{sourceId:source.sourceId},202)).replayed,true);
 r.now+=1000;await write('pull',{sourceId:source.sourceId},202);assert.equal((await read()).sources.find(row=>row.id===source.sourceId).lastReadAt,r.now,'identical directory content still proves current liveness');
 const collision=await create({name:'Synthetic isolated directory'}),collisionPreview=await preview(collision);assert.equal(collisionPreview.ok,false);assert.ok(collisionPreview.refusals.some(reason=>reason.includes('identity_collision')));
 // A member has actually enrolled before the observed leaver is approved.
 const enrolled=await register(r,await emailSession(r,users[0].profile.email));
 users=users.map(row=>row.id==='external-a'?{...row,status:'DEPROVISIONED',profile:{...row.profile,department:'Operations'}}:row);members=['external-a','external-b'];
 const moved={...source,...await write('pull',{sourceId:source.sourceId},202)};assert.equal(moved.state,'held');assert.equal((await person(users[0].profile.email)).status,'active');
 p=await preview(moved);await write('approve',{sourceId:source.sourceId,snapshotId:moved.snapshotId,digest:p.digest,confirm:true},403);
 await approve(moved,{confirmHeld:true});assert.equal((await person(users[0].profile.email)).status,'inactive');assert.equal((await r.call('/api/auth/me',{cookie:enrolled.cookie})).status,401);
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_group_members WHERE group_id=? AND person_id=?').bind(owned.group_id,first.id).first()).n,0);
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_group_members WHERE group_id=? AND person_id=?').bind(owned.group_id,second.id).first()).n,1);
 assert.equal((await r.db.prepare("SELECT value FROM auth_person_fields WHERE person_id=? AND field='department' AND source='directory'").bind(first.id).first()).value,'Operations');
 failGroups=true;await write('pull',{sourceId:source.sourceId},502);failGroups=false;
 foreignPage=true;await write('pull',{sourceId:source.sourceId},502);foreignPage=false;
 assert.ok(!requests.some(request=>request.path.includes('foreign')),'pagination refuses a foreign host before sending credentials');
 users=[];groups=[];members=[];const empty={...source,...await write('pull',{sourceId:source.sourceId},202)};assert.ok(empty.reasons.includes('empty_snapshot'));await approve(empty,{confirmHeld:true});
 assert.equal((await person('synthetic-auth-183@example.com')).status,'invited','full absence never means a termination');
 const entra=await create({kind:'entra',name:'Synthetic Entra',baseUrl:undefined,organizationBinding:tenant,credential:JSON.stringify({clientId:'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',clientSecret:'synthetic-auth-190'})});
 assert.equal(await person('synthetic-auth-185@example.com'),null);await approve(entra);await write('pull',{sourceId:entra.sourceId},202);
 assert.equal(requests.filter(request=>request.path===`/${tenant}/oauth2/v2.0/token`).length,2,'each Entra pull exchanges the sealed client credential');
 const google=await create({kind:'google',name:'Synthetic Google',baseUrl:undefined,organizationBinding:'Csynthetic186',credential:'synthetic-auth-191'});await approve(google);
 const scim=await create({kind:'scim',name:'Synthetic SCIM pull',baseUrl:'https://scim-pull.example.com/scim',organizationBinding:'https://scim-pull.example.com',credential:'synthetic-auth-192'});await approve(scim);
 const push=await create({kind:'scim',mode:'push',name:'Synthetic inbound',baseUrl:undefined,organizationBinding:r.origin,credential:undefined});
 const push2=await create({kind:'scim',mode:'push',name:'Synthetic other inbound',baseUrl:undefined,organizationBinding:r.origin,credential:undefined});
 const ingress=(method,tail,data,token=push.ingressToken)=>r.call(new URL(push.scimBase).pathname+'/'+tail,{method,data,headers:{authorization:'Bearer '+token,'content-type':'application/scim+json'}});
 assert.equal((await r.call(new URL(push.scimBase).pathname+'/Users',{cookie:owner.cookie})).status,401);
 assert.equal((await ingress('GET','Users',undefined,push2.ingressToken)).status,401);
 assert.equal((await r.call('/api/auth/directory-sources',{headers:{authorization:'Bearer '+push.ingressToken}})).status,401);
 const inbound=await ingress('POST','Users',{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],externalId:'pushed-user',userName:'synthetic-auth-193@example.com',displayName:'Synthetic pushed',active:true});
 assert.equal(inbound.status,201,await inbound.clone().text());assert.equal(await person('synthetic-auth-193@example.com'),null);
 const inboundGroup=await ingress('POST','Groups',{schemas:['urn:ietf:params:scim:schemas:core:2.0:Group'],externalId:'synthetic-auth-pushed-team',displayName:'Synthetic pushed team',members:[{value:'pushed-user',type:'User'}]});assert.equal(inboundGroup.status,201,await inboundGroup.clone().text());
 const inboundSnapshot={sourceId:push.sourceId,snapshotId:inboundGroup.headers.get('x-auth-directory-snapshot')};assert.equal((await preview(inboundSnapshot)).held,true);await approve(inboundSnapshot,{confirmHeld:true});
 assert.ok(await person('synthetic-auth-193@example.com'));
 const pushedTeam=await r.db.prepare('SELECT group_id FROM auth_directory_source_groups WHERE source_id=? AND external_id=?').bind(push.sourceId,'synthetic-auth-pushed-team').first();assert.ok(pushedTeam);
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_group_members WHERE group_id=? AND person_id=?').bind(pushedTeam.group_id,(await person('synthetic-auth-193@example.com')).id).first()).n,1);
 const patchBody={schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',path:'displayName',value:'Synthetic renamed'}]};
 const patched=await ingress('PATCH','Users/pushed-user',patchBody);assert.equal(patched.status,200,await patched.clone().text());
 const duplicate=await ingress('PATCH','Users/pushed-user',patchBody);assert.equal(duplicate.headers.get('x-auth-directory-snapshot'),patched.headers.get('x-auth-directory-snapshot'),'duplicate observations have one immutable snapshot');
 const replacement=await ingress('PUT','Users/pushed-user',{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],id:'pushed-user',userName:'synthetic-auth-193@example.com',displayName:'Synthetic replaced',active:true});assert.equal(replacement.status,200,await replacement.clone().text());
 await approve({sourceId:push.sourceId,snapshotId:replacement.headers.get('x-auth-directory-snapshot')},{confirmHeld:true});
 assert.equal((await person('synthetic-auth-193@example.com')).display_name,'Synthetic replaced','replacement keeps the existing person and applies only reviewed source fields');
 const custodial=await create({kind:'scim',mode:'push',name:'Synthetic custody',baseUrl:undefined,organizationBinding:r.origin,credential:undefined});
 await write('disable',{sourceId:custodial.sourceId,confirm:true});
 assert.equal((await r.call(new URL(custodial.scimBase).pathname+'/Users',{headers:{authorization:'Bearer '+custodial.ingressToken}})).status,401);
 // Ending a custodian also ends the credential, without waiting for a poll.
 const delegated=await write('create',{kind:'scim',mode:'push',name:'Synthetic custodian source',organizationBinding:r.origin,fields:['name'],confirm:true},201,admin);
 await r.call('/api/auth/directory/edit',post({personId:'source-custodian',state:'suspended'},owner.cookie)).then(response=>result(response));
 assert.equal((await r.call(new URL(delegated.scimBase).pathname+'/Users',{headers:{authorization:'Bearer '+delegated.ingressToken}})).status,403);
 const visible=JSON.stringify(await read());assert.ok(!visible.includes(push.ingressToken));assert.ok(!visible.includes('synthetic-auth-190'));
}

// Native freshness and follow-up share the existing source and obligation doors.
export async function directoryFreshnessFlow(t) {
 const {signInAgain}=await import('./agents-helpers.mjs');
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-03-09T09:00:00Z');
 const address=n=>['synthetic-auth-'+n,'example.com'].join('@');
 let owner=await passkeyPerson(r,'synthetic-auth-201',address(201),'owner');
 const custodian=await passkeyPerson(r,'synthetic-auth-202',address(202),'admin');
 let outage=false,incomplete=false,empty=false,inactive=false,holdNext=false,entered,release;
 const seen=[];
 const server=createServer(async(req,res)=>{
  const url=new URL(req.url,'https://edge.example.com');seen.push({path:url.pathname,authorization:req.headers.authorization});
  const send=(value,status=200)=>{res.writeHead(status,{'content-type':'application/scim+json'});res.end(JSON.stringify(value));};
  if(url.pathname==='/dns-query')return send({Status:0,Answer:url.searchParams.get('type')==='A'?[{type:1,data:'93.184.216.34'}]:[]});
  if(req.headers.authorization!=='Bearer synthetic-auth-203')return send({},401);
  if(url.pathname==='/scim/Users'&&holdNext){const failed=holdNext!=='success';holdNext=false;entered();await new Promise(done=>{release=done;});if(failed)return send({},503);}
  if(outage)return send({},503);
  const users=empty?[]:[{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],id:'synthetic-auth-204',userName:address(204),displayName:'Synthetic directory worker',active:!inactive}];
  const rows=url.pathname==='/scim/Users'?users:[];
  if(incomplete&&url.pathname==='/scim/Groups')return send({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:1,startIndex:1,itemsPerPage:0,Resources:[]});
  return send({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:rows.length,startIndex:1,itemsPerPage:rows.length,Resources:rows});
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 const edge='http://127.0.0.1:'+server.address().port;
 r.edges={'https://cloudflare-dns.com':edge,'https://freshness.example.com':edge};
 const command=(path,data,status=200,actor=owner)=>r.call('/api/auth/'+path,post(data,actor.cookie)).then(response=>result(response,status));
 const create=actor=>command('directory-sources/create',{kind:'scim',mode:'pull',name:'Synthetic freshness source',baseUrl:'https://freshness.example.com/scim',organizationBinding:'https://freshness.example.com',credential:'synthetic-auth-203',fields:['name'],confirm:true},201,actor);
 const read=()=>r.call('/api/auth/followup',{cookie:owner.cookie}).then(response=>result(response));
 const obligations=async sourceId=>(await read()).obligations.filter(ob=>ob.kind==='directory_source'&&ob.sourceLink.endsWith(sourceId));
 const source=await create(owner),pull=()=>command('directory-sources/pull',{sourceId:source.sourceId},202);
 const model=async id=>(await result(await r.call('/api/auth/directory-sources',{cookie:owner.cookie}))).sources.find(row=>row.id===id);
 const tick=()=>r.call('/',{action:'maintain'}).then(response=>result(response));
 const snapshots=()=>r.db.prepare('SELECT COUNT(*) AS n FROM auth_directory_snapshots WHERE source_id=?').bind(source.sourceId).first();
 const applied=()=>r.db.prepare('SELECT COUNT(*) AS n FROM auth_directory_snapshots WHERE source_id=? AND approved_at IS NOT NULL').bind(source.sourceId).first();
 const reminders=async()=>(await r.mails()).filter(mail=>mail.subject.startsWith('Auth follow-up'));
 assert.equal(source.state,'staged');r.now+=60000;
 const unchanged=await pull();assert.equal(unchanged.replayed,true);assert.equal(unchanged.snapshotId,source.snapshotId);
 assert.equal((await model(source.sourceId)).lastReadAt,r.now,'unchanged authenticated content advances observation time');
 assert.equal((await snapshots()).n,1);assert.equal((await applied()).n,0);
 await command('followup/settings',{enabled:true,confirm:true,calendar:{timezone:'UTC',weekdays:[0,1,2,3,4,5,6],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:1,recipients:['source_owner','synthetic-auth-201'],escalationRecipients:['synthetic-auth-201'],escalation:'repeat_until_resolved'});
 outage=true;await command('directory-sources/pull',{sourceId:source.sourceId},502);
 let [episode]=await obligations(source.sourceId);assert.ok(episode);assert.equal(episode.state,'open');assert.equal(episode.owner_id,'synthetic-auth-201');assert.equal(episode.last_error,'directory_source_request_refused');assert.equal(episode.canSend,false);assert.match(episode.next_action,/check_source_credentials/);
 assert.equal((await obligations(source.sourceId)).length,1);
 assert.equal((await r.call('/api/auth/followup')).status,401);
 assert.equal((await r.call('/api/auth/directory-sources/pull',{method:'POST',data:{sourceId:source.sourceId}})).status,401);
 await command('followup/send',{id:episode.id},403);await command('followup/schedule',{id:episode.id,ownerId:'synthetic-auth-202',dueBusinessDays:1,deadlineBusinessDays:2},403);
 const foreign=await command('organizations/create',{name:'Separate freshness employer'},201);
 const org={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+foreign.id+path,options)};
 const foreignOwner=await register(org,await emailSession(org,address(201)));
 const foreignView=await result(await org.call('/api/auth/followup',{cookie:foreignOwner.cookie}));assert.deepEqual(foreignView.obligations,[]);assert.deepEqual(foreignView.history,[]);
 assert.equal((await org.call('/api/auth/directory-sources/pull',post({sourceId:source.sourceId},foreignOwner.cookie))).status,404);
 assert.equal((await org.call('/api/auth/followup/send',post({id:episode.id},foreignOwner.cookie))).status,404);
 // The overdue episode survives downtime, retries and concurrent maintenance.
 r.now+=2*86400000;await r.restart();owner=await signInAgain(r,owner,address(201));await Promise.all([tick(),tick()]);
 assert.deepEqual((await obligations(source.sourceId)).map(ob=>[ob.id,ob.state]),[[episode.id,'open']]);
 assert.equal((await read()).history.filter(event=>event.obligation_id===episode.id&&event.event==='opened').length,1);
 assert.deepEqual(await reminders(),[],'neither global nor separately enabled HR consent dispatches directory reminders');
 outage=false;r.now+=60000;await pull();
 assert.equal((await model(source.sourceId)).lastReadAt,r.now);assert.equal((await model(source.sourceId)).lastError,null);
 assert.deepEqual((await obligations(source.sourceId)).map(ob=>[ob.id,ob.state]),[[episode.id,'completed']]);
 assert.ok((await read()).history.some(event=>event.obligation_id===episode.id&&event.event==='completed'));
 assert.equal((await snapshots()).n,1,'unchanged-content recovery creates no replacement snapshot');assert.equal((await applied()).n,0,'observation recovery never supplies human approval');
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind(address(204)).first(),null,'freshness recovery cannot import a worker');
 // A failed partial enumeration never replaces the complete staged snapshot.
 incomplete=true;const healthyAt=r.now;await command('directory-sources/pull',{sourceId:source.sourceId},502);incomplete=false;
 assert.equal((await snapshots()).n,1);assert.equal((await model(source.sourceId)).lastReadAt,healthyAt);
 const failed=(await obligations(source.sourceId)).find(ob=>ob.state==='open');assert.ok(failed);assert.notEqual(failed.id,episode.id);
 // Empty and destructive content refresh liveness but remain held, with no inferred departures.
 empty=true;r.now+=60000;const heldEmpty=await pull();assert.ok(heldEmpty.reasons.includes('empty_snapshot'));
 assert.equal((await obligations(source.sourceId)).find(ob=>ob.id===failed.id).state,'completed');
 const preview=await command('directory-sources/preview',{sourceId:source.sourceId,snapshotId:heldEmpty.snapshotId});
 await command('directory-sources/approve',{sourceId:source.sourceId,snapshotId:heldEmpty.snapshotId,digest:preview.digest,confirm:true},403);
 empty=false;inactive=true;const heldInactive=await pull();assert.ok(heldInactive.reasons.includes('destructive_change'));assert.equal(heldInactive.state,'held');assert.equal((await applied()).n,0);inactive=false;await pull();
 // A delayed failure cannot reopen a recovered source or overwrite its liveness.
 const waiting=new Promise(done=>{entered=done;});holdNext=true;
 const delayed=r.call('/api/auth/directory-sources/pull',post({sourceId:source.sourceId},owner.cookie));await waiting;
 r.now+=60000;await pull();release();await result(await delayed,502);
 assert.equal((await model(source.sourceId)).lastError,null);assert.equal((await model(source.sourceId)).lastReadAt,r.now);
 assert.equal((await obligations(source.sourceId)).filter(ob=>ob.state==='open').length,0);
 // A read that becomes overdue without a transport attempt still opens one episode.
 r.now+=15*60000;owner=await signInAgain(r,owner,address(201));await r.restart();
 const overdue=(await obligations(source.sourceId)).find(ob=>ob.state==='open');assert.ok(overdue);assert.equal(overdue.last_error,'directory_source_poll_overdue');
 outage=true;await Promise.all([tick(),tick()]);assert.equal((await obligations(source.sourceId)).filter(ob=>ob.state==='open').length,1);
 await command('directory-sources/disable',{sourceId:source.sourceId,confirm:true});
 const disabled=(await obligations(source.sourceId)).find(ob=>ob.id===overdue.id);assert.equal(disabled.state,'cancelled');assert.equal(disabled.last_error,'directory_source_disabled');
 assert.ok((await read()).history.some(event=>event.obligation_id===overdue.id&&event.event==='cancelled'&&event.error==='directory_source_disabled'));
 assert.equal((await r.call('/api/auth/directory-sources/pull',post({sourceId:source.sourceId},owner.cookie))).status,403);
 // A custodian's ended authority is permanent for this registered source.
 outage=false;const freshCustodian=await signInAgain(r,custodian,address(202)),owned=await create(freshCustodian);
 const siblings=[await create(freshCustodian),await create(freshCustodian)];
 r.now+=1;const healthy=await create(owner);
 outage=true;await command('directory-sources/pull',{sourceId:owned.sourceId},502);const [ownedEpisode]=await obligations(owned.sourceId);assert.ok(ownedEpisode);
 outage=false;const observedAt=(await model(owned.sourceId)).lastReadAt;r.now+=1000;
 const inFlight=new Promise(done=>{entered=done;});holdNext='success';
 const captured=r.call('/api/auth/directory-sources/pull',post({sourceId:owned.sourceId},owner.cookie));await inFlight;
 await command('directory/edit',{personId:'synthetic-auth-202',state:'suspended'});release();await result(await captured,409);
 assert.equal((await model(owned.sourceId)).lastReadAt,observedAt,'a captured unchanged read cannot refresh after custody is lost at commit');
 const before=seen.length;await Promise.all([tick(),tick()]);
 assert.equal((await r.call('/api/auth/directory-sources',{cookie:freshCustodian.cookie})).status,401);
 assert.equal((await r.call('/api/auth/directory-sources/pull',post({sourceId:owned.sourceId},owner.cookie))).status,403);assert.equal(seen.length,before,'ended custody makes no authenticated network call');
 const cancelled=(await obligations(owned.sourceId)).find(ob=>ob.id===ownedEpisode.id);assert.equal(cancelled.state,'cancelled');assert.equal(cancelled.last_error,'directory_source_authority_changed');
 assert.ok((await read()).history.some(event=>event.obligation_id===ownedEpisode.id&&event.event==='cancelled'&&event.error==='directory_source_authority_changed'));
 // Three older sources with ended custody must yield the bounded polling batch.
 // Only the healthy fourth source can make an authenticated directory request.
 const reads=()=>seen.filter(request=>request.path==='/scim/Users').length;
 const readsBefore=reads(),progress=[];
 for(let round=0;round<3;round++){r.now+=15*60000;await r.restart();await tick();progress.push(reads()-readsBefore);}
 assert.deepEqual(progress,[0,1,2],'ended custodians must not starve a healthy fourth directory source');
 for(const stopped of [owned,...siblings])assert.equal((await model(stopped.sourceId)).freshness.state,'custody_lost');
 assert.equal((await model(healthy.sourceId)).lastReadAt,r.now,'healthy source keeps its existing polling schedule');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_directory_snapshots WHERE approved_at IS NOT NULL').first()).n,0,'maintenance never approves any source');
 owner=await signInAgain(r,owner,address(201));
 await command('directory-sources/disable',{sourceId:healthy.sourceId,confirm:true});
 await command('directory/edit',{personId:'synthetic-auth-202',state:'active'});await r.restart();
 assert.equal((await r.call('/api/auth/directory-sources/pull',post({sourceId:owned.sourceId},owner.cookie))).status,403,'restored administrator cannot revive the old source credential');
 assert.deepEqual(await reminders(),[]);assert.equal((await applied()).n,0);
 // Closed source history follows the existing confirmed retention policy.
 const classes=['profiles','sourceSnapshots','authentication','decisions','provisioning','audit','modelTraces','erasureReceipts'];
 await command('retention/settings',{confirm:true,classes:Object.fromEntries(classes.map(name=>[name,name==='provisioning'?{unit:'days',value:90}:{unit:'years',value:7}]))});
 r.now+=120*86400000;await emailSession(r,address(201));owner=await signInAgain(r,owner,address(201));
 const queued=await command('retention/preview',{});assert.ok(queued.run);
 r.now+=8*86400000;await r.restart();await tick();owner=await signInAgain(r,owner,address(201));
 const retention=await result(await r.call('/api/auth/retention',{cookie:owner.cookie}));
 assert.equal(retention.runs.find(run=>run.id===queued.run.id).status,'completed','closed source history expires through the confirmed policy');
 const closed=await command('retention/preview',{});assert.ok(closed.run);
 r.now+=8*86400000;await r.restart();await tick();owner=await signInAgain(r,owner,address(201));
 const finalRetention=await result(await r.call('/api/auth/retention',{cookie:owner.cookie}));
 assert.equal(finalRetention.runs.find(run=>run.id===closed.run.id).status,'completed','closed source obligations must not block confirmed retention cleanup');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_directory_source_obligations').first()).n,0,'expired source bindings leave with their closed obligations');
 assert.equal((await read()).obligations.filter(ob=>ob.kind==='directory_source').length,0);
}
