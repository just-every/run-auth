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
 const applied=await approve(source);assert.equal(applied.state,'completed');
 const first=await person(users[0].profile.email),second=await person(users[1].profile.email);assert.ok(first&&second);assert.equal(first.status,'invited');
 assert.equal((await r.db.prepare("SELECT value FROM auth_person_fields WHERE person_id=? AND field='name' AND source='directory'").bind(first.id).first()).value,users[0].profile.displayName);
 const binding=await r.db.prepare("SELECT source_id FROM auth_person_sources WHERE source='directory' AND person_id=?").bind(first.id).first();assert.ok(binding.source_id.startsWith(source.sourceId+':'));
 const owned=await r.db.prepare('SELECT group_id FROM auth_directory_source_groups WHERE source_id=?').bind(source.sourceId).first();
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_group_members WHERE group_id=? AND person_id=?').bind(owned.group_id,first.id).first()).n,1);
 assert.equal((await write('pull',{sourceId:source.sourceId},202)).replayed,true);
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
 const inboundSnapshot={sourceId:push.sourceId,snapshotId:inbound.headers.get('x-auth-directory-snapshot')};assert.equal((await preview(inboundSnapshot)).held,true);await approve(inboundSnapshot,{confirmHeld:true});
 assert.ok(await person('synthetic-auth-193@example.com'));
 const patchBody={schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',path:'displayName',value:'Synthetic renamed'}]};
 const patched=await ingress('PATCH','Users/pushed-user',patchBody);assert.equal(patched.status,200,await patched.clone().text());
 const duplicate=await ingress('PATCH','Users/pushed-user',patchBody);assert.equal(duplicate.headers.get('x-auth-directory-snapshot'),patched.headers.get('x-auth-directory-snapshot'),'duplicate observations have one immutable snapshot');
 const custodial=await create({kind:'scim',mode:'push',name:'Synthetic custody',baseUrl:undefined,organizationBinding:r.origin,credential:undefined});
 await write('disable',{sourceId:custodial.sourceId,confirm:true});
 assert.equal((await r.call(new URL(custodial.scimBase).pathname+'/Users',{headers:{authorization:'Bearer '+custodial.ingressToken}})).status,401);
 // Ending a custodian also ends the credential, without waiting for a poll.
 const delegated=await write('create',{kind:'scim',mode:'push',name:'Synthetic custodian source',organizationBinding:r.origin,fields:['name'],confirm:true},201,admin);
 await r.call('/api/auth/directory/edit',post({personId:'source-custodian',state:'suspended'},owner.cookie)).then(response=>result(response));
 assert.equal((await r.call(new URL(delegated.scimBase).pathname+'/Users',{headers:{authorization:'Bearer '+delegated.ingressToken}})).status,403);
 const visible=JSON.stringify(await read());assert.ok(!visible.includes(push.ingressToken));assert.ok(!visible.includes('synthetic-auth-190'));
}
