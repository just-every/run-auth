import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomBytes,randomUUID,webcrypto} from 'node:crypto';
import {serveHosted} from '../../node_modules/@runeditrun/rer/cli/hosted-output.mjs';
import {agentConformanceNetwork} from '../../node_modules/@runeditrun/rer/cli/agent-network.mjs';
import {createCapturedMail} from '../../node_modules/@runeditrun/rer/cli/agent-mail.mjs';
import {createProtocol,errorCode,APPROVAL} from '../../node_modules/@runeditrun/rer/modules/agent-door/conformance/protocol.mjs';
import {autonomousPolicy,heldPolicy,signJws,seconds,accessToken} from '../../node_modules/@runeditrun/rer/modules/agent-door/conformance/crypto.mjs';
import {nativePerson} from './native-person.mjs';

const root=new URL('../../',import.meta.url).pathname;

// Fresh production migrations, signed disposable binding and ordinary native
// enrollment. Only paid mail and WebAuthn hardware are network-edge fixtures.
async function installation() {
 const surface=JSON.parse(await readFile(new URL('../../agent-surface.json',import.meta.url),'utf8'));
 const addresses=[1,2,3].map(n=>['synthetic-auth-'+n,'example.com'].join('@'));
 const mail=addresses.map(email=>createCapturedMail(email));
 const pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const signer={issuer:'https://synthetic-auth.invalid',installationId:randomUUID(),kid:randomUUID(),privateKey:pair.privateKey};
 const publicKeys=JSON.stringify({[signer.kid]:{...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid:signer.kid,alg:'ES256',use:'sig'}});
 const origin='https://rer-hosted-check.invalid',sub=randomUUID(),readerSub=randomUUID(),business='synthetic-auth';
 const hosted=await serveHosted(root,{bindings:{AUTH_ENCRYPTION_KEY:randomBytes(32).toString('hex'),OWNER_EMAIL:addresses[0],
  RER_OWNER_CLAIM_ISSUER:signer.issuer,RER_OWNER_CLAIM_INSTALLATION_ID:signer.installationId,RER_OWNER_CLAIM_APP_ORIGIN:origin,RER_OWNER_CLAIM_PUBLIC_KEYS:publicKeys,
  RER_BUSINESS_TRUST:JSON.stringify({v:1,issuer:signer.issuer,audience:origin,subject:signer.installationId,email:addresses[0],keys:JSON.parse(publicKeys)})},
  outboundService:async request=>{const copies=mail.map(()=>request.clone()),response=await agentConformanceNetwork(request);if(response.ok)await Promise.all(mail.map((box,i)=>box.capture(copies[i])));return response;}});
 const close=async()=>{mail.forEach(box=>box.close());await hosted.close();};
 try {
  const request=(url,init={})=>{assert.equal(new URL(url).origin,origin);return hosted.fetch(new URL(url).href.slice(origin.length+1),{...init,signal:AbortSignal.timeout(30000),headers:Object.fromEntries(new Headers(init.headers))});};
  const signed=(typ,body)=>signJws(signer.privateKey,signer.kid,typ,{v:1,iss:signer.issuer,aud:origin,jti:randomUUID(),iat:seconds(),exp:seconds()+300,...body});
  const owner=await nativePerson({request,origin,email:addresses[0],mail:mail[0],claim:{path:'/auth/owner-claim',token:await signed('rer-owner-claim+jwt',{installationId:signer.installationId,email:addresses[0]})}});
  const post=async(path,data,status=200)=>{const response=await owner.call('/api/auth/'+path,data);assert.equal(response.status,status,path);return response.json();};
  for(const [i,name] of [[1,'Morgan Worker'],[2,'Riley Reader']])await post('people/invite',{email:addresses[i],name},201);
  await nativePerson({request,origin,email:addresses[1],mail:mail[1]});
  const reader=await nativePerson({request,origin,email:addresses[2],mail:mail[2]});
  const get=async path=>{const response=await request(origin+path,{headers:{cookie:owner.cookie()}});assert.equal(response.status,200,path);return response.json();};
  const people=(await get('/api/auth/directory')).people;
  const ownerRecord=people.find(p=>p.email===addresses[0]),worker=people.find(p=>p.email===addresses[1]),readerRecord=people.find(p=>p.email===addresses[2]);
  assert.ok(ownerRecord?.id&&worker?.id&&readerRecord?.id);
  const settings=await signed('rer-business-settings+jwt',{sub:signer.installationId,business,email:addresses[0],owner_id:sub,rev:1,values:{},logo:null,
   team:[{id:readerSub,email:addresses[2],name:'Riley Reader',role:'member',invite:1}]});
  const paired=await request(origin+'/api/rer/business-settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({settings})});
  assert.equal(paired.status,200);assert.equal((await paired.json()).rev,1);
  const context=(cookie,email,subject)=>createProtocol({fetch:request,origin,surface,signer,person:{cookie,email,sub:subject},business,consent:randomUUID(),
   points:[],agentId:'synthetic-auth-'+randomUUID(),seq:0,revision:0,listed:new Map()});
  const c=context(owner.cookie(),addresses[0],sub),scoped=context(reader.cookie(),addresses[2],readerSub);
  const roleChange=async data=>{const preview=await post('roles/preview',data);return (await post('roles/apply',{previewId:preview.previewId})).plan;};
  return {c,scoped,post,get,roleChange,ownerRecord,worker,readerRecord,close};
 }catch(error){await close();throw error;}
}

test('native group audit targets reconcile reads, held reads, effects and private refusals with independently read directory records',async()=>{
 for(const mode of ['autonomous','held','read-approval']) {
  const f=await installation();
  try {
   const {c,scoped,post,get,roleChange,ownerRecord,worker,readerRecord}=f;
   const policy=mode==='autonomous'?autonomousPolicy():heldPolicy();
   if(mode==='read-approval')policy.rules=policy.rules.filter(rule=>rule.class!=='standard');
   await c.adopt(policy);
   // One real target is beyond the default first page; no target resolver may
   // search only that page or derive a target from an unvalidated argument.
   for(let n=0;n<27;n++)await post('groups/create',{name:'Synthetic group '+String(n).padStart(2,'0')},201);
   const native=async()=>(await get('/api/auth/directory/groups')).groups;
   const groups=await native(),g=groups.find(row=>row.name==='Synthetic group 26'),hidden=groups.find(row=>row.name==='Synthetic group 00'),other=groups.find(row=>row.name==='Synthetic group 25');
   assert.ok(g?.id&&hidden?.id&&other?.id);
   const target={kind:'group',id:g.id};
   const grant=await roleChange({kind:'grant',personId:readerRecord.id,roleId:'manager',resources:{view:{groups:[g.id],people:[worker.id]},edit:{}}});
   const rows=async()=>{
    const all=[];let cursor='';
    for(;;){const page=await c.personJson('/agents/api/audit'+(cursor?'?after='+cursor:''));assert.equal(page.differs_from_policy,0);all.push(...page.rows);if(!page.cursor||page.cursor===cursor)break;cursor=page.cursor;}
    return all;
   };
   const observed=async(who,name,args,expected,{code,pending=false,decision,requestState}={})=>{
    const before=new Set((await rows()).map(row=>row.id));
    const answer=await who.tool(name,args,{requestState});
    const added=(await rows()).filter(row=>!before.has(row.id)&&row.tool===name&&row.agent.id===who.agentId);
    assert.equal(added.length,1,'each call has one audit row');
    assert.deepEqual(added[0].resource,expected,'audit uses the independently read native target');
    assert.equal(added[0].outcome,code?'refused':pending?'pending':'done');
    assert.equal(added[0].code,code??null);
    assert.equal(errorCode(answer),code??null);
    if(decision)assert.equal(added[0].decision,decision);
    if(code)assert.equal(answer.result?.structuredContent,undefined,'a refusal exposes no native result');
    if(!code){assert.equal(answer.decision?.disposition,mode==='autonomous'?'autonomous':pending?'approval':'review');assert.equal(answer.decision?.classes[0].facts.measure,1);}
    return answer;
   };
   const pendingRead=async(who,name,args,expected)=>{
    const answer=await observed(who,name,args,expected,{pending:true});
    assert.equal(answer.result.structuredContent,undefined,'a held read publishes no record');
    const handle=answer.result._meta[APPROVAL];assert.ok(handle?.id);
    const {approval}=await who.personJson('/agents/api/approvals/'+handle.id);
    assert.deepEqual(approval.summary.nativeTarget,expected);
    return {who,name,args,answer,expected};
   };
   const refusePending=async({who,name,args,answer,expected})=>{
    const result=await who.decideApproval(answer);
    assert.equal(result.status,200);
    assert.equal(result.body.approval.state,'refused','current native authority fences an already prepared read');
    assert.equal(result.body.approval.code,'execution_failed');
    const executions=(await rows()).filter(row=>row.decision_id===answer.decision.id&&row.id!==answer.decision.id);
    assert.equal(executions.length,1);
    assert.equal(executions[0].outcome,'failed');
    assert.equal(executions[0].code,'execution_failed');
    assert.deepEqual(executions[0].resource,expected,'the execution audit retains only the target validated at preparation');
    await observed(who,name,args,null,{code:'resource_unavailable',requestState:answer.result.requestState});
   };
   const approvedReads=[];
   const complete=async(who,name,args,expected,options={})=>{
    const pending=mode==='read-approval'||mode==='held'&&options.write;
    const nativeBefore=await native();
    const answer=await observed(who,name,args,expected,{pending});
    if(!pending)return answer.result.structuredContent;
    assert.equal(answer.result.structuredContent,undefined,'pending reads expose no record');
    const handle=answer.result._meta[APPROVAL];assert.ok(handle?.id);
    const view=await who.personJson('/agents/api/approvals/'+handle.id);
    if(expected===null)assert.equal(Object.hasOwn(view.approval.summary,'nativeTarget'),false,'collection approval invents no single target');
    else assert.deepEqual(view.approval.summary.nativeTarget,expected);
    assert.deepEqual(await native(),nativeBefore,'a pending call changes no directory state');
    assert.equal((await who.decideApproval(answer)).body.approval.state,'executed');
    const execution=(await rows()).findLast(row=>row.decision_id===answer.decision.id);
    assert.deepEqual(execution.resource,expected);assert.equal(execution.outcome,'done');
    const retry=await who.tool(name,args,{requestState:answer.result.requestState});
    assert.equal(errorCode(retry),null);assert.ok(retry.result._meta['com.runeditrun/receipt']);
    if(who===scoped&&!options.write)approvedReads.push({name,args,requestState:answer.result.requestState});
    return retry.result.structuredContent;
   };
   const page=await complete(c,'auth.groups.inspect',{},null);
   assert.equal(page.items.length,25);assert.ok(!page.items.some(row=>row.id===g.id));
   const inspected=await complete(c,'auth.groups.inspect',{id:g.id},target);
   assert.deepEqual(inspected,{id:g.id,name:g.name,rule:g.rule});
   const pair=g.id+'/'+worker.id;
   assert.deepEqual(await complete(c,'auth.groups.grants',{id:pair},target),{grants:[]});

   // These decisions still name a validated native target, without performing
   // the proposed membership change or inferring one for an unavailable read.
   await observed(c,'auth.groups.add',{group_id:g.id,person_id:ownerRecord.id,idempotency_key:randomUUID()},target,{code:'self_escalation',decision:'self_escalation'});
   const blocked=autonomousPolicy();blocked.rules=[{id:'all',class:'*',do:'blocked'}];
   await c.adopt(blocked);
   for(const [name,args] of [['auth.groups.inspect',{id:g.id}],['auth.groups.grants',{id:pair}]])
    await observed(c,name,args,target,{code:'policy_blocked',decision:'blocked'});
   await c.adopt(null);
   for(const [name,args] of [['auth.groups.inspect',{id:g.id}],['auth.groups.grants',{id:pair}]])
    await observed(c,name,args,target,{code:'policy_unset',decision:'unset'});
   await observed(scoped,'auth.groups.inspect',{id:hidden.id},null,{code:'policy_unset',decision:'unset'});
   await c.adopt(policy);
   assert.deepEqual(await native(),groups,'refused decisions have no native effects');
   assert.deepEqual(await complete(scoped,'auth.groups.inspect',{id:g.id},target),inspected,'the scoped reader can read its granted group');
   assert.deepEqual(await complete(scoped,'auth.groups.grants',{id:pair},target),{grants:[]});
   const add={group_id:g.id,person_id:worker.id,idempotency_key:randomUUID()};
   await complete(c,'auth.groups.add',add,target,{write:true});
   assert.deepEqual((await native()).find(row=>row.id===g.id).members.map(p=>p.id),[worker.id]);
   // Successful-key replay retains the same target and exactly one membership.
   const replay=await c.tool('auth.groups.add',add);assert.equal(errorCode(replay),null);
   assert.deepEqual((await rows()).findLast(row=>row.tool==='auth.groups.add'&&row.agent.id===c.agentId).resource,target);
   assert.deepEqual((await native()).find(row=>row.id===g.id).members.map(p=>p.id),[worker.id]);
   const grants=await complete(c,'auth.groups.grants',{id:pair},target);
   assert.deepEqual(grants.grants,['group:'+g.id+':member:'+worker.id]);
   await complete(c,'auth.groups.remove',{id:pair,idempotency_key:randomUUID()},target,{write:true});
   assert.deepEqual(await native(),groups,'add and remove restore native membership');
   assert.deepEqual(await complete(c,'auth.groups.grants',{id:pair},target),{grants:[]});

   // Native reads validate both identities before publishing a target. A real
   // inaccessible group is indistinguishable from a missing group in the audit.
   for(const [name,args] of [
    ['auth.groups.inspect',{id:hidden.id}],['auth.groups.inspect',{id:'synthetic-auth-missing'}],
    ['auth.groups.grants',{id:hidden.id+'/'+worker.id}],['auth.groups.grants',{id:'synthetic-auth-missing/'+worker.id}],
    ['auth.groups.grants',{id:g.id+'/synthetic-auth-missing'}],['auth.groups.grants',{id:g.id+'/'+readerRecord.id}],
   ])await observed(scoped,name,args,null,{code:'resource_unavailable'});
   assert.deepEqual(await native(),groups,'missing and out-of-scope reads have no native effects');

   // An approved grant read observes current native membership, rather than
   // storing a private result when the request is first held.
   if(mode==='read-approval') {
    for(const [name,args] of [['auth.groups.inspect',{id:g.id}],['auth.groups.grants',{id:pair}]]) {
     const rejected=await pendingRead(c,name,args,target);
     const decision=await c.decideApproval(rejected.answer,'reject');
     assert.equal(decision.status,200);assert.equal(decision.body.approval.state,'rejected');
     await observed(c,name,args,target,{code:'approval_rejected',requestState:rejected.answer.result.requestState});
    }
    assert.deepEqual(await native(),groups,'rejecting held reads changes no native records');
    const held=await pendingRead(c,'auth.groups.grants',{id:pair},target);
    await post('groups/add',{groupId:g.id,personId:worker.id});
    const current=(await native()).find(row=>row.id===g.id);
    assert.deepEqual(current.members.map(p=>p.id),[worker.id]);
    assert.equal((await c.decideApproval(held.answer)).body.approval.state,'executed');
    const answer=await c.tool(held.name,held.args,{requestState:held.answer.result.requestState});
    assert.equal(errorCode(answer),null);
    assert.deepEqual(answer.result.structuredContent.grants,['group:'+current.id+':member:'+current.members[0].id]);
    await post('groups/remove',{groupId:g.id,personId:worker.id});
    assert.deepEqual(await native(),groups,'the person restores native membership after the held read');
   }
   const awaitingRevocation=[];
   if(mode==='read-approval')for(const [name,args] of [['auth.groups.inspect',{id:g.id}],['auth.groups.grants',{id:pair}]])
    awaitingRevocation.push(await pendingRead(scoped,name,args,target));

   // Revoke only this group's native read grant. Even an approved read receipt
   // must resolve current authority before returning its saved private result.
   await roleChange({kind:'grant',personId:readerRecord.id,roleId:'manager',resources:{view:{groups:[other.id],people:[worker.id]},edit:{}}});
   await roleChange({kind:'revoke',grantId:grant.id});
   for(const [name,args] of [['auth.groups.inspect',{id:g.id}],['auth.groups.grants',{id:pair}]])
    await observed(scoped,name,args,null,{code:'resource_unavailable'});
   for(const saved of awaitingRevocation)await refusePending(saved);
   for(const saved of approvedReads)
    await observed(scoped,saved.name,saved.args,null,{code:'resource_unavailable',requestState:saved.requestState});
   const allowed=await complete(scoped,'auth.groups.inspect',{id:other.id},{kind:'group',id:other.id});
   assert.deepEqual(allowed,{id:other.id,name:other.name,rule:other.rule},'unrelated native read authority remains usable');
   assert.deepEqual(await native(),groups,'refused receipt replays change no memberships');

   const removed=await post('groups/create',{name:'Synthetic removed group'},201);
   await complete(c,'auth.groups.inspect',{id:removed.id},{kind:'group',id:removed.id});
   const awaitingDeletion=[];
   if(mode==='read-approval')for(const [name,args] of [['auth.groups.inspect',{id:removed.id}],['auth.groups.grants',{id:removed.id+'/'+worker.id}]])
    awaitingDeletion.push(await pendingRead(c,name,args,{kind:'group',id:removed.id}));
   await post('groups/delete',{id:removed.id});
   for(const saved of awaitingDeletion)await refusePending(saved);
   await observed(c,'auth.groups.inspect',{id:removed.id},null,{code:'resource_unavailable'});
   await observed(c,'auth.groups.grants',{id:removed.id+'/'+worker.id},null,{code:'resource_unavailable'});
   assert.deepEqual(await native(),groups,'removed records never become inferred audit targets');

   // A readable group can still fail native write classification after target
   // resolution. Keep that known target without weakening the app boundary.
   const app=await post('company-apps/create',{name:'Synthetic board',entityId:'https://synthetic-auth.invalid/saml',acsUrl:'https://synthetic-auth.invalid/acs'},201);
   await post('company-apps/assign',{appId:app.id,principalType:'group',principalId:g.id,role:'reader'});
   const before=await native();
   await observed(c,'auth.groups.add',{group_id:g.id,person_id:worker.id,idempotency_key:randomUUID()},target,{code:'app_assignment_door_required'});
   await observed(c,'auth.groups.remove',{id:pair,idempotency_key:randomUUID()},target,{code:'app_assignment_door_required'});
   assert.deepEqual(await native(),before,'resolved native refusals change no membership or assignment');
   const anonymous=await c.request('/agents/api/audit');assert.equal(anonymous.status,401);
   const agent=await c.request('/agents/api/audit',{headers:{origin:c.origin,authorization:'Bearer '+await accessToken(c)}});assert.equal(agent.status,403);
   assert.ok(c.points.every(point=>point.ok),'shared protocol and approval checks remain active');
  }finally{await f.close();}
 }
});
