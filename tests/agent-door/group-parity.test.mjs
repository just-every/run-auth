import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {serveHosted,HOSTED_ORIGIN} from '../../node_modules/@runeditrun/rer/cli/hosted-output.mjs';
import {createAgentConformanceNetwork} from '../../node_modules/@runeditrun/rer/cli/agent-network.mjs';
import {createProtocol,errorCode,APPROVAL} from '../../node_modules/@runeditrun/rer/modules/agent-door/conformance/protocol.mjs';
import {autonomousPolicy,heldPolicy,seconds,signJws} from '../../node_modules/@runeditrun/rer/modules/agent-door/conformance/crypto.mjs';
import {nativePerson} from './native-person.mjs';
import {groupNames} from './parity-fixtures.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const surface=JSON.parse(await readFile(new URL('../../agent-surface.json',import.meta.url),'utf8'));

// Fresh emitted Workers, actual migrations, signed claim and roster binding.
// Only paid mail and WebAuthn hardware are replaced at their network boundaries.
async function installation(t) {
 const email=['synthetic-auth-1','example.test'].join('@'),sub=randomUUID(),kid=randomUUID(),installationId=randomUUID();
 const issuer=`https://synthetic-auth-${randomUUID()}.invalid`,business='synthetic-auth-1';
 const pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const publicKeys={[kid]:{...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid,alg:'ES256',use:'sig'}};
 const network=await createAgentConformanceNetwork(root,undefined,{email});t.after(()=>network.close());
 const hosted=await serveHosted(root,{outboundService:network.fetch,bindings:{
  OWNER_EMAIL:email,AUTH_ENCRYPTION_KEY:randomBytes(32).toString('hex'),
  RER_OWNER_CLAIM_ISSUER:issuer,RER_OWNER_CLAIM_INSTALLATION_ID:installationId,
  RER_OWNER_CLAIM_APP_ORIGIN:HOSTED_ORIGIN,RER_OWNER_CLAIM_PUBLIC_KEYS:JSON.stringify(publicKeys),
  RER_BUSINESS_TRUST:JSON.stringify({v:1,issuer,audience:HOSTED_ORIGIN,subject:installationId,email,keys:publicKeys}),
 }});t.after(()=>hosted.close());
 const origin=hosted.origin;
 const request=(url,init={})=>{assert.equal(new URL(url).origin,origin);return hosted.fetch(new URL(url).href.slice(origin.length+1),{...init,headers:Object.fromEntries(new Headers(init.headers))});};
 const sign=(typ,payload)=>signJws(pair.privateKey,kid,typ,{v:1,iss:issuer,aud:origin,email,jti:randomUUID(),iat:seconds(),exp:seconds()+300,...payload});
 const owner=await nativePerson({request,origin,email,mail:network.mail,claim:{path:'/auth/owner-claim',token:await sign('rer-owner-claim+jwt',{installationId})}});
 const paired=await request(origin+'/api/rer/business-settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({settings:await sign('rer-business-settings+jwt',{sub:installationId,business,owner_id:sub,rev:1,values:{},logo:null,team:null})})});
 const ack=await paired.json();assert.equal(paired.status,200,JSON.stringify(ack));assert.equal(ack.rev,1);
 const c=createProtocol({fetch:request,origin,surface,signer:{issuer,installationId,kid,privateKey:pair.privateKey},person:{email,sub,cookie:owner.cookie()},business,consent:randomUUID(),points:[],agentId:`synthetic-auth-${randomUUID()}`,seq:0,revision:0,listed:new Map()});
 const get=async path=>{const response=await c.personRequest(path);assert.equal(response.status,200,path);return response.json();};
 const state=async()=>{const model=await get('/api/auth/company-apps');return model.groups.map(({id,name,members})=>({id,name,members}));};
 const events=async()=>{const model=await get('/api/auth/me');return model.activity.filter(row=>row.event==='group_created');};
 return {c,owner,state,events,get};
}

async function create(install,name,key,held) {
 const {c,state}=install,args={name,idempotency_key:key};
 let answer=await c.tool('auth.groups.create',args),options;
 if(held) {
  assert.equal(answer.result?.resultType,'input_required');
  assert.deepEqual(await state(),install.before,'approval must precede any mutation');
  const id=answer.result._meta[APPROVAL].id;
  const {approval}=await c.personJson('/agents/api/approvals/'+encodeURIComponent(id));
  assert.deepEqual(approval.summary.items,[name.trim()],'summary shows the native validated name');
  assert.equal((await c.decideApproval(answer)).ok,true);
  options={requestState:answer.result.requestState};
  answer=await c.tool('auth.groups.create',args,options);
 }
 assert.equal(answer.result?.isError,false);
 assert.equal(answer.result?.structuredContent?.name,name.trim());
 return {answer,args,options};
}

test('group creation matches native names, empty state, audit and duplicate refusal, with one effect per successful key under autonomous and held policies',async t=>{
 for(const held of [false,true]) {
  const native=await installation(t),agent=await installation(t);
  const policy=held?heldPolicy():autonomousPolicy();
  // Explicitly hold standard creates too, so their exact summary is reviewed.
  if(held)policy.rules=policy.rules.filter(rule=>rule.class!=='standard');
  await native.c.adopt(policy);await agent.c.adopt(policy);
  assert.deepEqual(await native.state(),[]);assert.deepEqual(await agent.state(),[]);
  const phase=held?'held':'autonomous',names=groupNames(phase);
  for(const name of [names.create.padEnd(61,'n'),names.injected.padEnd(80,'n'),'  '+groupNames(phase).create.slice(0,61).padEnd(61,'n')+'  ']) {
   const nativeResponse=await native.owner.call('/api/auth/groups/create',{name});assert.equal(nativeResponse.status,201);
   const nativeCreated=await nativeResponse.json();assert.equal(nativeCreated.name,name.trim());
   agent.before=await agent.state();
   const {answer,args,options}=await create(agent,name,randomUUID(),held),created=answer.result.structuredContent;
   assert.deepEqual((await agent.state()).find(group=>group.id===created.id).members,[]);
   assert.deepEqual((await native.state()).find(group=>group.id===nativeCreated.id).members,[]);
   assert.deepEqual((await agent.state()).map(({name,members})=>({name,members})),(await native.state()).map(({name,members})=>({name,members})));
   assert.deepEqual((await agent.events()).filter(row=>row.subject_id===created.id).map(row=>row.event),['group_created']);
   assert.deepEqual((await native.events()).filter(row=>row.subject_id===nativeCreated.id).map(row=>row.event),['group_created']);
   const before=await agent.state(),audit=await agent.events();
   const replay=await agent.c.tool('auth.groups.create',args,options);
   assert.deepEqual(replay.result?.structuredContent,created);
   assert.deepEqual(await agent.state(),before);assert.deepEqual(await agent.events(),audit);
   // A fresh key is a real duplicate attempt, not a cached success.
   const duplicateArgs={name,idempotency_key:randomUUID()};
   const refused=await agent.c.tool('auth.groups.create',duplicateArgs);
   let final=refused;
   if(held&&refused.result?.resultType==='input_required') {
    assert.equal((await agent.c.decideApproval(refused)).ok,true);
    final=await agent.c.tool('auth.groups.create',duplicateArgs,{requestState:refused.result.requestState});
   }
   // Native duplicate validation also runs at execution after approval.
   assert.equal(final.result?.isError,true);assert.equal(errorCode(final),'group_exists');
   const nativeBefore=await native.state(),nativeAudit=await native.events();
   const uiRefused=await native.owner.call('/api/auth/groups/create',{name});assert.equal(uiRefused.status,409);assert.equal((await uiRefused.json()).error,'group_exists');
   assert.deepEqual(await native.state(),nativeBefore);assert.deepEqual(await native.events(),nativeAudit);
   assert.deepEqual(await agent.state(),before);assert.deepEqual(await agent.events(),audit);
   console.log(`PROBE BASE-AGENT-002 ${phase} name-length=${name.trim().length}: native and MCP -> exact name, empty members, group_created; duplicate group_exists; replay unchanged`);
  }
  for(const name of ['', '   ', 'n'.repeat(81)]) {
   const before=await agent.state(),audit=await agent.events(),nativeBefore=await native.state(),nativeAudit=await native.events();
   const refused=await agent.c.tool('auth.groups.create',{name,idempotency_key:randomUUID()});
   const uiRefused=await native.owner.call('/api/auth/groups/create',{name});
   assert.equal(uiRefused.status,400);assert.equal((await uiRefused.json()).error,'invalid_group_name');
   assert.equal(refused.result?.isError,true);assert.equal(errorCode(refused),'invalid_group_name');
   assert.deepEqual(await agent.state(),before);assert.deepEqual(await agent.events(),audit);
   assert.deepEqual(await native.state(),nativeBefore);assert.deepEqual(await native.events(),nativeAudit);
  }
  if(held) {
   // A human can create the requested name while its approval is pending.
   // Approval must not bypass the command's current duplicate validation.
   const name=groupNames('pending').create.padEnd(80,'n'),args={name,idempotency_key:randomUUID()};
   const before=await agent.state(),audit=await agent.events();
   const pending=await agent.c.tool('auth.groups.create',args);
   assert.equal(pending.result?.resultType,'input_required');
   assert.deepEqual(await agent.state(),before);assert.deepEqual(await agent.events(),audit);
   const {approval}=await agent.c.personJson('/agents/api/approvals/'+encodeURIComponent(pending.result._meta[APPROVAL].id));
   assert.deepEqual(approval.summary.items,[name]);
   for(const install of [native,agent]) {
    const created=await install.owner.call('/api/auth/groups/create',{name});
    assert.equal(created.status,201);assert.equal((await created.json()).name,name);
   }
   const current=await agent.state(),currentAudit=await agent.events();
   assert.equal((await agent.c.decideApproval(pending)).ok,true);
   const refused=await agent.c.tool('auth.groups.create',args,{requestState:pending.result.requestState});
   assert.equal(refused.result?.isError,true);assert.equal(errorCode(refused),'group_exists');
   const nativeBefore=await native.state(),nativeAudit=await native.events();
   const nativeRefused=await native.owner.call('/api/auth/groups/create',{name});
   assert.equal(nativeRefused.status,409);assert.equal((await nativeRefused.json()).error,'group_exists');
   assert.deepEqual(await native.state(),nativeBefore);assert.deepEqual(await native.events(),nativeAudit);
   assert.deepEqual(await agent.state(),current);assert.deepEqual(await agent.events(),currentAudit);
   assert.deepEqual(current.map(({name,members})=>({name,members})),nativeBefore.map(({name,members})=>({name,members})));
   console.log('PROBE BASE-AGENT-002 held pending duplicate: native create while approval waits -> group_exists, unchanged groups and group_created events');
  }
  assert.ok(agent.c.points.every(point=>point.ok));
 }
});
