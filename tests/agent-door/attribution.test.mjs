import assert from 'node:assert/strict';
import {randomBytes,randomUUID,webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {serveHosted,HOSTED_ORIGIN} from '../../node_modules/@runeditrun/rer/cli/hosted-output.mjs';
import {createAgentConformanceNetwork} from '../../node_modules/@runeditrun/rer/cli/agent-network.mjs';
import {signJws,seconds,accessToken,autonomousPolicy} from '../../src/modules/agent-door/conformance/crypto.mjs';
import {createProtocol,APPROVAL} from '../../src/modules/agent-door/conformance/protocol.mjs';
import {nativePerson} from './native-person.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
export const names={agent:'Directory_Agent <img src=x onerror="window.attributionInjected=1">',sponsor:'Avery_Sponsor & Co',approver:'Morgan_Approver <img src=x onerror="window.attributionInjected=1">'};
const address=n=>['synthetic-auth-'+n,'example.com'].join('@');

// A single sanity journey, registered by the directory browser suite. Only mail
// delivery and WebAuthn hardware are faked; all state uses production HTTP doors.
export async function attributionFlow(t,inspect) {
 for(const policy of ['autonomous','held']) {
  const email=address(81),approverEmail=address(82),memberEmail=address(83),business='synthetic-auth-business';
  const kid=randomUUID(),pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const publicKey={...await webcrypto.subtle.exportKey('jwk',pair.publicKey),kid,alg:'ES256',use:'sig'};
  const signer={issuer:'https://synthetic-auth-business.invalid',installationId:randomUUID(),kid,privateKey:pair.privateKey};
  const network=await createAgentConformanceNetwork(root,undefined,{email});
  const approverNetwork=await createAgentConformanceNetwork(root,undefined,{email:approverEmail});
  const publicKeys=JSON.stringify({[kid]:publicKey});
  const hosted=await serveHosted(root,{bindings:{OWNER_EMAIL:email,SETUP_TOKEN:randomBytes(32).toString('hex'),AUTH_ENCRYPTION_KEY:randomBytes(32).toString('hex'),
   RER_OWNER_CLAIM_ISSUER:signer.issuer,RER_OWNER_CLAIM_INSTALLATION_ID:signer.installationId,RER_OWNER_CLAIM_APP_ORIGIN:HOSTED_ORIGIN,RER_OWNER_CLAIM_PUBLIC_KEYS:publicKeys,
   RER_BUSINESS_TRUST:JSON.stringify({v:1,issuer:signer.issuer,audience:HOSTED_ORIGIN,subject:signer.installationId,email,keys:{[kid]:publicKey}})},
   outboundService:async request=>{const copy=request.clone();const response=await network.fetch(request);if(response.ok)await approverNetwork.fetch(copy);return response;}});
  try {
   const origin=hosted.origin,request=(absolute,init={})=>{const url=new URL(absolute);assert.equal(url.origin,origin);return hosted.fetch(url.href.slice(origin.length+1),{...init,headers:Object.fromEntries(new Headers(init.headers))});};
   const issued=seconds(),claim=await signJws(pair.privateKey,kid,'rer-owner-claim+jwt',{v:1,iss:signer.issuer,aud:origin,installationId:signer.installationId,email,jti:randomUUID(),iat:issued,exp:issued+300});
   const owner=await nativePerson({request,origin,email,mail:network.mail,claim:{path:'/auth/owner-claim',token:claim}});
   const setup=await owner.call('/setup',{confirm:'yes'},{form:true});assert.equal(setup.status,303);
   const post=async(person,path,data,status=200)=>{const response=await person.call(path,data);assert.equal(response.status,status,await response.clone().text());return response.json();};
   await post(owner,'/api/auth/profile/update',{fields:{name:names.sponsor}});
   await post(owner,'/api/auth/people/invite',{email:approverEmail,name:names.approver},201);
   await post(owner,'/api/auth/people/invite',{email:memberEmail,name:'Synthetic Member'},201);
   const approver=await nativePerson({request,origin,email:approverEmail,mail:approverNetwork.mail});
   const me=async person=>(await(await request(origin+'/api/auth/profile',{headers:{cookie:person.cookie()}})).json()).person;
   const sponsor=await me(owner),human=await me(approver);
   assert.equal(sponsor.name,names.sponsor);assert.equal(human.name,names.approver);
   const sub='synthetic-auth-owner',approverSub='synthetic-auth-approver',iat=seconds();
   const settings=await signJws(pair.privateKey,kid,'rer-business-settings+jwt',{v:1,iss:signer.issuer,aud:origin,sub:signer.installationId,business,email,owner_id:sub,
    jti:randomUUID(),iat,exp:iat+300,rev:1,values:{},logo:null,team:[{id:approverSub,email:approverEmail,name:names.approver,role:'member',invite:1}]});
   const binding=await request(origin+'/api/rer/business-settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({settings})});assert.equal(binding.status,200,await binding.clone().text());
   const surface=JSON.parse(await readFile(new URL('../../agent-surface.json',import.meta.url)));
   const c=createProtocol({fetch:request,origin,surface,signer,person:{email,cookie:owner.cookie(),sub},business,consent:randomUUID(),points:[],agentId:randomUUID(),seq:0,revision:0});
   const document=autonomousPolicy();if(policy==='held')document.rules=[{id:'membership',class:'access',do:'approval',approver:['person:'+approverSub],wait:'PT1H'},{id:'rest',class:'*',do:'autonomous'}];
   await c.adopt(document);assert.ok(c.points.every(point=>point.ok),'signed policy adopted');
   const token=await accessToken(c,{act:{sub:c.agentId,name:names.agent,specialist:surface.specialist}});
   const group=await post(owner,'/api/auth/groups/create',{name:'Synthetic attribution group'},201);
   const people=await(await request(origin+'/api/auth/people',{headers:{cookie:owner.cookie()}})).json(),member=people.find(person=>person.email===memberEmail);assert.ok(member);
   const args={group_id:group.id,person_id:member.id,idempotency_key:randomUUID()};
   const effects=async()=>{const db=await hosted.database('DB');return (await db.prepare("SELECT a.id,a.actor_id,a.subject_id,d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='agent_door_effect' ORDER BY a.id").all()).results;};
   const members=async()=>{const response=await request(origin+'/api/auth/company-apps',{headers:{cookie:owner.cookie()}});assert.equal(response.status,200);const model=await response.json();return model.groups.find(item=>item.id===group.id).members;};
   const before=await members();let answer=await c.tool('auth.groups.add',args,{token});
   if(policy==='held') {
    assert.equal(answer.result?.resultType,'input_required',JSON.stringify(answer.body));assert.deepEqual(await effects(),[]);assert.deepEqual(await members(),before,'pending approval changes no membership');
    const id=answer.result._meta[APPROVAL].id,path='/agents/api/approvals/'+id;
    const detail=await(await request(origin+path,{headers:{cookie:approver.cookie()}})).json();
    assert.deepEqual(detail.approval.prepared_by.agent,{id:c.agentId,name:names.agent});assert.deepEqual(detail.approval.prepared_by.for,{id:sponsor.id,name:names.sponsor});
    const decision={revision:detail.approval.revision,summary_sha256:detail.approval.summary_sha256};
    assert.equal((await request(origin+path+'/approve',{method:'POST',headers:{origin,'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify(decision)})).status,403);
    assert.equal((await request(origin+path+'/approve',{method:'POST',headers:{origin,'content-type':'application/json'},body:JSON.stringify(decision)})).status,401);
    assert.deepEqual(await effects(),[]);assert.deepEqual(await members(),before,'refused approval changes nothing');
    await inspect({stage:'approve',policy,hosted,person:approver,id,decision});
    answer=await c.tool('auth.groups.add',args,{token});
   }
   assert.equal(answer.result?.isError,false,JSON.stringify(answer.body));assert.deepEqual(answer.result.structuredContent,{id:group.id+'/'+member.id});
   const stored=await effects();assert.equal(stored.length,1);const row=stored[0],detail=JSON.parse(row.detail);
   assert.equal(row.actor_id,names.agent+' for '+names.sponsor);assert.equal(detail.agent,c.agentId);assert.equal(detail.sponsor,sponsor.id);
   assert.deepEqual(detail.approvers,policy==='held'?[{id:human.id,name:names.approver}]:[]);
   const current=await members();assert.deepEqual(current.map(person=>person.id),[member.id],'the native membership change completed');
   await c.tool('auth.groups.add',args,{token});assert.deepEqual(await effects(),stored,'successful-key replay adds no second effect');assert.deepEqual(await members(),current);
   const path='/api/auth/audit/export?event=agent_door_effect',exported=await request(origin+path,{headers:{cookie:owner.cookie()}});assert.equal(exported.status,200);
   const result=await exported.json();assert.equal(result.total,1);assert.equal(result.events[0].actor_id,row.actor_id);assert.equal(result.events[0].detail,row.detail);assert.equal(result.events[0].id,row.id);
   for(const headers of [{},{authorization:'Bearer '+token},{cookie:approver.cookie()}]) {
    const denied=await request(origin+path,{headers});assert.equal(denied.status,headers.cookie?403:401);assert.ok(!(await denied.text()).includes(names.approver));
   }
   for(const headers of [{},{authorization:'Bearer '+token}]) {
    const denied=await request(origin+'/app/activity?event=agent_door_effect',{headers});assert.notEqual(denied.status,200);assert.ok(!(await denied.text()).includes(names.sponsor));
   }
   await inspect({stage:'activity',policy,hosted,person:owner,row,detail,exported:result});
   assert.deepEqual(await effects(),stored,'reads and refusals leave the stored effect unchanged');
   console.log('PROBE BASE-AGENT-008 '+policy+': public membership, approval, audit export and Activity -> one attributed native effect; refusals and replay unchanged');
  } finally {await hosted.close();await network.close();await approverNetwork.close();}
 }
}
