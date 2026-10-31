import assert from 'node:assert/strict';
import {randomUUID,webcrypto} from 'node:crypto';
import {openApp} from '../integration/runtime.mjs';
import {nativePerson} from './native-person.mjs';
import {signJws,accessToken,policyEnvelope,autonomousPolicy} from '../../node_modules/@runeditrun/rer/modules/agent-door/conformance/crypto.mjs';

export const heldMembershipPolicy=()=>({schema:'rer-agent-policy/1',catalogue:'rer-agent-classes/1',rules:[{id:'access',class:'access',do:'approval',approver:['sponsor'],wait:'PT1H'},{id:'other',class:'*',do:'autonomous'}],spend:{none:true}});

// Disposable signing authority and native accounts only. The fixture never
// inserts an identity, session, grant, binding or agent result into storage.
export async function authorityFixture(t) {
 const pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const kid=randomUUID(),issuer='https://synthetic-auth-1.invalid',installationId=randomUUID(),business='synthetic-auth-1';
 const publicKey=await webcrypto.subtle.exportKey('jwk',pair.publicKey),keys={[kid]:{...publicKey,kid,alg:'ES256',use:'sig'}};
 const address=n=>['synthetic-auth-'+n,'example.com'].join('@');
 const app=await openApp({bindings:origin=>({
  OWNER_EMAIL:address(1),RER_OWNER_CLAIM_ISSUER:issuer,RER_OWNER_CLAIM_INSTALLATION_ID:installationId,
  RER_OWNER_CLAIM_APP_ORIGIN:origin,RER_OWNER_CLAIM_PUBLIC_KEYS:JSON.stringify(keys),
  RER_BUSINESS_TRUST:JSON.stringify({v:1,issuer,audience:origin,subject:installationId,email:address(1),keys}),
 })});
 t.after(()=>app.close());
 const request=(url,init)=>fetch(url,init),mail={read:async()=>[{text:(await app.link()).href}]};
 const enroll=email=>nativePerson({request,origin:app.origin,email,mail});
 const owner=await nativePerson({request,origin:app.origin,email:address(1),mail,claim:{path:'/auth/bootstrap',token:app.vars.SETUP_TOKEN}});
 const get=async(person,path)=>{
  const response=await app.get(path,{cookie:person.cookie()});
  assert.equal(response.status,200,path);return response.json();
 };
 const post=async(person,path,data,status=200)=>{
  const response=await person.call(path,data);
  const body=await response.json();assert.equal(response.status,status,path+' '+JSON.stringify(body));return body;
 };
 const people={owner};
 for(const [label,n] of [['editor',2],['reader',3],['worker',4],['other',5],['outside',6]]) {
  await post(owner,'/api/auth/people/invite',{email:address(n),name:'Synthetic '+label},201);
  people[label]=await enroll(address(n));
 }
 const directory=await get(owner,'/api/auth/people');
 for(const [label,person] of Object.entries(people)) {
  const n={owner:1,editor:2,reader:3,worker:4,other:5,outside:6}[label];
  person.id=directory.find(p=>p.email===address(n)).id;person.email=address(n);person.sub='synthetic-auth-'+label;
 }
 const groups={};
 for(const label of ['first','second','outside'])groups[label]=await post(owner,'/api/auth/groups/create',{name:'Synthetic '+label},201);
 const change=async data=>{
  const preview=await post(owner,'/api/auth/roles/preview',data);
  return (await post(owner,'/api/auth/roles/apply',{previewId:preview.previewId})).plan;
 };
 const view={people:[people.worker.id,people.other.id,people.editor.id],groups:Object.values(groups).map(g=>g.id)};
 const grants={};
 grants.read=await change({kind:'grant',personId:people.editor.id,roleId:'manager',resources:{view,edit:{}}});
 for(const [label,target] of [['first','worker'],['second','other']])grants[label]=await change({kind:'grant',personId:people.editor.id,roleId:'group-owner',resources:{view,edit:{people:[people[target].id,people.editor.id],groups:[groups[label].id]}}});
 await change({kind:'grant',personId:people.reader.id,roleId:'manager',resources:{view,edit:{}}});
 const iat=Math.floor(Date.now()/1000);
 const signed=await signJws(pair.privateKey,kid,'rer-business-settings+jwt',{
  v:1,iss:issuer,aud:app.origin,sub:installationId,business,email:owner.email,owner_id:owner.sub,
  jti:randomUUID(),iat,exp:iat+300,rev:1,values:{},logo:null,
  team:['editor','reader'].map(label=>({id:people[label].sub,email:people[label].email,name:'Synthetic '+label,role:'member',invite:1})),
 });
 const paired=await app.post('/api/rer/business-settings',{settings:signed});assert.equal(paired.status,200);assert.equal((await paired.json()).rev,1);
 const context={origin:app.origin,signer:{issuer,installationId,kid,privateKey:pair.privateKey},business,revision:0,seq:0,surface:{specialist:'identity steward',tools:[{scope:'directory:read'},{scope:'directory:write'}]}};
 async function policy(document=autonomousPolicy()) {
  const envelope=await policyEnvelope(context,document);
  const response=await app.post('/api/rer/agent-policy',{policy:envelope.policy});
  assert.equal(response.status,200,'signed policy '+await response.text());
  context.seq=envelope.payload.seq;context.revision=envelope.payload.revision;
 }
 async function client(person) {
  const token=await accessToken({...context,person,agentId:'synthetic-auth-agent-'+person.sub,consent:'synthetic-auth-consent-'+person.sub});
  return async function call(name,args={}) {
  // Business tokens stay in the header, never in URLs or fixture diagnostics.
  const version='2026-07-28';
  const answer=await fetch(app.origin+'/mcp',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','mcp-protocol-version':version,'mcp-method':'tools/call','mcp-name':name},body:JSON.stringify({jsonrpc:'2.0',id:randomUUID(),method:'tools/call',params:{name,arguments:args,_meta:{'io.modelcontextprotocol/protocolVersion':version}}})});
  const body=await answer.json();return {status:answer.status,...body.result,error:body.error};
  };
 }
 const call=async(person,name,args={})=>(await client(person))(name,args);
 const approve=async(person,pending)=>{
  const id=pending._meta['com.runeditrun/approval'].id;
  const {approval}=await get(person,'/agents/api/approvals/'+id);
  return post(person,'/agents/api/approvals/'+id+'/approve',{revision:approval.revision,summary_sha256:approval.summary_sha256});
 };
 const members=async()=>(await get(owner,'/api/auth/company-apps')).groups;
 return {app,people,groups,grants,get,post,change,policy,call,client,approve,members};
}
