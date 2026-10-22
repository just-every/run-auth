import assert from 'node:assert/strict';
import {samlInstall,addApp,idpCertificates,serviceProvider,signIn,posted} from './saml-helpers.mjs';
import {passkeyPerson,post} from './agents-helpers.mjs';
import {authenticate} from './webauthn.mjs';
import {cookieOf} from './runtime.mjs';
import {decisionProof,decide} from './access-decisions-flow.mjs';
import {scimServer} from './scim-server.mjs';

const result=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};

// A reviewer reduces existing direct and group-derived access; the real SCIM
// transport and signed SAML response must observe the same persistent cap.
export async function reviewReductionFlow(t) {
 const r=await samlInstall(t),manager=await passkeyPerson(r,'manager','synthetic-auth-10@example.com','member');
 manager.cookie=cookieOf((await authenticate(r,manager.key)).response);
 const edge=await scimServer(t,'synthetic-auth-11');r.scimServer=edge.url;
 const entity='https://synthetic-auth-12.example.com';
 const app=await addApp(r,{name:'Synthetic review workspace',entityId:entity,acsUrl:entity+'/acs',assign:[],sign:'both',attributes:[{name:'role',source:'role'}]});
 const other=await addApp(r,{name:'Synthetic separate workspace',entityId:'https://synthetic-auth-13.example.com',acsUrl:'https://synthetic-auth-13.example.com/acs',assign:[]});
 for(const appId of [app.id,other.id])for(const principalId of ['ada','manager'])await result(await r.admin('company-apps/assign',{appId,principalType:'person',principalId,role:'editor'}));
 const group=await result(await r.admin('groups/create',{name:'Synthetic review team'}),201);
 await result(await r.admin('groups/add',{groupId:group.id,personId:'bob'}));
 await result(await r.admin('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id,role:'editor'}));
 const api=await result(await r.admin('resource-apis/register',{appId:app.id,name:'Synthetic reviewed API',audience:entity+'/api',scopes:['read','write'],roles:[{role:'editor',scopes:['read','write'],resources:['record:1']},{role:'viewer',scopes:['read'],resources:['record:1']}],resources:[{id:'record:1'}]}),201);
 const check=async(action='write')=>result(await r.call('/api/auth/resource-apis/check',post({apiId:api.id,action,resource:'record:1'},r.ada)));
 assert.equal((await check()).allowed,true);
 await result(await r.admin('provisioning/connect',{appId:app.id,baseUrl:'https://scim.example.com/scim/v2',token:'synthetic-auth-11'}),201);
 const roles=[{role:'viewer',level:0},{role:'reader',level:0},{role:'editor',level:10},{role:'co-editor',level:10},{role:'admin',level:20}];
 const publish=()=>r.admin('reviews/role-order',{appId:app.id,roles});
 assert.equal((await r.call('/api/auth/reviews/role-order',post({appId:app.id,roles},manager.cookie))).status,403);
 assert.equal((await r.call('/api/auth/reviews/role-order',post({appId:app.id,roles},r.ada))).status,403);
 const first=await result(await publish());
 for(const invalid of [[...roles,roles[0]],[{role:'viewer',level:0.5}],[{role:'viewer',level:Infinity}],Array.from({length:101},(_,i)=>({role:'synthetic-auth-'+i,level:i}))])assert.equal((await r.admin('reviews/role-order',{appId:app.id,roles:invalid})).status,400);
 const review=await result(await r.admin('reviews/create',{name:'Synthetic role reduction',reviewerId:'manager',periodStart:r.now-86400000,periodEnd:r.now,dueAt:r.now+3600000}),201);
 const read=async()=>{const model=await result(await r.call('/api/auth/reviews',{cookie:r.owner.cookie}));return model.reviews.find(x=>x.id===review.id);};
 const items=(await read()).items,ada=items.find(x=>x.subject_id==='ada'&&x.app_id===app.id),bob=items.find(x=>x.subject_id==='bob'),self=items.find(x=>x.subject_id==='manager'&&x.app_id===app.id),otherAda=items.find(x=>x.subject_id==='ada'&&x.app_id===other.id);
 const params=(item,newRole='viewer')=>({kind:'review',targetId:item.id,operation:'reduce',newRole,reason:'Read access is sufficient'});
 for(const [newRole,status] of [['admin',400],['editor',400],['co-editor',400],['unknown',409]])assert.equal((await decide(r,manager,params(ada,newRole))).status,status);
 assert.equal((await decide(r,manager,params(self))).status,403);
 assert.equal((await decide(r,manager,params(otherAda))).status,409,'another app does not inherit a role order');
 const pending=await decisionProof(r,manager,params(ada));assert.ok(pending.transaction);
 const second=await result(await publish());assert.notEqual(first.revision,second.revision);
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:pending.transaction,response:pending.response},pending.cookie))).status,409,'publication invalidates an in-flight passkey decision');
 edge.fail(10,503);
 const proof=await decisionProof(r,manager,params(ada));assert.ok(proof.transaction);
 await result(await r.call('/api/auth/decisions/commit',post({transaction:proof.transaction,response:proof.response},proof.cookie)));
 assert.equal((await r.call('/api/auth/decisions/commit',post({transaction:proof.transaction,response:proof.response},proof.cookie))).status,400,'the reduction commits once');
 assert.equal((await read()).items.find(x=>x.id===ada.id).remediation.complete,false,'dispatch failure cannot claim verified reduction');
 assert.equal((await check()).allowed,false,'the resource API loses write access immediately');
 assert.equal((await check('read')).allowed,true,'the resource API preserves the lower grant');
 const preview=await result(await r.admin('provisioning/preview',{appId:app.id}));assert.equal(preview.changes.find(x=>x.id==='ada').attributes.role,'viewer');
 assert.equal([...edge.users.values()].find(x=>x.externalId==='ada').roles[0].value,'editor','remote failure remains visible');
 edge.faults.length=0;await result(await r.admin('provisioning/retry',{appId:app.id}));
 assert.equal([...edge.users.values()].find(x=>x.externalId==='ada').roles[0].value,'viewer');
 assert.equal((await read()).items.find(x=>x.id===ada.id).remediation.complete,true);
 const sp=serviceProvider(r,{entity,idpCerts:await idpCertificates(r)}),postedResponse=await posted(await signIn(r,sp,r.ada));
 const saml=await sp.validatePostResponseAsync({SAMLResponse:postedResponse.SAMLResponse});assert.equal(saml.profile.role,'viewer');
 await result(await decide(r,manager,params(bob)));
 assert.equal([...edge.users.values()].find(x=>x.externalId==='bob').roles[0].value,'viewer','group assignments are capped per person');
 // A later direct grant cannot override either kind of reviewed cap.
 for(const principalId of ['ada','bob'])await result(await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId,role:'admin'}));
 await r.restart();
 const persisted=await result(await r.admin('provisioning/preview',{appId:app.id}));
 for(const personId of ['ada','bob'])assert.equal(persisted.changes.find(x=>x.id===personId).attributes.role,'viewer');
 assert.deepEqual((await result(await r.call('/api/auth/launcher',{cookie:r.ada}))).apps.map(x=>x.id).sort(),[app.id,other.id].sort());
 // Reordering cannot turn the saved cap into a higher grant: it closes access
 // until an administrator explicitly restores the reviewed assignment.
 await result(await publish());
 assert.deepEqual((await result(await r.call('/api/auth/launcher',{cookie:r.ada}))).apps.map(x=>x.id),[other.id]);
 assert.equal((await check('read')).allowed,false,'a stale cap cannot bypass the hierarchy through resource checks');
 assert.equal([...edge.users.values()].find(x=>x.externalId==='ada').active,false);
 assert.equal((await r.call('/api/auth/reviews/reduction-clear',post({appId:app.id,personId:'ada',reason:'Restore assigned role'},manager.cookie))).status,403);
 await result(await r.admin('reviews/reduction-clear',{appId:app.id,personId:'ada',reason:'Administrator confirms the new hierarchy and assignment'}));
 assert.equal([...edge.users.values()].find(x=>x.externalId==='ada').active,true);
 assert.equal([...edge.users.values()].find(x=>x.externalId==='ada').roles[0].value,'admin');
}
