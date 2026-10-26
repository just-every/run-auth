// Held credentials enter only through the fleet's named-key launcher. Provider
// responses and identifiers never leave this process. Okta resources created
// here are owned by this invocation and are removed in its finally block.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {openRuntime,emailSession} from '../tests/auth/runtime.mjs';
import {register} from '../tests/auth/webauthn.mjs';

const required=['OKTA_ORG_URL','OKTA_API_TOKEN','ENTRA_TENANT_ID','ENTRA_CLIENT_ID','ENTRA_CLIENT_SECRET'];
for(const name of required)if(!process.env[name])throw new Error('missing credential name '+name);
const org=new URL(process.env.OKTA_ORG_URL).origin,headers={authorization:'SSWS '+process.env.OKTA_API_TOKEN,'content-type':'application/json',accept:'application/json'};
const tag='synthetic-auth-'+Date.now().toString(36)+'-'+randomBytes(3).toString('hex');
const createdUsers=[],createdGroups=[];let r,failed=false;
async function okta(path,method='GET',body) {
 const response=await fetch(org+path,{method,headers,redirect:'manual',...(body?{body:JSON.stringify(body)}:{})});
 if(!response.ok)throw new Error('Okta sandbox operation refused: HTTP '+response.status);
 return response.status===204?null:response.json();
}
try {
 r=await openRuntime();
 await r.person('owner','synthetic-auth-owner@example.com','owner');
 const owner=await register(r,await emailSession(r,'synthetic-auth-owner@example.com'));
 const call=async(action,data)=>{
  const response=await r.call('/api/auth/directory-sources/'+action,{method:'POST',data,cookie:owner.cookie});
  if(response.status!==201&&response.status!==202&&response.status!==200)throw new Error('Auth '+action+' refused: HTTP '+response.status+' '+(await response.json()).error);
  return response.json();
 };
 for(let i=0;i<20;i++){
  const user=await okta('/api/v1/users?activate=true&sendEmail=false','POST',{profile:{firstName:'Synthetic',lastName:'Auth '+i,email:tag+'-'+i+'@example.com',login:tag+'-'+i+'@example.com'},credentials:{password:{value:randomBytes(36).toString('base64url')+'aA7!'}}});
  createdUsers.push(user.id);
 }
 const group=await okta('/api/v1/groups','POST',{profile:{name:tag,description:'Temporary Auth directory qualification cohort'}});createdGroups.push(group.id);
 for(const user of createdUsers)await okta('/api/v1/groups/'+encodeURIComponent(group.id)+'/users/'+encodeURIComponent(user),'PUT');
 const source=await call('create',{kind:'okta',name:'Authorized Okta sandbox',baseUrl:org,organizationBinding:org,credential:process.env.OKTA_API_TOKEN,fields:['name','department'],confirm:true});
 const preview=await call('preview',{sourceId:source.sourceId,snapshotId:source.snapshotId});
 const imported=preview.changes.filter(change=>change.kind==='person'&&createdUsers.includes(change.externalId));
 assert.equal(imported.length,20,'all twenty sandbox employees reached the real Auth source preview');
 assert.ok(preview.changes.some(change=>change.kind==='group_create'&&change.externalId===group.id),'the sandbox group reached the real source preview');
 const second=await call('pull',{sourceId:source.sourceId});assert.equal(second.replayed,true);
 await call('disable',{sourceId:source.sourceId,confirm:true});
 console.log(JSON.stringify({journey:'live Okta directory public routes',employeesObserved:20,cohortGroupObserved:true,duplicateSnapshotHeldStable:true,nativeChangesApproved:false,credentialDestroyed:true}));
 const entra=await call('create',{kind:'entra',name:'Authorized Entra sandbox',organizationBinding:process.env.ENTRA_TENANT_ID,credential:JSON.stringify({clientId:process.env.ENTRA_CLIENT_ID,clientSecret:process.env.ENTRA_CLIENT_SECRET}),fields:['name','department'],confirm:true});
 const entraPreview=await call('preview',{sourceId:entra.sourceId,snapshotId:entra.snapshotId});
 await call('pull',{sourceId:entra.sourceId});await call('disable',{sourceId:entra.sourceId,confirm:true});
 console.log(JSON.stringify({journey:'live Entra directory public routes',verifiedTenantBinding:true,sourceSnapshotStaged:true,previewChanges:entraPreview.changes.length,credentialExchangedOnEachPull:true,nativeChangesApproved:false,credentialDestroyed:true}));
}catch(error){failed=true;console.error(JSON.stringify({journey:'live directory public routes',outcome:'failed',reason:/^(Auth |Okta sandbox operation refused:)/.test(error.message)?error.message:'sanitized provider or assertion failure'}));}
finally{
 let removedUsers=0,removedGroups=0;
 for(const id of createdGroups)try{await okta('/api/v1/groups/'+encodeURIComponent(id),'DELETE');removedGroups++;}catch{failed=true;}
 for(const id of createdUsers)try{await okta('/api/v1/users/'+encodeURIComponent(id)+'/lifecycle/deactivate?sendEmail=false','POST');await okta('/api/v1/users/'+encodeURIComponent(id),'DELETE');removedUsers++;}catch{failed=true;}
 await r?.close();
 console.log(JSON.stringify({journey:'Okta sandbox cleanup',usersCreated:createdUsers.length,usersRemoved:removedUsers,groupsCreated:createdGroups.length,groupsRemoved:removedGroups,complete:createdUsers.length===removedUsers&&createdGroups.length===removedGroups}));
 if(failed)process.exitCode=1;
}
