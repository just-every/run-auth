import {all,one,random,hash,json,fail} from '../core.mjs';
import {authority,requireAuthority} from '../local-email.mjs';
import {domainName} from '../domains/ownership.mjs';
import {configurationHash} from '../domain-policy.mjs';
import {seal} from '../keys.mjs';
import {setupProvider} from './setup-config.mjs';
import {setupOwner,setupById,setupConfiguration,setupLabel,requireSetupCreator,mappingPreview,mappingGuard,setupPreview,SETUP_LIFETIME} from './setup-state.mjs';
import {beginSetupTest} from './setup-callback.mjs';
export {federationProviders} from './setup-state.mjs';
export {federationSetupRoute} from './setup-callback.mjs';

export const FEDERATION_READ='/api/auth/federation';
export const isFederationAction=path=>['/federation/create','/federation/test','/federation/preview','/federation/activate','/federation/disable'].includes(path);
function only(data,keys) {
 if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(key=>!keys.includes(key)))fail('invalid_federation_request');
}
const publicPreview=({provider,...preview})=>preview;
function auditStatements(ctx,owner,event,id,detail) {
 return [ctx.db.prepare('INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,?,?,? WHERE changes()=1').bind(owner.person_id,event,id,ctx.now()),
 ctx.db.prepare('INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE changes()=1').bind(JSON.stringify(detail))];
}
async function committed(ctx,owner,guard,statements) {
 const results=await ctx.db.batch(statements);
 if(!results[0].meta.changes){await requireAuthority(ctx,owner,guard);fail('federation_setup_changed',409);}
 return results;
}
export async function federationRead(ctx,request) {
 await setupOwner(ctx,request,{write:false});
 const selected=new URL(request.url).searchParams.get('federation');let preview=null,previewError=null;
 if(selected)try{preview=publicPreview(await setupPreview(ctx,await setupById(ctx,selected)));}catch(error){if(!error.status)throw error;previewError=error.message;}
 const rows=await all(ctx,'SELECT id,provider_id,domain,state,config_hash,revision,tested_subject,tested_at,created_at,activated_at FROM auth_federation_setups ORDER BY created_at DESC,id');
 return json({preview,previewError,setups:rows.map(row=>({id:row.id,providerId:row.provider_id,domain:row.domain,state:row.state,configurationHash:row.config_hash,revision:row.revision,testedSubject:row.tested_subject,testedAt:row.tested_at,createdAt:row.created_at,activatedAt:row.activated_at})),policy:{ownerOnly:true,exactDomain:true,reviewedSubjectsOnly:true,representativeTestCreatesSession:false}});
}
async function create(ctx,owner,data) {
 only(data,['domain','provider','confirm']);if(data.confirm!==true)fail('federation_explicit_consent_required',403);
 const domain=domainName(data.domain),provider=await setupProvider(ctx,data.provider),people=await mappingPreview(ctx,domain,provider);
 if((ctx.configuredUpstreamProviders??ctx.upstreamProviders??[]).some(p=>p.id===provider.id&&!p.federationSetupId)||await one(ctx,'SELECT provider_id FROM auth_employer_providers WHERE provider_id=?',provider.id))fail('federation_provider_id_in_use',409);
 const id=random(),configuration=await configurationHash(provider),sealed=await seal(ctx,setupLabel(ctx,id),provider),guard=authority(ctx,owner,['owner']),mapping=mappingGuard(ctx,domain,provider,people);
 await committed(ctx,owner,guard,[ctx.db.prepare(`INSERT INTO auth_federation_setups(id,provider_id,domain,config_hash,sealed_config,state,created_by,owner_version,revision,created_at) SELECT ?,?,?,?,?,'draft',?,?,1,? WHERE ${guard.clause} AND ${mapping.clause} AND NOT EXISTS(SELECT 1 FROM auth_federation_setups WHERE provider_id=? AND state<>'disabled') AND (SELECT COUNT(*) FROM auth_federation_setups WHERE state<>'disabled')<8`)
  .bind(id,provider.id,domain,configuration,sealed,owner.person_id,owner.person_version,ctx.now(),...guard.args,...mapping.args,provider.id),
  ...auditStatements(ctx,owner,'federation_setup_created',id,{providerId:provider.id,domain,configurationHash:configuration,subjects:people.length})]);
 return json(publicPreview(await setupPreview(ctx,await setupById(ctx,id))),201);
}
async function test(ctx,request,owner,row,provider,data) {
 only(data,['id','subject']);requireSetupCreator(row,owner);
 if(!['draft','testing','tested'].includes(row.state)||typeof data.subject!=='string'||!Object.hasOwn(provider.subjectEmails,data.subject))fail('federation_representative_required',409);
 const people=await mappingPreview(ctx,row.domain,provider),mapping=mappingGuard(ctx,row.domain,provider,people),browser=random(),guard=authority(ctx,owner,['owner']);
 await committed(ctx,owner,guard,[ctx.db.prepare(`UPDATE auth_federation_setups SET state='testing',test_session_id=?,test_binding_hash=?,test_until=?,test_subject=?,tested_subject=NULL,tested_at=NULL,revision=revision+1 WHERE id=? AND revision=? AND state IN ('draft','testing','tested') AND ${guard.clause} AND ${mapping.clause}`)
  .bind(owner.id,await hash(browser),ctx.now()+SETUP_LIFETIME,data.subject,row.id,row.revision,...guard.args,...mapping.args),
  ...auditStatements(ctx,owner,'federation_test_started',row.id,{providerId:row.provider_id,configurationHash:row.config_hash,subject:data.subject})]);
 return beginSetupTest(ctx,request,await setupById(ctx,row.id),provider,browser);
}
async function activate(ctx,owner,row,provider,data) {
 only(data,['id','digest','revision','confirm']);requireSetupCreator(row,owner);
 if(data.confirm!==true)fail('federation_explicit_consent_required',403);
 const preview=await setupPreview(ctx,row);
 if(row.state!=='tested'||!row.tested_subject||!row.tested_at||data.revision!==row.revision||data.digest!==preview.digest)fail('federation_preview_changed',409);
 if(provider.metadataValidUntil&&Date.parse(provider.metadataValidUntil)<=ctx.now())fail('expired_federation_metadata',409);
 if(row.config_hash!==await configurationHash(provider))fail('federation_configuration_changed',409);
 const guard=authority(ctx,owner,['owner']),mapping=mappingGuard(ctx,row.domain,provider,preview.people);
 if(provider.preset!=='saml'&&!await one(ctx,"SELECT provider_id FROM auth_federation_test_providers WHERE setup_id=? AND provider_id=? AND status='linked'",row.id,row.provider_id))fail('federation_test_required',409);
 const statements=[ctx.db.prepare(`UPDATE auth_federation_setups SET state='active',activated_at=?,revision=revision+1,test_session_id=NULL,test_binding_hash=NULL,test_subject=NULL,test_until=NULL WHERE id=? AND revision=? AND state='tested' AND ${guard.clause} AND ${mapping.clause} AND (SELECT COUNT(*) FROM auth_federation_setups WHERE state='active')<8`)
  .bind(ctx.now(),row.id,row.revision,...guard.args,...mapping.args)];
 if(provider.preset!=='saml')statements.push(ctx.db.prepare(`INSERT INTO oa_identity_providers(provider_id,preset,status,issuer,client_id,jwks_uri,authorization_endpoint,token_endpoint,algorithms,token_auth_method,response_iss,interface_version,linked_at,jwks,jwks_fetched_at)
  SELECT provider_id,preset,status,issuer,client_id,jwks_uri,authorization_endpoint,token_endpoint,algorithms,token_auth_method,response_iss,interface_version,MAX(linked_at,?),jwks,jwks_fetched_at FROM auth_federation_test_providers WHERE setup_id=? AND provider_id=? AND changes()=1
  ON CONFLICT(provider_id) DO UPDATE SET preset=excluded.preset,status=excluded.status,issuer=excluded.issuer,client_id=excluded.client_id,jwks_uri=excluded.jwks_uri,authorization_endpoint=excluded.authorization_endpoint,token_endpoint=excluded.token_endpoint,algorithms=excluded.algorithms,token_auth_method=excluded.token_auth_method,response_iss=excluded.response_iss,interface_version=excluded.interface_version,linked_at=MAX(oa_identity_providers.linked_at+1,excluded.linked_at),jwks=excluded.jwks,jwks_fetched_at=excluded.jwks_fetched_at,pending_issuer=NULL,pending_client_id=NULL,pending_preset=NULL,pending_at=NULL`).bind(ctx.now(),row.id,row.provider_id));
 statements.push(...auditStatements(ctx,owner,'federation_activated',row.id,{providerId:row.provider_id,domain:row.domain,digest:preview.digest,configurationHash:row.config_hash,revision:row.revision+1,testedSubject:row.tested_subject,people:preview.people,consent:true}));
 await committed(ctx,owner,guard,statements);
 return json({ok:true,id:row.id,state:'active',revision:row.revision+1,configurationHash:row.config_hash});
}
export async function federationAction(ctx,request,action,data) {
 if(!isFederationAction(action))fail('not_found',404);
 if(request.method!=='POST')fail('method_not_allowed',405);
 if(request.headers.get('origin')!==ctx.origin||request.headers.get('sec-fetch-site')==='cross-site')fail('origin_required',403);
 const owner=await setupOwner(ctx,request);
 if(action==='/federation/create')return create(ctx,owner,data);
 const row=await setupById(ctx,data?.id);if(row.state==='disabled')fail('federation_setup_changed',409);
 const provider=await setupConfiguration(ctx,row);
 if(action==='/federation/test')return test(ctx,request,owner,row,provider,data);
 if(action==='/federation/preview') {only(data,['id']);return json(publicPreview(await setupPreview(ctx,row)));}
 if(action==='/federation/activate')return activate(ctx,owner,row,provider,data);
 only(data,['id','revision','confirm']);
 if(data.confirm!==true)fail('federation_explicit_consent_required',403);
 if(!Number.isSafeInteger(data.revision)||data.revision!==row.revision||row.state==='disabled')fail('federation_setup_changed',409);
 const guard=authority(ctx,owner,['owner']);
 await committed(ctx,owner,guard,[ctx.db.prepare(`UPDATE auth_federation_setups SET state='disabled',sealed_config='',revision=revision+1,test_session_id=NULL,test_binding_hash=NULL,test_until=NULL,test_subject=NULL WHERE id=? AND revision=? AND state<>'disabled' AND ${guard.clause}`).bind(row.id,row.revision,...guard.args),
  ...auditStatements(ctx,owner,'federation_disabled',row.id,{providerId:row.provider_id,configurationHash:row.config_hash,revision:row.revision+1,consent:true})]);
 return json({ok:true,id:row.id,state:'disabled',revision:row.revision+1});
}
