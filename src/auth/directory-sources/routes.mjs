import {syncObligations} from '../obligations/sources.mjs';
import {directorySourceHealth,recordDirectoryFailure} from './followup.mjs';
import {AuthError,one,all,run,hash,random,fail,json,auditDetail} from '../core.mjs';
import {authority,requireAuthority} from '../local-email.mjs';
import {seal,unseal} from '../keys.mjs';
import {fetchDirectorySnapshot} from './index.mjs';
import {directoryCredential,validateCredential} from './credential.mjs';
import {object} from './network.mjs';
import {reviewSnapshot,publicReview} from './review.mjs';
import {approveSnapshot} from './apply.mjs';
import {DIRECTORY_SOURCES,LIMITATIONS,administrator,sourceOf,publicSource,requireLiveSource,combine,stageSnapshot} from './store.mjs';
export {DIRECTORY_SOURCES} from './store.mjs';
export {directorySourceScim} from './ingress.mjs';
export const isDirectorySourceAction=action=>['/directory-sources/create','/directory-sources/disable','/directory-sources/pull','/directory-sources/preview','/directory-sources/approve'].includes(action);
const CONFIG_FIELDS=new Set(['name','department','title','location']);
export async function directorySourceModel(ctx) {
 const sources=await all(ctx,'SELECT * FROM auth_directory_sources ORDER BY created_at,id');
 const snapshots=await all(ctx,'SELECT id,source_id,digest,complete,state,reasons,created_at,approved_by,approved_at,error FROM auth_directory_snapshots ORDER BY created_at DESC,id DESC LIMIT 100');
 return {sources:await Promise.all(sources.map(async source=>({...publicSource(source),freshness:await directorySourceHealth(ctx,source)}))),snapshots:snapshots.map(row=>({id:row.id,sourceId:row.source_id,digest:row.digest,complete:Boolean(row.complete),state:row.state,reasons:JSON.parse(row.reasons),createdAt:row.created_at,approvedBy:row.approved_by,approvedAt:row.approved_at,error:row.error})),limitations:LIMITATIONS};
}
export async function directorySourceRead(ctx,request) {
 const s=await administrator(ctx,request),model=await directorySourceModel(ctx),snapshotId=new URL(request.url).searchParams.get('snapshotId');
 const preview=snapshotId?publicReview(await reviewSnapshot(ctx,s.person_id,snapshotId)):null;
 const current=await administrator(ctx,request);if(current.id!==s.id)fail('session_authority_changed',403);
 return json({...model,preview});
}
export async function pullDirectorySource(ctx,source,guard) {
 try {
 const config={kind:source.kind,baseUrl:source.base_url??undefined,organizationBinding:source.organization_binding};
 const credential=await directoryCredential(ctx,config,await unseal(ctx,'directory-source:'+source.id,source.sealed_credential));
 const snapshot=await fetchDirectorySnapshot(ctx,config,credential);
 const result=await stageSnapshot(ctx,source,snapshot,guard);
 await syncObligations(ctx);return result;
 }catch(error){
  if(error instanceof AuthError&&!['directory_source_changed','directory_source_authority_changed'].includes(error.message)){await recordDirectoryFailure(ctx,source,error.message);await syncObligations(ctx);}
  throw error;
 }
}
export async function directorySourceAction(ctx,request,action,data) {
 const s=await administrator(ctx,request,action!=='/directory-sources/preview');
 if(!object(data))fail('directory_source_invalid_configuration');
 if(action==='/directory-sources/preview'){
  const preview=await reviewSnapshot(ctx,s.person_id,data.snapshotId);
  if(data.sourceId!==undefined&&data.sourceId!==preview.sourceId)fail('directory_source_not_found',404);
  return json(publicReview(preview));
 }
 if(action==='/directory-sources/approve')return approveSnapshot(ctx,s,data);
 const human=authority(ctx,s,['owner','admin']);
 if(action==='/directory-sources/create'){
  if(data.confirm!==true)fail('explicit_directory_source_confirmation_required',403);
  const {kind}=data,mode=data.mode??'pull',name=typeof data.name==='string'?data.name.trim():'';
  if(!['okta','entra','google','scim'].includes(kind)||!['pull','push'].includes(mode)||mode==='push'&&kind!=='scim'||!name||name.length>48||/[\x00-\x1f\x7f]/.test(name)||!Array.isArray(data.fields)||data.fields.length>4||data.fields.some(field=>!CONFIG_FIELDS.has(field))||new Set(data.fields).size!==data.fields.length||typeof data.organizationBinding!=='string'||!data.organizationBinding||data.organizationBinding.length>512)fail('directory_source_invalid_configuration');
  const config={kind,baseUrl:data.baseUrl,organizationBinding:data.organizationBinding},id=random();let snapshot=null,credential=null,ingressToken=null;
  if(mode==='push'){
   if(data.baseUrl!==undefined&&data.baseUrl!==null&&data.baseUrl!==''||data.credential!==undefined&&data.credential!==null&&data.credential!==''||data.organizationBinding!==(ctx.issuer??ctx.origin))fail('directory_source_binding_refused',403);
   ingressToken=random();
  }else{
   credential=validateCredential(kind,data.credential);
   snapshot=await fetchDirectorySnapshot(ctx,config,await directoryCredential(ctx,config,credential));
   if(snapshot.complete!==true)fail('directory_source_incomplete_registration',409);
  }
  const done=await run(ctx,`INSERT INTO auth_directory_sources(id,kind,mode,name,base_url,organization_binding,sealed_credential,ingress_hash,fields,created_by,owner_version,created_at,next_poll_at) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ${human.clause}`,
   id,kind,mode,name,mode==='push'?null:data.baseUrl??null,data.organizationBinding,credential?await seal(ctx,'directory-source:'+id,credential):null,ingressToken?await hash(ingressToken):null,JSON.stringify([...data.fields].sort()),s.person_id,s.person_version,ctx.now(),mode==='pull'?ctx.now()+15*60000:null,...human.args);
  await requireAuthority(ctx,s,human);if(!done.meta.changes)fail('session_authority_changed',403);
  const source=await sourceOf(ctx,id),staged=snapshot?await stageSnapshot(ctx,source,snapshot,combine(human,await requireLiveSource(ctx,source))):{};
  await auditDetail(ctx,s.person_id,'directory_source_created',id,{kind,mode,name,fields:data.fields,organizationBinding:data.organizationBinding});
  return json({source:publicSource(await sourceOf(ctx,id)),sourceId:id,...staged,...(ingressToken?{ingressToken,scimBase:(ctx.issuer??ctx.origin)+DIRECTORY_SOURCES+'/scim/'+id}:{}),limitations:LIMITATIONS},201);
 }
 const source=await sourceOf(ctx,data.sourceId),guard=combine(human,await requireLiveSource(ctx,source));
 if(action==='/directory-sources/disable'){
  if(data.confirm!==true)fail('explicit_directory_source_confirmation_required',403);
  const done=await run(ctx,`UPDATE auth_directory_sources SET disabled_at=?,sealed_credential=NULL,ingress_hash=NULL,next_poll_at=NULL,revision=revision+1 WHERE id=? AND ${guard.clause}`,ctx.now(),source.id,...guard.args);
  await requireAuthority(ctx,s,human);if(!done.meta.changes)fail('directory_source_changed',409);
  await syncObligations(ctx);await auditDetail(ctx,s.person_id,'directory_source_disabled',source.id,{});return json({ok:true});
 }
 if(action==='/directory-sources/pull'){
  if(source.mode!=='pull')fail('directory_source_pull_refused',409);
  return json({sourceId:source.id,...await pullDirectorySource(ctx,source,guard)},202);
 }
 fail('not_found',404);
}
