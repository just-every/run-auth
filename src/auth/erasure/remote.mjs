import {importJWK,SignJWT} from 'jose';
import {random,one,all,run,fail,AuthError} from '../core.mjs';
import {seal,unseal} from '../keys.mjs';
import {outboundUrl} from '../outbound.mjs';
import {LOGOUT_EVENT,FENCE_EVENT} from '../links/logout.mjs';
import {organizationOf,issuerOf,blocked,scimRequest,scimConnection,fenceConnection,validateFreshConnection} from './connection.mjs';

const rows=(plan,table)=>plan.stores.get(table)?.rows||[];
const mandatory=kind=>['authority-fence','scim-deactivate','scim-clear-group'].includes(kind);
const deletion=kind=>['scim-delete','partner-delete'].includes(kind);
const opaque=row=>typeof row.partner==='string'&&row.partner.startsWith('opaque:');
const label=value=>String(value||'Unidentified application').replace(/[\x00-\x1f\x7f]/g,'').slice(0,120);
const baseBinding=ctx=>({version:2,organization:organizationOf(ctx),issuer:issuerOf(ctx)});
async function signer(ctx,plan,alg='ES256') {
 const key=rows(plan,'auth_signing_keys').filter(k=>!k.retire_at&&JSON.parse(k.public_jwk).alg===alg).sort((a,b)=>b.published_at-a.published_at)[0];
 if(!key)return null;
 return {jwk:await unseal(ctx,key.kid,key.encrypted_private),kid:key.kid,alg};
}
function appLabel(plan,task) {
 const appId=task.work?.connector?.app_id;
 const app=rows(plan,'auth_apps').find(app=>app.id===appId||app.name===task.partner||[app.launch_url,app.acs].some(url=>{try{return new URL(url).origin===task.partner;}catch{return false;}}));
 const client=rows(plan,'auth_clients').find(client=>client.origin===task.partner);
 return label(app?.name||client?.name);
}
export async function remoteWork(ctx,plan,destinations=[]) {
 const selected=new Set(destinations),tasks=[];
 for(const task of plan.remote) {
  const appId=task.work?.connector?.app_id;
  let work={...baseBinding(ctx),type:'partner',partner:task.partner},connection=null;
  if(task.work?.connector) {
   const original=task.work,account=rows(plan,'auth_scim_accounts').find(account=>account.app_id===appId&&account.remote_id===original.remoteId&&(original.resource==='Groups'?account.subject_type==='group':account.subject_type==='person'));
   work={...baseBinding(ctx),type:'scim',partner:task.partner,appId,baseUrl:original.connector.base_url,remoteId:String(original.remoteId),resource:original.resource,externalId:account?.subject_id??null};
   connection={token:await unseal(ctx,'scim:'+appId,original.connector.sealed_token)};
  }
  const prepared={kind:task.kind,partner:task.partner,appLabel:appLabel(plan,task),work,connection};
  tasks.push(prepared);
  if(task.kind==='scim-delete')tasks.push({...prepared,kind:work.resource==='Groups'?'scim-clear-group':'scim-deactivate'});
 }
 for(const client of rows(plan,'auth_clients')) {
  if(!client.logout_uri)continue;
  for(const grant of rows(plan,'auth_grants').filter(g=>g.client_id===client.id&&(plan.reset||plan.kind==='app'&&client.id===plan.target||plan.kind==='person'&&g.person_id===plan.target))) {
   const subject=rows(plan,'auth_subjects').find(s=>s.sector_id===client.sector_id&&s.person_id===grant.person_id)?.subject;
   const signing=await signer(ctx,plan),partner=new URL(client.logout_uri).origin;
   tasks.push({kind:'authority-fence',partner,appLabel:label(client.name),connection:signing?{signing}:null,
    work:subject?{...baseBinding(ctx),type:'fence',partner,url:client.logout_uri,keyId:signing?.kid??null,alg:signing?.alg??'ES256',acceptReplay:true,claims:{aud:client.id,sub:subject,jti:random(),events:{[FENCE_EVENT]:{}}}}:null});
  }
 }
 for(const logged of rows(plan,'auth_oidc_sessions')) {
  const session=rows(plan,'auth_sessions').find(s=>s.id===logged.session_id),client=rows(plan,'auth_oidc_clients').find(c=>c.client_id===logged.client_id);
  if(!session||!client?.backchannel_logout_uri||!(plan.reset||plan.kind==='person'&&session.person_id===plan.target||plan.kind==='app'&&client.app_id===plan.target))continue;
  const subject=client.subject_type==='public'?session.person_id:rows(plan,'auth_subjects').find(s=>s.sector_id==='oidc:'+client.client_id&&s.person_id===session.person_id)?.subject;
  const signing=await signer(ctx,plan,client.id_token_alg),partner=new URL(client.backchannel_logout_uri).origin;
  tasks.push({kind:'authority-fence',partner,appLabel:label(rows(plan,'auth_apps').find(app=>app.id===client.app_id)?.name),connection:signing?{signing}:null,
   work:subject?{...baseBinding(ctx),type:'fence',partner,url:client.backchannel_logout_uri,keyId:signing?.kid??null,alg:client.id_token_alg,acceptReplay:false,claims:{aud:client.client_id,sub:subject,sid:session.id,jti:random(),events:{[LOGOUT_EVENT]:{}}}}:null});
 }
 tasks.sort((a,b)=>Number(mandatory(b.kind))-Number(mandatory(a.kind)));
 return Promise.all(tasks.map(async task=>{
  const id=random();
  // Only identifiers and the tenant binding enter sealed persistent work.
  // connection contains transient credentials and is never part of this seal.
  return {...task,id,storedPartner:plan.reset?'opaque:'+random():task.partner,consented:mandatory(task.kind)||selected.has(task.partner),sealed:task.work?await seal(ctx,'erasure:'+id,task.work):null};
 }));
}
async function attempt(ctx,row,options) {
 if(deletion(row.kind)&&!row.consented_at)return blocked('remote_deletion_consent_required');
 if(!row.sealed_work)return blocked(row.kind==='partner-delete'?'partner_deletion_confirmation_required':'remote_connection_required');
 const work=await unseal(ctx,'erasure:'+row.id,row.sealed_work);
 if(work.version!==2)return blocked('remote_connection_required');
 const transient=options.connections?.get(row.id);
 if(['scim-delete','scim-deactivate','scim-clear-group'].includes(row.kind)) {
  if(work.type!=='scim')return blocked('remote_connection_recipe_required');
  const connection=await scimConnection(ctx,work,transient,options.connection);
  if(connection.state)return connection;
  const clearing=row.kind==='scim-clear-group',revoking=row.kind!=='scim-delete';
  const body=revoking?{schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',value:clearing?{members:[]}:{active:false}}]}:undefined;
  const {status:removed}=await scimRequest(ctx,work,connection.token,revoking?'PATCH':'DELETE',body,options.assertAuthority);
  if(removed===404)return {state:'verified',status:404,error:null};
  if(removed<200||removed>=300)return {state:[401,403,409].includes(removed)?'blocked':'failed',status:removed,error:removed?revoking?'remote_revocation_refused':'remote_delete_refused':'remote_unreachable'};
  const read=await scimRequest(ctx,work,connection.token,'GET');
  const verified=read.status===404||revoking&&read.status===200&&(clearing?read.body?.id&&(!read.body.members||Array.isArray(read.body.members)&&read.body.members.length===0):read.body?.active===false);
  return verified?{state:'verified',status:read.status,error:null}:{state:read.status===401||read.status===403?'blocked':'failed',status:read.status,error:revoking?'remote_revocation_unverified':'remote_absence_unverified'};
 }
 if(row.kind==='authority-fence') {
  if(work.type!=='fence'||options.connection)return blocked('remote_connection_recipe_required');
  const signing=await fenceConnection(ctx,work,transient);if(signing.state)return signing;
  const now=Math.floor(ctx.now()/1000),token=await new SignJWT(work.claims).setProtectedHeader({alg:signing.alg,kid:signing.kid,typ:'logout+jwt'}).setIssuer(work.issuer).setIssuedAt(now).setExpirationTime(now+120).sign(await importJWK(signing.jwk,signing.alg));
  const url=outboundUrl(ctx,work.url,'invalid_erasure_remote_url').href;
  await options.assertAuthority?.();
  let status=0;
  try {const response=await(ctx.connectorFetch||ctx.fetch||fetch)(url,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({logout_token:token}).toString()});status=response.status;await response.body?.cancel();}catch{}
  return status>=200&&status<300||work.acceptReplay&&status===409?{state:'verified',status,error:null}:{state:status>=400&&status<500&&![408,429].includes(status)?'blocked':'failed',status,error:status?'remote_fence_refused':'remote_unreachable'};
 }
 return blocked(options.connection?'remote_connection_recipe_required':'partner_deletion_confirmation_required');
}
export async function executeRemote(ctx,receiptId,options={}) {
 if(options.workIds!==undefined&&(!Array.isArray(options.workIds)||options.workIds.length!==1||typeof options.workIds[0]!=='string'||!options.workIds[0]))fail('remote_work_selection_required');
 if(options.connection&&(!options.workIds||!validateFreshConnection(options.connection)))fail('invalid_remote_connection');
 const tasks=await all(ctx,"SELECT * FROM auth_erasure_remote WHERE receipt_id=? AND state!='verified' AND abandoned_at IS NULL",receiptId);
 if(options.workIds&&!tasks.some(task=>task.id===options.workIds[0]))fail('remote_work_unavailable',409);
 tasks.sort((a,b)=>Number(mandatory(b.kind))-Number(mandatory(a.kind)));
 for(const task of tasks) {
  if(options.workIds&&!options.workIds.includes(task.id))continue;
  // A retained root item is a one-work retry. Only the server's initial
  // post-commit capability can dispatch all captured tasks together.
  if(opaque(task)&&!options.workIds&&!options.connections?.has(task.id))continue;
  const live=await one(ctx,"SELECT * FROM auth_erasure_remote WHERE id=? AND receipt_id=? AND abandoned_at IS NULL AND state!='verified'",task.id,receiptId);
  if(!live)continue;
  let result;
  try{result=await attempt(ctx,live,options);}catch(error){if(error instanceof AuthError)throw error;result={state:'failed',status:null,error:'remote_request_failed'};}
  finally{options.connections?.delete(task.id);}
  await run(ctx,'UPDATE auth_erasure_remote SET state=?,attempts=attempts+?,last_status=?,last_error=?,updated_at=?,sealed_work=CASE WHEN ?=\'verified\' THEN NULL ELSE sealed_work END WHERE id=? AND abandoned_at IS NULL',result.state,result.status===null?0:1,result.status,result.error,ctx.now(),result.state,task.id);
 }
 await refreshReceiptStatus(ctx,receiptId);
}
export async function refreshReceiptStatus(ctx,receiptId) {
 const counts=await one(ctx,"SELECT COUNT(*) AS unfinished,COALESCE(SUM(CASE WHEN abandoned_at IS NULL THEN 1 ELSE 0 END),0) AS live FROM auth_erasure_remote WHERE receipt_id=? AND state!='verified'",receiptId);
 const status=counts.unfinished===0?'complete':counts.live===0?'remote_abandoned':'remote_unfinished';
 await run(ctx,'UPDATE auth_erasure_receipts SET status=? WHERE id=?',status,receiptId);
 return status;
}
export const publicRemote=(row,retained=false)=>{
 const hidden=retained===true||opaque(row),abandoned=Boolean(row.abandoned_at),consentRequired=deletion(row.kind)&&!row.consented_at&&!abandoned&&row.state!=='verified';
 let instruction='Resolve the provider refusal or outage, then retry with an authorized connection. Local erasure is complete; remote work remains unfinished.';
 if(abandoned)instruction='Owner abandoned this unfinished remote work. Its sealed identifier was destroyed; remote completion is not claimed. Contact the application’s owner using your independently held records for partner deletion. A request already in flight may still finish.';
 else if(consentRequired)instruction=hidden?'The employer did not consent to deletion before reset. Retained custody cannot add that consent. Ask the application’s owner to arrange deletion using their own records.':'Remote deletion is waiting for explicit consent for this destination. Access revocation proceeds independently.';
 else if(row.kind==='partner-delete')instruction='Ask the application’s owner to delete independently held records and delivered messages, and retain their confirmation. Auth has not verified that deletion.';
 else if(row.state==='verified')instruction=row.kind==='scim-delete'?'Remote data removal verified by absence (404).':row.kind==='scim-clear-group'?'Remote group membership cleared or the group was absent. This verifies access revocation, not independent data deletion.':row.kind==='scim-deactivate'?'Remote account inactive or absent. This verifies access revocation, not independent data deletion.':'The app acknowledged Auth authority revocation. Independent data deletion is not claimed.';
 else if(row.last_error==='remote_connection_required')instruction='The employer’s credential was destroyed. Retry only with a new, explicitly authorized one-purpose connection verified against the sealed tenant binding; otherwise ask the application’s owner to complete removal.';
 const lastError=typeof row.last_error==='string'&&/^[a-z0-9_]{1,80}$/.test(row.last_error)?row.last_error:null;
 return {id:row.id,appLabel:label(row.app_label),kind:row.kind,...(hidden?{}:{partner:row.partner}),state:abandoned?'abandoned':row.state,attempts:row.attempts,lastStatus:row.last_status,lastError,consentedAt:row.consented_at??null,abandonedAt:row.abandoned_at??null,consentRequired,deletion:deletion(row.kind),instruction};
};
