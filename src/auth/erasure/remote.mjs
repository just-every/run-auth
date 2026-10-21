import {importJWK,SignJWT} from 'jose';
import {random,one,all,run} from '../core.mjs';
import {seal,unseal} from '../keys.mjs';
import {outboundUrl} from '../outbound.mjs';
import {LOGOUT_EVENT,FENCE_EVENT} from '../links/logout.mjs';

const rows=(plan,table)=>plan.stores.get(table)?.rows||[];
async function signer(ctx,plan,alg='ES256') {
 const key=rows(plan,'auth_signing_keys').filter(k=>!k.retire_at&&JSON.parse(k.public_jwk).alg===alg).sort((a,b)=>b.published_at-a.published_at)[0];
 if(!key)return null;
 return {jwk:await unseal(ctx,key.kid,key.encrypted_private),kid:key.kid,alg};
}
const mandatory=kind=>['authority-fence','scim-deactivate','scim-clear-group'].includes(kind);
const deletion=kind=>['scim-delete','partner-delete'].includes(kind);
const minimalWork=work=>work?.connector?{connector:{app_id:work.connector.app_id,base_url:work.connector.base_url,sealed_token:work.connector.sealed_token},remoteId:work.remoteId,resource:work.resource}:work;
export async function remoteWork(ctx,plan,destinations=[]) {
 const selected=new Set(destinations),tasks=[];
 for(const task of plan.remote) {
  const work=minimalWork(task.work);
  tasks.push({...task,work});
  if(task.kind==='scim-delete')tasks.push({kind:work?.resource==='Groups'?'scim-clear-group':'scim-deactivate',partner:task.partner,work});
 }
 for(const client of rows(plan,'auth_clients')) {
  if(!client.logout_uri)continue;
  for(const grant of rows(plan,'auth_grants').filter(g=>g.client_id===client.id&&(plan.reset||plan.kind==='app'&&client.id===plan.target||plan.kind==='person'&&g.person_id===plan.target))) {
   const subject=rows(plan,'auth_subjects').find(s=>s.sector_id===client.sector_id&&s.person_id===grant.person_id)?.subject;
   const signing=await signer(ctx,plan);
   tasks.push({kind:'authority-fence',partner:new URL(client.logout_uri).origin,
    work:subject&&signing?{url:client.logout_uri,signing,issuer:ctx.issuer||ctx.origin,claims:{aud:client.id,sub:subject,jti:random(),events:{[FENCE_EVENT]:{}}}}:null});
  }
 }
 for(const logged of rows(plan,'auth_oidc_sessions')) {
  const session=rows(plan,'auth_sessions').find(s=>s.id===logged.session_id),client=rows(plan,'auth_oidc_clients').find(c=>c.client_id===logged.client_id);
  if(!session||!client?.backchannel_logout_uri||!(plan.reset||plan.kind==='person'&&session.person_id===plan.target||plan.kind==='app'&&client.app_id===plan.target))continue;
  const subject=client.subject_type==='public'?session.person_id:rows(plan,'auth_subjects').find(s=>s.sector_id==='oidc:'+client.client_id&&s.person_id===session.person_id)?.subject;
  const signing=await signer(ctx,plan,client.id_token_alg);
  tasks.push({kind:'authority-fence',partner:new URL(client.backchannel_logout_uri).origin,
   work:subject&&signing?{url:client.backchannel_logout_uri,signing,issuer:ctx.issuer||ctx.origin,claims:{aud:client.client_id,sub:subject,sid:session.id,jti:random(),events:{[LOGOUT_EVENT]:{}}}}:null});
 }
 tasks.sort((a,b)=>Number(mandatory(b.kind))-Number(mandatory(a.kind)));
 return Promise.all(tasks.map(async task=>{const id=random();return {...task,id,consented:mandatory(task.kind)||selected.has(task.partner),sealed:task.work?await seal(ctx,'erasure:'+id,task.work):null};}));
}
const request=async(ctx,url,method,headers,body)=>{
 const endpoint=outboundUrl(ctx,url,'invalid_erasure_remote_url').href;
 try {
  const response=await (ctx.connectorFetch||ctx.fetch||fetch)(endpoint,{method,redirect:'manual',signal:AbortSignal.timeout(15000),headers:{...headers,...(body?{'content-type':'application/scim+json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
  let parsed=null;
  if(method==='GET') {const text=await response.text();if(text.length<=1048576)try{parsed=JSON.parse(text);}catch{}}
  else await response.body?.cancel();
  return {status:response.status,body:parsed};
 }catch{return {status:0,body:null};}
};
async function attempt(ctx,row) {
 if(deletion(row.kind)&&!row.consented_at)return {state:'blocked',error:'remote_deletion_consent_required',status:null};
 if(!row.sealed_work)return {state:'blocked',error:row.kind==='partner-delete'?'partner_deletion_confirmation_required':'remote_authority_unavailable',status:null};
 const work=await unseal(ctx,'erasure:'+row.id,row.sealed_work);
 if(['scim-delete','scim-deactivate','scim-clear-group'].includes(row.kind)) {
  const token=await unseal(ctx,'scim:'+work.connector.app_id,work.connector.sealed_token);
  const url=work.connector.base_url+'/'+work.resource+'/'+encodeURIComponent(work.remoteId),headers={authorization:'Bearer '+token,accept:'application/scim+json'};
  const clearing=row.kind==='scim-clear-group',revoking=row.kind!=='scim-delete';
  const body=revoking?{schemas:['urn:ietf:params:scim:api:messages:2.0:PatchOp'],Operations:[{op:'replace',value:clearing?{members:[]}:{active:false}}]}:undefined;
  const {status:removed}=await request(ctx,url,revoking?'PATCH':'DELETE',headers,body);
  if(removed===404)return {state:'verified',status:404,error:null};
  if(removed<200||removed>=300)return {state:[401,403,409].includes(removed)?'blocked':'failed',status:removed,error:removed?revoking?'remote_revocation_refused':'remote_delete_refused':'remote_unreachable'};
  const read=await request(ctx,url,'GET',headers);
  const verified=read.status===404||revoking&&read.status===200&&(clearing?read.body?.id&&(!read.body.members||Array.isArray(read.body.members)&&read.body.members.length===0):read.body?.active===false);
  return verified?{state:'verified',status:read.status,error:null}:{state:read.status===401||read.status===403?'blocked':'failed',status:read.status,error:revoking?'remote_revocation_unverified':'remote_absence_unverified'};
 }
 if(row.kind==='authority-fence') {
  const signing=work.signing,now=Math.floor(ctx.now()/1000);
  const token=await new SignJWT(work.claims).setProtectedHeader({alg:signing.alg,kid:signing.kid,typ:'logout+jwt'}).setIssuer(work.issuer).setIssuedAt(now).setExpirationTime(now+120).sign(await importJWK(signing.jwk,signing.alg));
  const url=outboundUrl(ctx,work.url,'invalid_erasure_remote_url').href;
  let status=0;
  try {const response=await(ctx.connectorFetch||ctx.fetch||fetch)(url,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({logout_token:token}).toString()});status=response.status;await response.body?.cancel();}catch{}
  return status>=200&&status<300||status===409?{state:'verified',status,error:null}:{state:status>=400&&status<500&&![408,429].includes(status)?'blocked':'failed',status,error:status?'remote_fence_refused':'remote_unreachable'};
 }
 return {state:'blocked',status:null,error:'partner_deletion_confirmation_required'};
}
// Authority revocation always runs. Deletion requires the destination's durable
// explicit consent. Never store a provider response or expose sealed work.
export async function executeRemote(ctx,receiptId) {
 const tasks=await all(ctx,"SELECT * FROM auth_erasure_remote WHERE receipt_id=? AND state!='verified' AND abandoned_at IS NULL",receiptId);
 tasks.sort((a,b)=>Number(mandatory(b.kind))-Number(mandatory(a.kind)));
 for(const task of tasks) {
  const live=await one(ctx,"SELECT * FROM auth_erasure_remote WHERE id=? AND receipt_id=? AND abandoned_at IS NULL AND state!='verified'",task.id,receiptId);
  if(!live)continue;
  const consentMissing=deletion(live.kind)&&!live.consented_at;
  const result=await attempt(ctx,live).catch(()=>({state:'failed',status:null,error:'remote_request_failed'}));
  await run(ctx,'UPDATE auth_erasure_remote SET state=?,attempts=attempts+?,last_status=?,last_error=?,updated_at=?,sealed_work=CASE WHEN ?=\'verified\' THEN NULL ELSE sealed_work END WHERE id=? AND abandoned_at IS NULL',result.state,consentMissing||!live.sealed_work?0:1,result.status,result.error,ctx.now(),result.state,task.id);
 }
 await refreshReceiptStatus(ctx,receiptId);
}
export async function refreshReceiptStatus(ctx,receiptId) {
 const counts=await one(ctx,"SELECT COUNT(*) AS unfinished,COALESCE(SUM(CASE WHEN abandoned_at IS NULL THEN 1 ELSE 0 END),0) AS live FROM auth_erasure_remote WHERE receipt_id=? AND state!='verified'",receiptId);
 const status=counts.unfinished===0?'complete':counts.live===0?'remote_abandoned':'remote_unfinished';
 await run(ctx,'UPDATE auth_erasure_receipts SET status=? WHERE id=?',status,receiptId);
 return status;
}
export const publicRemote=row=>{
 const abandoned=Boolean(row.abandoned_at),consentRequired=deletion(row.kind)&&!row.consented_at&&!abandoned&&row.state!=='verified';
 let instruction='Resolve the provider refusal or outage, then retry. Local erasure is complete; remote work remains unfinished.';
 if(abandoned)instruction='Owner abandoned this unfinished remote work. Its sealed identifiers and credentials were destroyed; remote completion is not claimed. A request already in flight may still finish.';
 else if(consentRequired)instruction='Remote deletion is waiting for explicit consent for this destination. Access revocation proceeds independently.';
 else if(row.kind==='partner-delete')instruction='Ask this app/provider’s owner to delete independently held records and delivered messages, and retain their confirmation. Auth has not verified that deletion.';
 else if(row.state==='verified')instruction=row.kind==='scim-delete'?'Remote data removal verified by absence (404).':row.kind==='scim-clear-group'?'Remote group membership cleared or the group was absent. This verifies access revocation, not independent data deletion.':row.kind==='scim-deactivate'?'Remote account inactive or absent. This verifies access revocation, not independent data deletion.':'The app acknowledged Auth authority revocation. Independent data deletion is not claimed.';
 return {id:row.id,kind:row.kind,partner:row.partner,state:abandoned?'abandoned':row.state,attempts:row.attempts,lastStatus:row.last_status,lastError:row.last_error,consentedAt:row.consented_at??null,abandonedAt:row.abandoned_at??null,consentRequired,deletion:deletion(row.kind),instruction};
};
