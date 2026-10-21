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
export async function remoteWork(ctx,plan) {
 const tasks=[...plan.remote];
 for(const client of rows(plan,'auth_clients')) {
  if(!client.logout_uri)continue;
  for(const grant of rows(plan,'auth_grants').filter(g=>g.client_id===client.id&&(plan.reset||plan.kind==='app'&&client.id===plan.target||plan.kind==='person'&&g.person_id===plan.target))) {
   const subject=rows(plan,'auth_subjects').find(s=>s.sector_id===client.sector_id&&s.person_id===grant.person_id)?.subject;
   const signing=await signer(ctx,plan);
   tasks.push({kind:'authority-fence',partner:new URL(client.logout_uri).origin,
    work:subject&&signing?{url:client.logout_uri,signing,issuer:ctx.origin,claims:{aud:client.id,sub:subject,jti:random(),events:{[FENCE_EVENT]:{}}}}:null});
  }
 }
 for(const logged of rows(plan,'auth_oidc_sessions')) {
  const session=rows(plan,'auth_sessions').find(s=>s.id===logged.session_id),client=rows(plan,'auth_oidc_clients').find(c=>c.client_id===logged.client_id);
  if(!session||!client?.backchannel_logout_uri||!(plan.reset||plan.kind==='person'&&session.person_id===plan.target||plan.kind==='app'&&client.app_id===plan.target))continue;
  const subject=client.subject_type==='public'?session.person_id:rows(plan,'auth_subjects').find(s=>s.sector_id==='oidc:'+client.client_id&&s.person_id===session.person_id)?.subject;
  const signing=await signer(ctx,plan,client.id_token_alg);
  tasks.push({kind:'authority-fence',partner:new URL(client.backchannel_logout_uri).origin,
   work:subject&&signing?{url:client.backchannel_logout_uri,signing,issuer:ctx.origin,claims:{aud:client.client_id,sub:subject,sid:session.id,jti:random(),events:{[LOGOUT_EVENT]:{}}}}:null});
 }
 return Promise.all(tasks.map(async task=>{const id=random();return {...task,id,sealed:task.work?await seal(ctx,'erasure:'+id,task.work):null};}));
}
const request=async(ctx,url,method,headers)=>{
 const endpoint=outboundUrl(ctx,url,'invalid_erasure_remote_url').href;
 try {
  const response=await (ctx.connectorFetch||ctx.fetch||fetch)(endpoint,{method,redirect:'manual',signal:AbortSignal.timeout(15000),headers});
  await response.body?.cancel();return response.status;
 }catch{return 0;}
};
async function attempt(ctx,row) {
 if(!row.sealed_work)return {state:'blocked',error:row.kind==='partner-delete'?'partner_deletion_confirmation_required':'remote_authority_unavailable',status:null};
 const work=await unseal(ctx,'erasure:'+row.id,row.sealed_work);
 if(row.kind==='scim-delete') {
  const token=await unseal(ctx,'scim:'+work.connector.app_id,work.connector.sealed_token);
  const url=work.connector.base_url+'/'+work.resource+'/'+encodeURIComponent(work.remoteId),headers={authorization:'Bearer '+token,accept:'application/scim+json'};
  const removed=await request(ctx,url,'DELETE',headers);
  if(removed===404)return {state:'verified',status:404,error:null};
  if(removed<200||removed>=300)return {state:[401,403,409].includes(removed)?'blocked':'failed',status:removed,error:removed?'remote_delete_refused':'remote_unreachable'};
  const read=await request(ctx,url,'GET',headers);
  return read===404?{state:'verified',status:404,error:null}:{state:read===401||read===403?'blocked':'failed',status:read,error:'remote_absence_unverified'};
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
// Called only after an owner explicitly authorized remote erasure. No provider
// response is stored: it might repeat a bearer credential or personal data.
export async function executeRemote(ctx,receiptId) {
 const tasks=await all(ctx,"SELECT * FROM auth_erasure_remote WHERE receipt_id=? AND state!='verified'",receiptId);
 for(const task of tasks) {
  const result=await attempt(ctx,task).catch(()=>({state:'failed',status:null,error:'remote_request_failed'}));
  await run(ctx,'UPDATE auth_erasure_remote SET state=?,attempts=attempts+1,last_status=?,last_error=?,updated_at=?,sealed_work=CASE WHEN ?=\'verified\' THEN NULL ELSE sealed_work END WHERE id=?',result.state,result.status,result.error,ctx.now(),result.state,task.id);
 }
 const remaining=await one(ctx,"SELECT COUNT(*) AS n FROM auth_erasure_remote WHERE receipt_id=? AND state!='verified'",receiptId);
 await run(ctx,'UPDATE auth_erasure_receipts SET status=? WHERE id=?',remaining.n?'remote_unfinished':'complete',receiptId);
}
export const publicRemote=row=>({id:row.id,kind:row.kind,partner:row.partner,state:row.state,attempts:row.attempts,lastStatus:row.last_status,lastError:row.last_error,
 instruction:row.kind==='partner-delete'?'Ask the app/provider to delete independently held records and delivered messages; retain its confirmation.':row.state==='verified'?'Remote authority removal verified.':'Resolve the provider refusal or outage, then authorize Retry. Local erasure is complete.'});
