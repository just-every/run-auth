import {all,one,fail,random} from '../core.mjs';
import {erasedOrganizationDatabase} from '../tenancy/storage.mjs';
import {executeRemote,publicRemote,refreshReceiptStatus} from './remote.mjs';
import {ownerWrite} from './authorization.mjs';
import {custodyOwner,auditCustody,findRetained,assertCustody} from './retained-context.mjs';

const symbol=value=>typeof value==='string'&&/^[a-z][a-z0-9_.-]{0,79}$/i.test(value)?value:'retained';
const count=value=>Number.isSafeInteger(value)&&value>=0?value:0;
function anonymousStores(stores) {
 return stores.map(store=>({store:symbol(store.store),examined:count(store.examined),deleted:count(store.deleted),anonymized:count(store.anonymized),status:symbol(store.status||'complete')}));
}
function anonymousDecisions(decisions) {
 return decisions.map(decision=>({kind:symbol(decision.kind),status:symbol(decision.status),createdAt:count(decision.createdAt),decidedAt:decision.decidedAt===null?null:count(decision.decidedAt)}));
}
export async function receiptModel(ctx,{retained=false}={}) {
 const [receipts,remote]=await Promise.all([
  all(ctx,'SELECT id,reference,kind,actor_ref,created_at,stores,limitations,decisions,status FROM auth_erasure_receipts ORDER BY created_at DESC'),
  all(ctx,'SELECT * FROM auth_erasure_remote ORDER BY created_at DESC'),
 ]);
 return receipts.map(row=>{
  const stores=JSON.parse(row.stores),decisions=JSON.parse(row.decisions);
  const shared={id:row.id,reference:row.reference,kind:row.kind,createdAt:row.created_at,stores:retained?anonymousStores(stores):stores,
   decisions:retained?anonymousDecisions(decisions):decisions,local:'complete',status:row.status,
   remote:remote.filter(item=>item.receipt_id===row.id).map(item=>publicRemote(item,retained))};
  return retained?{...shared,retained:true,limitations:['Only anonymous receipts/outcomes and sealed pending identifiers remain in installation-owner custody.','Delivered messages, exported archives, external audit sinks and provider-held copies belong to their external custodians. Ask the application’s owner to arrange deletion using independently held records.']}:{...shared,actor:row.actor_ref,limitations:JSON.parse(row.limitations)};
 });
}
export async function retainedReceipts(ctx,proof) {
 if(ctx.organizationId!=='root')return [];
 const s=await custodyOwner(ctx,proof),organizations=await all(ctx,"SELECT id FROM auth_organizations WHERE status='erased'"),receipts=[];
 for(const {id} of organizations) {
  const selected=await erasedOrganizationDatabase(ctx.db,id);if(!selected)continue;
  const found=await receiptModel({...ctx,db:selected.db},{retained:true});
  for(const receipt of found)await auditCustody(ctx,s,'erasure_custody_view',receipt.id);
  receipts.push(...found);
 }
 if(!receipts.length)await auditCustody(ctx,s,'erasure_custody_view');
 await custodyOwner(ctx,s);
 return receipts;
}
function workSelection(data,abandon) {
 const provided=data.workIds===undefined?(data.workId===undefined?[]:[data.workId]):data.workIds;
 if(!Array.isArray(provided)||!provided.length||provided.some(id=>typeof id!=='string'||!id||id.length>256)||data.workId!==undefined&&data.workIds!==undefined)fail('remote_work_selection_required');
 const ids=[...new Set(provided)];if(!abandon&&ids.length!==1)fail('remote_work_selection_required');return ids;
}
export async function retryRetained(ctx,proof,data,abandon=false) {
 const s=await custodyOwner(ctx,proof,true);
 if(!data||typeof data!=='object'||Array.isArray(data)||data.organizationId!==undefined)fail('invalid_retained_erasure_request');
 if(data.destinations!==undefined&&(!Array.isArray(data.destinations)||data.destinations.length)||data.confirmRemoteDeletion===true)fail('retained_deletion_consent_frozen',403);
 const workIds=workSelection(data,abandon);
 if(abandon?data.confirmation!=='ABANDON':data.confirmRetry!==true)fail(abandon?'remote_abandon_confirmation_required':'remote_retry_confirmation_required');
 if(abandon&&data.connection!==undefined)fail('invalid_remote_connection');
 const selected=await findRetained(ctx,data.receiptId,s),tasks=await all(selected,"SELECT id,kind,state,consented_at,abandoned_at FROM auth_erasure_remote WHERE receipt_id=?",data.receiptId);
 const chosen=workIds.map(id=>tasks.find(task=>task.id===id));
 if(chosen.some(task=>!task||task.state==='verified'||task.abandoned_at))fail('remote_work_unavailable',409);
 if(!abandon&&chosen.some(task=>['scim-delete','partner-delete'].includes(task.kind)&&!task.consented_at))fail('retained_deletion_consent_frozen',403);
 for(const id of workIds)await auditCustody(ctx,s,abandon?'erasure_custody_abandon':'erasure_custody_retry',id);
 if(abandon) {
  const claim=random(),eligible=workIds.map(()=>"EXISTS(SELECT 1 FROM auth_erasure_remote WHERE id=? AND receipt_id=? AND state!='verified' AND abandoned_at IS NULL)").join(' AND ');
  await ownerWrite(selected,s,guard=>[
   selected.db.prepare(`INSERT INTO auth_erasure_commits(id,kind) SELECT ?,'remote-abandon' WHERE ${guard.clause} AND ${eligible}`).bind(claim,...guard.args,...workIds.flatMap(id=>[id,data.receiptId])),
   ...workIds.map(id=>selected.db.prepare("UPDATE auth_erasure_remote SET sealed_work=NULL,abandoned_at=?,state='blocked',last_error='remote_erasure_abandoned',updated_at=? WHERE id=? AND receipt_id=? AND state!='verified' AND abandoned_at IS NULL AND EXISTS(SELECT 1 FROM auth_erasure_commits WHERE id=?)").bind(ctx.now(),ctx.now(),id,data.receiptId,claim)),
   selected.db.prepare('DELETE FROM auth_erasure_commits WHERE id=?').bind(claim),
  ]);
  await refreshReceiptStatus(selected,data.receiptId);
 }else {
  if(data.connection!==undefined)await auditCustody(ctx,s,'erasure_custody_connection',workIds[0]);
  await executeRemote(selected,data.receiptId,{workIds,...(data.connection!==undefined?{connection:data.connection}:{}),assertAuthority:()=>assertCustody(ctx,s)});
 }
 const outcome=await one(selected,'SELECT status FROM auth_erasure_receipts WHERE id=?',data.receiptId);
 await auditCustody(ctx,s,abandon?'erasure_custody_abandon_outcome':'erasure_custody_retry_outcome',workIds[0]);
 return {receiptId:data.receiptId,status:outcome.status};
}
