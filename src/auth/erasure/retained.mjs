import {all,one,run,fail} from '../core.mjs';
import {authority,requireAuthority} from '../local-email.mjs';
import {erasedOrganizationDatabase} from '../tenancy/storage.mjs';
import {executeRemote,publicRemote} from './remote.mjs';

export async function receiptModel(ctx) {
 const [receipts,remote]=await Promise.all([
  all(ctx,'SELECT id,reference,kind,actor_ref,created_at,stores,limitations,decisions,status FROM auth_erasure_receipts ORDER BY created_at DESC'),
  all(ctx,'SELECT * FROM auth_erasure_remote ORDER BY created_at DESC'),
 ]);
 return receipts.map(r=>({id:r.id,reference:r.reference,kind:r.kind,actor:r.actor_ref,createdAt:r.created_at,stores:JSON.parse(r.stores),limitations:JSON.parse(r.limitations),decisions:JSON.parse(r.decisions),local:'complete',status:r.status,remote:remote.filter(d=>d.receipt_id===r.id).map(publicRemote)}));
}
export async function retainedReceipts(ctx) {
 if(ctx.organizationId!=='root')return [];
 const organizations=await all(ctx,"SELECT id FROM auth_organizations WHERE status='erased'");
 const receipts=[];
 for(const {id} of organizations) {
  const selected=await erasedOrganizationDatabase(ctx.db,id);
  if(selected)receipts.push(...(await receiptModel({...ctx,db:selected.db})).map(r=>({...r,organizationId:id})));
 }
 return receipts;
}
// Called only after the root installation owner has proved hardware and fresh
// local email. Never use a session or role from the erased employer, and never
// disclose its sealed connector/signing material to the installation owner.
export async function retryRetained(ctx,s,data) {
 if(ctx.organizationId!=='root')fail('installation_owner_required',403);
 const selected=await erasedOrganizationDatabase(ctx.db,data.organizationId);
 if(!selected)fail('erasure_receipt_not_found',404);
 const receipt=await one({...ctx,db:selected.db},'SELECT id FROM auth_erasure_receipts WHERE id=?',data.receiptId);
 if(!receipt)fail('erasure_receipt_not_found',404);
 const guard=authority(ctx,s,['owner']);
 const result=await run(ctx,`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'erasure_remote_retry',?,? WHERE ${guard.clause}`,s.person_id,receipt.id,ctx.now(),...guard.args);
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('erasure_conflict',409);}
 await executeRemote({...ctx,db:selected.db},receipt.id);
}
