import {all,one,fail,requireSession,sessionById,audit as appendAudit} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {erasedOrganizationDatabase} from '../tenancy/storage.mjs';

export async function custodyOwner(ctx,proof,write=false) {
 if(ctx.organizationId!=='root')fail('installation_owner_required',403);
 const request=proof instanceof Request?proof:new Request(ctx.origin);
 const s=proof instanceof Request?await requireSession(ctx,proof,true):await sessionById(ctx,request,proof?.id);
 if(!s||s.role!=='owner'||!JSON.parse(s.amr).includes('hwk'))fail('installation_owner_required',403);
 if(write){requireLocalEmail(ctx,s);await requireAuthority(ctx,s,authority(ctx,s,['owner']));}
 return s;
}
export async function auditCustody(ctx,s,event,subject=null) {
 if(ctx.organizationId!=='root')fail('installation_owner_required',403);
 await appendAudit(ctx,s.person_id,event,subject);
}
export async function findRetained(ctx,receiptId,s) {
 if(ctx.organizationId!=='root')fail('installation_owner_required',403);
 if(typeof receiptId!=='string'||!receiptId||receiptId.length>256)fail('invalid_erasure_receipt');
 const organizations=await all(ctx,"SELECT id FROM auth_organizations WHERE status='erased'");
 let found=null;
 for(const {id} of organizations) {
  const opened=await erasedOrganizationDatabase(ctx.db,id);if(!opened)continue;
  const selected={...ctx,db:opened.db,organization:opened.organization,organizationId:id,issuer:ctx.origin+'/org/'+id,
   retainedCustody:true,custodyRoot:ctx,custodySession:s,retainedReceiptId:receiptId,
   installationAuthority:{context:ctx,session:s,erased:true}};
  if(!await one(selected,'SELECT id FROM auth_erasure_receipts WHERE id=?',receiptId))continue;
  if(found)fail('erasure_receipt_ambiguous',409);found=selected;
 }
 if(!found)fail('erasure_receipt_not_found',404);
 return found;
}
export const assertCustody=async(ctx,s)=>{
 await custodyOwner(ctx,s,true);
};
