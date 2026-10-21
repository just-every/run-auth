import {createLocalJWKSet,jwtVerify} from 'jose';
import {fail,one} from '../core.mjs';
import {erasedOrganizationDatabase} from '../tenancy/storage.mjs';
import {verifyAuditCommitments} from './audit.mjs';

export async function receiptContext(ctx,organizationId) {
 if(!organizationId||organizationId===ctx.organizationId)return ctx;
 if(ctx.organizationId!=='root')fail('installation_owner_required',403);
 const selected=await erasedOrganizationDatabase(ctx.db,organizationId);
 if(!selected)fail('erasure_receipt_not_found',404);
 return {...ctx,db:selected.db,organizationId,issuer:ctx.origin+'/org/'+organizationId};
}
export async function savedJournal(ctx,receiptId) {
 const row=receiptId?await one(ctx,'SELECT journal FROM auth_erasure_receipts WHERE id=?',receiptId):await one(ctx,'SELECT journal FROM auth_erasure_receipts ORDER BY created_at DESC,rowid DESC LIMIT 1');
 if(!row&&receiptId)fail('erasure_receipt_not_found',404);
 return row?JSON.parse(row.journal):null;
}
export async function journalIntegrity(ctx,journal) {
 if(!journal)return {valid:false,checked:0,changed:0,reason:'erasure_receipt_required'};
 try {
  const issuer=ctx.issuer||ctx.origin;
  const {payload}=await jwtVerify(journal.proof,createLocalJWKSet(journal.jwks),{issuer,audience:issuer,algorithms:['ES256','RS256'],currentDate:new Date(ctx.now())});
  for(const [key,value] of Object.entries(journal))if(!['proof','jwks'].includes(key)&&JSON.stringify(payload[key])!==JSON.stringify(value))throw new Error('changed_journal');
 }catch{return {valid:false,checked:0,changed:0,reason:'invalid_erasure_journal'};}
 return verifyAuditCommitments(ctx,journal);
}
