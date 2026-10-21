import {createLocalJWKSet,jwtVerify} from 'jose';
import {fail,one,hash,b64,unb64,utf8} from '../core.mjs';
import {unseal} from '../keys.mjs';
import {verifyAuditCommitments} from './audit.mjs';
import {custodyOwner,auditCustody,findRetained} from './retained-context.mjs';

export async function receiptContext(ctx,receiptId,proof) {
 if(!receiptId)return ctx;
 if(await one(ctx,'SELECT id FROM auth_erasure_receipts WHERE id=?',receiptId))return ctx;
 if(ctx.organizationId!=='root')fail('erasure_receipt_not_found',404);
 const s=await custodyOwner(ctx,proof);
 return findRetained(ctx,receiptId,s);
}
async function rawJournal(ctx,receiptId) {
 const row=receiptId?await one(ctx,'SELECT id,journal FROM auth_erasure_receipts WHERE id=?',receiptId):await one(ctx,'SELECT id,journal FROM auth_erasure_receipts ORDER BY created_at DESC,rowid DESC LIMIT 1');
 if(!row&&receiptId)fail('erasure_receipt_not_found',404);
 if(!row)return null;
 let document;try{document=JSON.parse(row.journal);}catch{fail('invalid_erasure_journal');}
 if(document?.format==='auth-sealed-erasure-journal') {
  if(document.version!==1||typeof document.sealed!=='string')fail('invalid_erasure_journal');
  try{return await unseal(ctx,'erasure-journal:'+row.id,document.sealed);}catch{fail('invalid_erasure_journal');}
 }
 if(ctx.retainedCustody)fail('retained_journal_not_sealed',503);
 return document;
}
async function installationKey(ctx) {
 if(ctx.organizationId!=='root')fail('installation_owner_required',403);
 let bytes;
 try{bytes=/^[a-f0-9]{64}$/i.test(ctx.secret)?Uint8Array.from(ctx.secret.match(/../g),value=>parseInt(value,16)):unb64(ctx.secret);}catch{fail('installation_key_required',503);}
 if(bytes.length!==32)fail('installation_key_required',503);
 return crypto.subtle.importKey('raw',bytes,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
const total=(array,field)=>Array.isArray(array)?array.reduce((sum,item)=>sum+(Array.isArray(item?.[field])?item[field].length:0),0):0;
// The source journal stays sealed. The public commitment carries only counts,
// an opaque receipt ID and a digest; it contains no source key, row or issuer.
export async function sanitizeJournal(root,journal,receiptId) {
 if(typeof receiptId!=='string'||!receiptId)fail('erasure_receipt_required');
 const entries=Array.isArray(journal?.entries)?journal.entries:[];
 const payload={format:'auth-retained-erasure-commitment',version:1,receiptId,createdAt:Number.isSafeInteger(journal?.createdAt)?journal.createdAt:0,
  entries:entries.length,records:total(entries,'records'),auditRows:total(journal?.auditCommitments?.tables,'rows'),commitment:await hash(JSON.stringify(journal))};
 const signature=b64(await crypto.subtle.sign('HMAC',await installationKey(root),utf8.encode(JSON.stringify(payload))));
 return {...payload,proof:{algorithm:'HMAC-SHA256',signature}};
}
async function authenticatedCommitment(root,document) {
 if(document?.format!=='auth-retained-erasure-commitment'||document.version!==1||document.proof?.algorithm!=='HMAC-SHA256'||typeof document.proof.signature!=='string')return false;
 const {proof,...payload}=document;
 try{return crypto.subtle.verify('HMAC',await installationKey(root),unb64(proof.signature),utf8.encode(JSON.stringify(payload)));}catch{return false;}
}
export async function savedJournal(ctx,receiptId) {
 if(!ctx.retainedCustody)return rawJournal(ctx,receiptId);
 const root=ctx.custodyRoot,s=await custodyOwner(root,ctx.custodySession),id=receiptId||ctx.retainedReceiptId;
 if(id!==ctx.retainedReceiptId)fail('erasure_receipt_not_found',404);
 const journal=await rawJournal(ctx,id);
 await auditCustody(root,s,'erasure_custody_journal_view',id);
 const publicJournal=await sanitizeJournal(root,journal,id);
 await custodyOwner(root,s);
 return publicJournal;
}
async function sourceIntegrity(ctx,journal) {
 if(!journal)return {valid:false,checked:0,changed:0,reason:'erasure_receipt_required'};
 try {
  const issuer=ctx.issuer||ctx.origin;
  const {payload}=await jwtVerify(journal.proof,createLocalJWKSet(journal.jwks),{issuer,audience:issuer,algorithms:['ES256','RS256'],currentDate:new Date(ctx.now())});
  for(const [key,value] of Object.entries(journal))if(!['proof','jwks'].includes(key)&&JSON.stringify(payload[key])!==JSON.stringify(value))throw new Error('changed_journal');
  return await verifyAuditCommitments(ctx,journal);
 }catch{return {valid:false,checked:0,changed:0,reason:'invalid_erasure_journal'};}
}
export async function journalIntegrity(ctx,journal) {
 if(!ctx.retainedCustody)return sourceIntegrity(ctx,journal);
 const root=ctx.custodyRoot,s=await custodyOwner(root,ctx.custodySession),id=ctx.retainedReceiptId;
 await auditCustody(root,s,'erasure_custody_integrity_view',id);
 if(journal?.receiptId!==id||!await authenticatedCommitment(root,journal))return {valid:false,checked:0,changed:0,reason:'invalid_retained_commitment'};
 const original=await rawJournal(ctx,id);
 if(await hash(JSON.stringify(original))!==journal.commitment)return {valid:false,checked:0,changed:0,reason:'changed_retained_journal'};
 const result=await sourceIntegrity(ctx,original);
 await custodyOwner(root,s);
 return result;
}
