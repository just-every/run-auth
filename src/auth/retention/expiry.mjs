import {all,random,b64,unb64,utf8,fail} from '../core.mjs';
import {evidenceDigest} from '../erasure/audit.mjs';
import {isEvidence} from '../erasure/scrub.mjs';
import {tableQuote} from './catalog.mjs';

async function key(ctx) {
 let bytes;try{bytes=/^[a-f0-9]{64}$/i.test(ctx.secret)?Uint8Array.from(ctx.secret.match(/../g),v=>parseInt(v,16)):unb64(ctx.secret);}catch{fail('retention_signing_secret_required',503);}
 if(bytes.length!==32)fail('retention_signing_secret_required',503);
 return crypto.subtle.importKey('raw',bytes,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
const payload=row=>JSON.stringify(['auth-policy-expiry',1,row.id,row.table_name,row.digest,row.run_id,row.expired_at,row.issuer]);
// These statements immediately precede the same guarded DELETE in its atomic
// batch. No commitment is recorded unless that exact row remains eligible.
export async function expiryStatements(ctx,entry,planned,condition,args,runId) {
 if(!isEvidence(entry.table))return [];
 const statements=[],signingKey=await key(ctx);
 for(const candidate of planned.records) {
  const row={id:random(),table_name:entry.table,digest:await evidenceDigest(candidate.row),run_id:runId,expired_at:ctx.now(),issuer:ctx.issuer??ctx.origin};
  const signature=b64(await crypto.subtle.sign('HMAC',signingKey,utf8.encode(payload(row))));
  const identity=entry.key.map(c=>`t.${tableQuote(c)} IS ?`).join(' AND ');
  statements.push(ctx.db.prepare(`INSERT INTO auth_retention_expiry(id,table_name,digest,run_id,expired_at,issuer,signature) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM ${tableQuote(entry.table)} t WHERE ${condition} AND ${identity})`).bind(row.id,row.table_name,row.digest,row.run_id,row.expired_at,row.issuer,signature,...args,...entry.key.map(c=>candidate.row[c])));
 }
 return statements;
}
export async function authenticatedExpiries(ctx,table) {
 const rows=await all(ctx,'SELECT * FROM auth_retention_expiry WHERE table_name=?',table),valid=[],signingKey=await key(ctx);
 for(const row of rows) {
  if(row.issuer!==(ctx.issuer??ctx.origin))continue;
  try{if(await crypto.subtle.verify('HMAC',signingKey,unb64(row.signature),utf8.encode(payload(row))))valid.push(row);}catch{}
 }
 return valid;
}
