import {all,fail,hash,b64} from '../core.mjs';
import {quoted,schema} from './schema.mjs';
import {isEvidence} from './scrub.mjs';
import {authenticatedExpiries} from '../retention/expiry.mjs';

// SQLite row values are scalars or blobs. Type tags keep text/numbers/blobs
// distinct; JSON columns remain their exact stored text. No identity values
// leave this module: only SHA-256 commitments and aggregate counts do.
function valueOf(value) {
 if(value===null)return ['null'];
 if(typeof value==='string')return ['text',value];
 if(typeof value==='number'&&Number.isFinite(value))return ['number',Object.is(value,-0)?'-0':String(value)];
 if(typeof value==='bigint')return ['integer',String(value)];
 if(typeof value==='boolean')return ['boolean',value];
 if(value instanceof ArrayBuffer)return ['blob',b64(value)];
 if(ArrayBuffer.isView(value))return ['blob',b64(new Uint8Array(value.buffer,value.byteOffset,value.byteLength))];
 // D1 JSON results can represent a SQLite BLOB as an array of bytes.
 if(Array.isArray(value)&&value.every(v=>Number.isInteger(v)&&v>=0&&v<=255))return ['blob',b64(Uint8Array.from(value))];
 fail('invalid_audit_row',503);
}
export async function evidenceDigest(row) {
 if(!row||typeof row!=='object'||Array.isArray(row))fail('invalid_audit_row',503);
 const columns=Object.keys(row).sort().map(name=>[name,valueOf(row[name])]);
 return hash(JSON.stringify(['auth-retained-audit-row',1,columns]));
}

// The plan's keys are table:index (plan.mjs keyOf). Keeping that trivial key
// local avoids a plan -> audit -> plan import cycle when the receipt is built.
export async function auditCommitments(plan) {
 const tables=await Promise.all([...plan.stores.values()].filter(t=>isEvidence(t.name)).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0).map(async table=>{
  const remaining=table.rows.flatMap((row,index)=>{
   const key=table.name+':'+index;
   return plan.removed.has(key)?[]:[{...row,...plan.updates.get(key)}];
  });
  return {table:table.name,rows:(await Promise.all(remaining.map(evidenceDigest))).sort()};
 }));
 return {algorithm:'SHA-256',tables};
}

function manifestOf(journal) {
 const manifest=journal?.auditCommitments;
 if(!manifest||manifest.algorithm!=='SHA-256'||!Array.isArray(manifest.tables))fail('invalid_audit_commitments');
 const seen=new Set();
 for(const entry of manifest.tables) {
  if(!entry||typeof entry.table!=='string'||!isEvidence(entry.table)||seen.has(entry.table)||!Array.isArray(entry.rows)||entry.rows.some(d=>typeof d!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(d)))fail('invalid_audit_commitments');
  seen.add(entry.table);
 }
 return manifest;
}

// The caller authenticates the owner and verifies the journal's signature and
// issuer/organization before calling. Check only its latest receipt's manifest:
// another erasure legitimately changes an earlier receipt's retained rows.
export async function verifyAuditCommitments(ctx,journal) {
 const manifest=manifestOf(journal),available=new Set((await schema(ctx)).map(t=>t.name));
 const counts=await Promise.all(manifest.tables.map(async entry=>{
  // A dropped evidence table makes all its committed rows absent. Never read
  // a caller-named table outside the fixed evidence set or the scoped schema.
  const rows=available.has(entry.table)?await all(ctx,`SELECT * FROM ${quoted(entry.table)}`):[];
  const current=new Map();
  for(const digest of await Promise.all(rows.map(evidenceDigest)))current.set(digest,(current.get(digest)||0)+1);
  // A signed commitment is appended atomically with legitimate policy expiry.
  // Changed or deleted commitments still fail verification, as do unsigned
  // deletions and changes to any audit row that remains present.
  const expired=new Map();
  for(const row of await authenticatedExpiries(ctx,entry.table))if(row.expired_at>=(journal.createdAt??0))expired.set(row.digest,(expired.get(row.digest)||0)+1);
  let changed=0;
  for(const digest of entry.rows) {
   const matches=current.get(digest)||0;
   if(matches)current.set(digest,matches-1);
   else if(expired.get(digest))expired.set(digest,expired.get(digest)-1);
   else changed++;
  }
  // Extra rows are later audit appends. Multiplicity still matters for every
  // originally committed row, including tables without a primary key.
  return {checked:entry.rows.length,changed};
 }));
 const checked=counts.reduce((sum,c)=>sum+c.checked,0),changed=counts.reduce((sum,c)=>sum+c.changed,0);
 return {valid:changed===0,checked,changed};
}
