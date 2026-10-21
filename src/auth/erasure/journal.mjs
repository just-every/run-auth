import {hash} from '../core.mjs';

export const JOURNAL_FORMAT='auth-erasure-journal';
export const sourceOf=ctx=>ctx.issuer||ctx.origin;
export const organizationOf=ctx=>ctx.organizationId||'root';
export const normalized=value=>String(value).trim().toLowerCase();
export const identityHash=(source,organization,value)=>hash(JSON.stringify([source,organization,normalized(value)]));
export const recordHash=(source,organization,table,columns,row)=>hash(JSON.stringify([source,organization,table,columns.map(c=>[c,row[c]??null])]));
export async function hashesFor(ctx,values) {
 return [...new Set(await Promise.all([...values].filter(Boolean).map(v=>identityHash(sourceOf(ctx),organizationOf(ctx),v))))].sort();
}
export function stringsOf(value) {
 if(typeof value==='string') {
  const strings=[value];
  try {const parsed=JSON.parse(value);if(parsed!==value)strings.push(...stringsOf(parsed));}catch{}
  // Embedded addresses, IDs and values in free-form audit/CSV/outbox text.
  strings.push(...value.split(/[\s,"'<>;()[\]{}:=\\/]+/).filter(Boolean));
  return strings;
 }
 if(Array.isArray(value))return value.flatMap(stringsOf);
 if(value&&typeof value==='object')return Object.values(value).flatMap(stringsOf);
 return [];
}
