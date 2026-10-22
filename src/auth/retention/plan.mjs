import {all,hash} from '../core.mjs';
import {subtractPeriod} from './policy.mjs';
import {CATALOG,tableQuote,entryId} from './catalog.mjs';
import {unheld,unfinished} from './holds.mjs';
export const PLAN_LIMIT=200;
export function eligibility(entry,policy,at) {
 const time=entry.time,cutoff=subtractPeriod(at,policy.classes[entry.class]);
 return `${time} IS NOT NULL AND ${time}<=${cutoff} AND (${(entry.where??'1').replaceAll(':now',String(at))}) AND (${entry.deleteWhere??'1'}) AND ${unheld(entry,time)} AND ${unfinished(time)}`;
}
export async function retentionPlan(ctx,policy) {
 const entries=[],summary={};let total=0;
 for(const entry of CATALOG) {
  const columns=entry.columns?entry.columns.map(c=>'t.'+tableQuote(c)).join(','):'t.*';
  const rows=total>=PLAN_LIMIT?[]:await all(ctx,`SELECT ${columns} FROM ${tableQuote(entry.table)} t WHERE ${eligibility(entry,policy,ctx.now())} ORDER BY ${entry.key.map(c=>'t.'+tableQuote(c)).join(',')} LIMIT ?`,PLAN_LIMIT-total);
  total+=rows.length;
  if(rows.length) {
   const records=await Promise.all(rows.map(async row=>({row,digest:await hash(JSON.stringify(row)),...(entry.operation==='anonymize'?{expiredEmail:'expired-'+await hash(String(row.id))+'@retention.invalid'}:{})})));
   entries.push({id:entryId(entry),records});
  }
  const bucket=summary[entry.class]??={count:0,stores:{}};
  bucket.count+=rows.length;bucket.stores[entry.table]=(bucket.stores[entry.table]??0)+rows.length;
 }
 return {entries,summary,total,limit:PLAN_LIMIT};
}
export function matchSnapshot(entry) {
 const columns=entry.columns??null;
 // Every selected scalar is compared, so a changed row is never deleted under
 // an older preview. SQL JSON paths and identifiers are catalog-owned.
 const keys=columns??entry.snapshotColumns;
 return `EXISTS(SELECT 1 FROM json_each(?) candidate WHERE ${keys.map(c=>`t.${tableQuote(c)} IS json_extract(candidate.value,'$.row.${c}')`).join(' AND ')})`;
}
export async function snapshotColumns(ctx,entry) {
 if(entry.columns)return entry.columns;
 // PRAGMA on the fixed catalog table is compatible with organization scoping.
 return (await all(ctx,`PRAGMA table_info(${tableQuote(entry.table)})`)).map(c=>c.name);
}
export const runView=row=>({id:row.id,status:row.status,policyRevision:row.policy_revision,createdAt:row.created_at,deleteAfter:row.delete_after,completedAt:row.completed_at,summary:JSON.parse(row.summary),result:JSON.parse(row.result),canExport:row.status==='queued'});
