import {installationFence} from './portability.mjs';
import {batchWithInstallation} from '../tenancy/storage.mjs';
import {fail,random} from '../core.mjs';
import {ownerProof,assertOwnerProof} from './authorization.mjs';
import {quoted,rowKey,deletionOrder,erasureTable} from './schema.mjs';
import {keyOf} from './plan.mjs';
import {hashesFor,recordHash} from './journal.mjs';
import {remoteWork,executeRemote} from './remote.mjs';
import {signedJournal} from './export.mjs';
import {auditCommitments} from './audit.mjs';

export async function commitErasure(ctx,s,plan,previewId,destinations=[]) {
 if(plan.holds.length)fail('erasure_legal_hold',409);
 if(!plan.policy?.configured)fail('erasure_policy_configuration_required',409);
 const id=random(),latch=random(),proof=ownerProof(ctx,s),guard=proof.guard,tasks=await remoteWork(ctx,plan,destinations);
 const hashes=await hashesFor(ctx,plan.identifiers),now=ctx.now();
 const statements=[ctx.db.prepare(`INSERT INTO auth_erasure_commits(id,kind) SELECT ?,? WHERE ${guard.clause}
  AND EXISTS(SELECT 1 FROM auth_erasure_previews WHERE id=? AND actor_id=? AND expires_at>?)
  AND NOT EXISTS(SELECT 1 FROM auth_erasure_holds WHERE released_at IS NULL AND (kind IN ('organization','installation') OR ?=1 OR target=?))`).bind(latch,plan.kind,...guard.args,previewId,s.person_id,now,plan.reset?1:0,plan.target)];
 // Check the actual snapshot inside the atomic batch, before any data write.
 // Concurrent enrollments, imported rows, changed holds and provider work all
 // invalidate the preview; no newly created dependent row can escape erasure.
 for(const table of plan.stores.values()) {
  statements.push(ctx.db.prepare(`DELETE FROM auth_erasure_commits WHERE id=? AND (SELECT COUNT(*) FROM ${quoted(table.name)})!=?`).bind(latch,table.rows.length));
  for(const row of table.rows) {
   const columns=table.columns.map(c=>c.name);
   statements.push(ctx.db.prepare(`DELETE FROM auth_erasure_commits WHERE id=? AND NOT EXISTS(SELECT 1 FROM ${quoted(table.name)} WHERE ${columns.map(c=>quoted(c)+' IS ?').join(' AND ')})`).bind(latch,...columns.map(c=>row[c])));
  }
 }
 const held='EXISTS(SELECT 1 FROM auth_erasure_commits WHERE id=?)';
 const statement=(sql,args=[])=>ctx.db.prepare(sql+' AND '+held).bind(...args,latch);
 // Write durable anonymized evidence before touching source rows. No receipt
 // or journal may exist for an uncommitted/refused erasure.
 const records=[];
 for(const table of plan.stores.values())for(const [index,row] of table.rows.entries()) {
  const key=keyOf(table.name,index),changes=plan.updates.get(key);
  if(!plan.removed.has(key)&&!changes)continue;
  const primary=table.columns.filter(c=>c.pk).sort((a,b)=>a.pk-b.pk),columns=(primary.length?primary:table.columns).map(c=>c.name);
  const portableChanges=changes&&Object.fromEntries(Object.entries(changes).map(([column,value])=>[column,table.foreignKeys.some(f=>f.from===column&&f.table==='oa_operators')&&value!==null?{custodian:true}:value]));
  records.push({table:table.name,columns,key:await recordHash(plan.source,plan.organization,table.name,columns,row),action:plan.removed.has(key)?'delete':'anonymize',...(changes&&!plan.removed.has(key)?{changes:portableChanges}: {})});
 }
 const journal=await signedJournal(ctx,{id,source:plan.source,organization:plan.organization,kind:plan.kind,reference:plan.reference,hashes,records,createdAt:now},await auditCommitments(plan));
 statements.push(ctx.db.prepare(`INSERT INTO auth_erasure_receipts(id,reference,kind,actor_ref,created_at,stores,limitations,decisions,status,journal) SELECT ?,?,?,?,?,?,?,?,'remote_unfinished',? WHERE ${held}`).bind(id,plan.reference,plan.kind,plan.reset||plan.identifiers.has(s.person_id)?plan.reference:s.person_id,now,JSON.stringify(plan.counts),JSON.stringify(['Mailbox/provider owners must delete delivered messages; Auth cannot recall them.','Installation owners must delete exported archives/backups or supply the later erasure journal on restore.','External audit receiver owners and named app/provider owners must delete independently held copies and retain their confirmations.']),JSON.stringify(plan.decisions),JSON.stringify(journal),latch));
 statements.push(ctx.db.prepare(`INSERT INTO auth_erasure_journal(id,source,organization,kind,reference,hashes,records,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${held}`).bind(id,plan.source,plan.organization,plan.kind,plan.reference,JSON.stringify(hashes),JSON.stringify(records),now,latch));
 for(const task of tasks)statements.push(ctx.db.prepare(`INSERT INTO auth_erasure_remote(id,receipt_id,kind,partner,sealed_work,state,created_at,updated_at,consented_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${held}`).bind(task.id,id,task.kind,task.partner,task.sealed,task.sealed?'pending':'blocked',now,now,task.consented?now:null,latch));
 for(const table of plan.stores.values())for(const [index,row] of table.rows.entries()) {
  const key=keyOf(table.name,index),changes=plan.updates.get(key);if(!changes||plan.removed.has(key))continue;
  const where=rowKey(table,row),columns=Object.keys(changes);
  statements.push(statement(`UPDATE ${quoted(table.name)} SET ${columns.map(c=>quoted(c)+'=?').join(',')} WHERE ${where.clause}`,[...columns.map(c=>changes[c]),...where.args]));
 }
 for(const name of deletionOrder(plan.stores)) {
  if(erasureTable(name))continue;
  const table=plan.stores.get(name),rows=table.rows.filter((_,i)=>plan.removed.has(keyOf(name,i)));
  if(rows.length===table.rows.length&&rows.length)statements.push(statement(`DELETE FROM ${quoted(name)} WHERE 1`));
  else for(const row of rows){const where=rowKey(table,row);statements.push(statement(`DELETE FROM ${quoted(name)} WHERE ${where.clause}`,where.args));}
 }
 // Earlier previews and provenance must not keep a removed person's identity.
 if(plan.reset) {
  statements.push(statement("DELETE FROM auth_erasure_previews WHERE 1"));
  statements.push(statement("UPDATE auth_erasure_policy SET updated_by=?,updated_at=? WHERE singleton=1",[plan.reference,now]));
  statements.push(statement('UPDATE auth_erasure_receipts SET actor_ref=? WHERE id!=?',[plan.reference,id]));
  statements.push(statement("UPDATE auth_erasure_holds SET target=?,reason=?,created_by=?,released_by=? WHERE released_at IS NOT NULL",[plan.reference,'Retained hold release evidence',plan.reference,plan.reference]));
 }else {
  statements.push(statement('DELETE FROM auth_erasure_previews WHERE target=? OR actor_id=?',[plan.target,plan.target]));
  statements.push(statement('UPDATE auth_erasure_receipts SET actor_ref=? WHERE actor_ref=?',[plan.reference,plan.target]));
  statements.push(statement('UPDATE auth_erasure_policy SET updated_by=? WHERE updated_by=?',[plan.reference,plan.target]));
  statements.push(statement('UPDATE auth_erasure_holds SET target=?,reason=?,created_by=?,released_by=? WHERE released_at IS NOT NULL AND (target=? OR created_by=? OR released_by=?)',[plan.reference,'Retained hold release evidence',plan.reference,plan.reference,plan.target,plan.target,plan.target]));
 }
 statements.push(statement('DELETE FROM auth_erasure_previews WHERE id=?',[previewId]));
 statements.push(ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'erasure_completed',?,? WHERE ${held}`).bind(plan.reset||plan.identifiers.has(s.person_id)?plan.reference:s.person_id,plan.reference,now,latch));
 const global=await installationFence(ctx,latch);
 const marker=(ctx.organization?.namespace??'')+'auth_erasure_commits';
 if(plan.kind==='organization'&&ctx.organizationId!=='root')global.push(ctx.rootDb.prepare(`UPDATE auth_organizations SET name=?,created_by=?,status='erased' WHERE id=? AND EXISTS(SELECT 1 FROM ${marker} WHERE id=?)`).bind(plan.reference,plan.reference,ctx.organizationId,latch));
 global.push((ctx.rootDb??ctx.db).prepare(`DELETE FROM ${marker} WHERE id=?`).bind(latch));
 const batch=await batchWithInstallation(ctx.db,statements,[...global,...proof.after],proof.before),results=batch.slice(proof.before.length);
 const saved=results[1+[...plan.stores.values()].reduce((n,t)=>n+1+t.rows.length,0)];
 if(!results[0].meta.changes||!saved?.meta.changes){await assertOwnerProof(ctx,s);fail('erasure_conflict',409);}
 await executeRemote(ctx,id);
 const receipt=await ctx.db.prepare('SELECT stores,status,limitations FROM auth_erasure_receipts WHERE id=?').bind(id).first();
 return {id,reference:plan.reference,local:'complete',journalRequired:true,journal,receipt:{stores:JSON.parse(receipt.stores),status:receipt.status,limitations:JSON.parse(receipt.limitations)}};
}
