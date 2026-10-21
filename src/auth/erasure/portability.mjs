import {tombstone} from '@runeditrun/rer/modules/portability/journal';

export async function initializePortability(ctx) {
 const db=ctx.rootDb??ctx.db;
 await db.prepare('INSERT OR IGNORE INTO rer_portability_state(id,source_identity) VALUES(1,?)').bind(crypto.randomUUID()).run();
}
export async function installationFence(ctx,latch) {
 const db=ctx.rootDb??ctx.db,state=await db.prepare('SELECT source_identity FROM rer_portability_state WHERE id=1').first();
 if(!state)throw new Error('portability_state_required');
 const checkpoint=await tombstone(state.source_identity,'rer_portability_state',{id:1});
 const marker=(ctx.organization?.namespace??'')+'auth_erasure_commits',held=`EXISTS(SELECT 1 FROM ${marker} WHERE id=?)`;
 // Redacted history keeps its stable primary keys. The checkpoint therefore
 // refuses the entire older archive, rather than banning those anonymous rows
 // from a new export. Base's normal --journal restore path enforces this fence.
 return [
  db.prepare(`INSERT OR IGNORE INTO rer_portability_journal(source,tombstone) SELECT ?,? WHERE ${held}`).bind(state.source_identity,checkpoint,latch),
  db.prepare(`UPDATE rer_portability_state SET epoch=epoch+1,import_job=NULL,applying=0 WHERE id=1 AND ${held}`).bind(latch),
  db.prepare(`INSERT INTO rer_portability_epochs(source,epoch) SELECT source_identity,epoch FROM rer_portability_state WHERE id=1 AND ${held} ON CONFLICT(source) DO UPDATE SET epoch=MAX(epoch,excluded.epoch)`).bind(latch),
  db.prepare(`DELETE FROM rer_portability_jobs WHERE ${held}`).bind(latch),
 ];
}
