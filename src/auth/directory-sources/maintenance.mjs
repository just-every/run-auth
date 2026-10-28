import {all,run,AuthError} from '../core.mjs';
import {syncObligations} from '../obligations/sources.mjs';
import {requireLiveSource} from './store.mjs';
import {pullDirectorySource} from './routes.mjs';
import {executeDirectorySnapshot} from './apply.mjs';

// A source credential can observe. Only durable, exact administrator approvals
// can resume local writes; maintenance never invents or renews an approval.
export async function maintainDirectorySources(ctx) {
 await syncObligations(ctx);
 const sources=await all(ctx,"SELECT * FROM auth_directory_sources WHERE disabled_at IS NULL AND mode='pull' AND next_poll_at<=? ORDER BY next_poll_at LIMIT 3",ctx.now());
 for(const source of sources){
  try{await pullDirectorySource(ctx,source,await requireLiveSource(ctx,source));}
  catch(error){
   if(!(error instanceof AuthError))throw error;
   // Pull failures are recorded under the observation's revision fence.
   // Ended custody is permanent for this source; stop scheduling it without
   // refreshing liveness or overwriting a newer observation or disablement.
   if(error.message==='directory_source_authority_changed')await run(ctx,
    'UPDATE auth_directory_sources SET next_poll_at=NULL WHERE id=? AND revision=? AND observation_version=? AND next_poll_at=? AND disabled_at IS NULL',
    source.id,source.revision,source.observation_version,source.next_poll_at);
  }
 }
 await syncObligations(ctx);
 const approved=await all(ctx,"SELECT id FROM auth_directory_snapshots WHERE state='applying' ORDER BY approved_at LIMIT 10");
 for(const snapshot of approved)await executeDirectorySnapshot(ctx,snapshot.id);
}
