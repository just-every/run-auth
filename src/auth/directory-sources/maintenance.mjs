import {all,AuthError} from '../core.mjs';
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
   // Custody loss never refreshes liveness or retries with ended authority.
  }
 }
 await syncObligations(ctx);
 const approved=await all(ctx,"SELECT id FROM auth_directory_snapshots WHERE state='applying' ORDER BY approved_at LIMIT 10");
 for(const snapshot of approved)await executeDirectorySnapshot(ctx,snapshot.id);
}
