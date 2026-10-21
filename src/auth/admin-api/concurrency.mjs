import {one,random,fail,hash} from '../core.mjs';

export const epoch=async ctx=>(await one(ctx,'SELECT version FROM auth_admin_api_epoch WHERE id=1')).version;
export async function entityTag(ctx,principal,version) {
 // Owner configuration is outside D1's mutation triggers. Include its public
 // identity/settings, never secrets, so a config redeploy invalidates old tags.
 const config=(ctx.configuredUpstreamProviders??ctx.upstreamProviders??[]).map(p=>[p.id,p.label??p.preset,p.preset,p.issuer??null,p.tenant??null,p.clientId]);
 return `"auth-v1-${principal.id}-${principal.revision}-${version}-${await hash(JSON.stringify(config))}"`;
}
export async function precondition(ctx,request,principal,required) {
 const version=await epoch(ctx),given=request.headers.get('if-match');
 if(required&&!given)fail('precondition_required',428);
 if(given&&given!==await entityTag(ctx,principal,version))fail('precondition_failed',412);
 return version;
}
// First native commit atomically claims the expected epoch and live service
// authority, executes the existing commands, and drops its latch. Concurrent UI
// writes invalidate the claim; the command's own epoch changes do not.
export function transactionPrincipal(ctx,principal,version) {
 const id=random();let first=true;
 return {...principal,get guard(){return {clause:'EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)',args:[id]};},
  // Native post-write checks refer to authority already proved by this
  // transaction's claim. Every later mutation still prepares fresh authority.
  assertAuthority:async()=>{if(first)await principal.assertAuthority();},
  commit:async statements=>{
   await principal.prepareAuthority?.();
   const guard=principal.guard,check=first?' AND EXISTS(SELECT 1 FROM auth_admin_api_epoch WHERE id=1 AND version=?)':'';
   const results=await ctx.db.batch([
    ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause}${check}`).bind(id,...guard.args,...(first?[version]:[])),
    ...statements,ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(id),
   ]);
   if(!results[0].meta.changes){await principal.assertAuthority();fail('precondition_failed',412);}
   first=false;return results.slice(1,-1);
  },
 };
}
