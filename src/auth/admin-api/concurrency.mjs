import {one,random,fail} from '../core.mjs';

export const epoch=async ctx=>(await one(ctx,'SELECT version FROM auth_admin_api_epoch WHERE id=1')).version;
export const entityTag=(principal,version)=>`"auth-v1-${principal.id}-${principal.revision}-${version}"`;
export async function precondition(ctx,request,principal,required) {
 const version=await epoch(ctx),given=request.headers.get('if-match');
 if(required&&!given)fail('precondition_required',428);
 if(given&&given!==entityTag(principal,version))fail('precondition_failed',412);
 return version;
}
// First native commit atomically claims the expected epoch and live service
// authority, executes the existing commands, and drops its latch. Concurrent UI
// writes invalidate the claim; the command's own epoch changes do not.
export function transactionPrincipal(ctx,principal,version) {
 const id=random();let first=true;
 return {...principal,get guard(){const guard=principal.guard;return {clause:`(${guard.clause}) AND EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)`,args:[...guard.args,id]};},
  commit:async statements=>{
   const guard=principal.guard,check=first?' AND EXISTS(SELECT 1 FROM auth_admin_api_epoch WHERE id=1 AND version=?)':'';
   const results=await ctx.db.batch([
    ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause}${check}`).bind(id,...guard.args,...(first?[version]:[])),
    ...statements,ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(id),
   ]);
   if(!results[0].meta.changes){await principal.assertAuthority();fail('precondition_failed',412);}
   first=false;await principal.assertAuthority();return results.slice(1,-1);
  },
 };
}
