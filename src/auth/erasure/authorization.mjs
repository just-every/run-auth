import {fail,random} from '../core.mjs';
import {authority,requireAuthority} from '../local-email.mjs';
import {organizationDatabase,batchWithInstallation} from '../tenancy/storage.mjs';

// Company owners control their people/app erasure. Entire employer destruction
// belongs to the installation owner, through its own session at the root door.
export async function selectErasureContext(ctx,s,path,data) {
 if(path==='/erasure/retry'||path==='/erasure/abandon')return ctx;
 const selected=data.organizationId||(data.kind==='organization'&&data.target!=='root'?data.target:null);
 if(ctx.organizationId!=='root') {
  if(selected&&selected!==ctx.organizationId||data.kind==='organization'||data.kind==='installation')fail('installation_owner_required',403);
  return ctx;
 }
 if(!selected)return ctx;
 if(!['/erasure/policy','/erasure/preview','/erasure/confirm','/erasure/hold'].includes(path))fail('invalid_erasure_request');
 if(path==='/erasure/preview'&&data.kind!=='organization'||path==='/erasure/hold'&&data.kind!=='organization'&&!data.release)fail('organization_reset_only',403);
 const opened=await organizationDatabase(ctx.db,selected);
 if(!opened)fail('organization_unavailable',404);
 return {...ctx,db:opened.db,rootDb:ctx.db,organization:opened.organization,organizationId:selected,
  issuer:ctx.origin+'/org/'+selected,basePath:'/org/'+selected,installationAuthority:{context:ctx,session:s}};
}
export function ownerProof(ctx,s) {
 const installation=ctx.installationAuthority;
 if(!installation)return {guard:authority(ctx,s,['owner']),before:[],after:[]};
 const id=random(),namespace=ctx.organization.namespace,root=installation.context;
 const guard=authority(root,installation.session,['owner']);
 return {guard:{clause:'EXISTS(SELECT 1 FROM auth_erasure_commits WHERE id=?)',args:[id]},
  before:[root.db.prepare(`INSERT INTO ${namespace}auth_erasure_commits(id,kind) SELECT ?,'authorization' WHERE ${guard.clause} AND EXISTS(SELECT 1 FROM auth_organizations WHERE id=? AND status=?)`).bind(id,...guard.args,ctx.organizationId,installation.erased?'erased':'active')],
  after:[root.db.prepare(`DELETE FROM ${namespace}auth_erasure_commits WHERE id=?`).bind(id)]};
}
export async function assertOwnerProof(ctx,s) {
 const selected=ctx.installationAuthority;
 const active=selected?.context??ctx,person=selected?.session??s;
 await requireAuthority(active,person,authority(active,person,['owner']));
}
export async function ownerWrite(ctx,s,build) {
 const proof=ownerProof(ctx,s),local=build(proof.guard);
 const results=await batchWithInstallation(ctx.db,local,proof.after,proof.before);
 const saved=results.slice(proof.before.length,proof.before.length+local.length);
 if(!saved[0]?.meta.changes){await assertOwnerProof(ctx,s);fail('erasure_conflict',409);}
 return saved;
}
