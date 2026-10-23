import {one,all,random,hash,fail,json,requireSession} from '../core.mjs';
import {seal} from '../keys.mjs';
import {organizationContext} from '../tenancy/context.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {syncObligations} from '../obligations/sources.mjs';

export const RELEASE_PREFIX='identity-release:';
export const releaseSource=ob=>ob?.kind==='recovery'&&typeof ob.source_id==='string'&&ob.source_id.startsWith(RELEASE_PREFIX);
export const privatePairStore=name=>['auth_identity_pairs','auth_identity_release_notices','auth_erasure_person_receipts'].includes(name);
const namespace=id=>{if(!/^[a-f0-9]{32}$/.test(id))fail('invalid_organization_id');return 'org_'+id+'_';};

// Only explicitly linked rows are read. No email, subject, employer membership
// search or identity comparison runs during installation-person erasure.
export async function pairErasureWork(ctx,plan) {
 const before=[],after=[],global=[],root=ctx.rootDb??ctx.db;
 if(plan.kind==='person'&&(ctx.organizationId??'root')==='root') {
  const pairs=plan.stores.get('auth_identity_pairs')?.rows.filter(pair=>pair.person_id===plan.target)??[],notices=[];
  for(const pair of pairs) {
   const employer=await root.prepare("SELECT id FROM auth_organizations WHERE id=? AND status='active'").bind(pair.organization_id).first();
   if(!employer)continue;
   await organizationContext({...ctx,db:root},employer.id);
   const ns=namespace(employer.id),noticeId=random();
   before.push({sql:`INSERT OR IGNORE INTO ${ns}auth_identity_release_notices(id,handle,erasure_reference,created_at,updated_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM ${ns}auth_identity_pairs WHERE handle=?) AND EXISTS(SELECT 1 FROM auth_organizations WHERE id=? AND status='active')`,args:[noticeId,pair.handle,plan.reference,ctx.now(),ctx.now(),pair.handle,employer.id]});
   notices.push({organizationId:employer.id,handle:pair.handle,erasureReference:plan.reference,noticeId});
  }
  for(const receipt of await all(ctx,'SELECT token_hash FROM auth_erasure_person_receipts WHERE person_id=? AND erased_at IS NULL AND revoked_at IS NULL AND expired_at IS NULL',plan.target)) {
   const encrypted=await seal(ctx,'personal-erasure-receipt:'+receipt.token_hash,notices);
   after.push({sql:'UPDATE auth_erasure_person_receipts SET person_id=NULL,erased_at=?,notices=? WHERE token_hash=? AND person_id=?',args:[ctx.now(),encrypted,receipt.token_hash,plan.target]});
  }
 }
 if(plan.kind==='person'&&ctx.organizationId!=='root') {
  const handles=plan.stores.get('auth_identity_pairs')?.rows.filter(pair=>pair.person_id===plan.target).map(pair=>pair.handle)??[];
  for(const handle of handles)before.push({sql:"UPDATE auth_identity_release_notices SET state='erased',hold_id=NULL,updated_at=? WHERE handle=?",args:[ctx.now(),handle]});
  // A linked employer identity is erased independently; its installation pair
  // is destroyed without touching the installation identity or other employers.
  const marker=(ctx.organization?.namespace??'')+'auth_erasure_commits';
  for(const handle of handles)global.push(root.prepare(`DELETE FROM auth_identity_pairs WHERE handle=? AND EXISTS(SELECT 1 FROM ${marker} WHERE id=?)`));
  // Bind the erasure latch later, when commitErasure has claimed its exact plan.
  for(let i=0;i<global.length;i++)global[i]={statement:global[i],args:[handles[i]]};
 }
 if(plan.kind==='organization'&&ctx.organizationId!=='root') {
  const marker=ctx.organization.namespace+'auth_erasure_commits';
  global.push({statement:root.prepare(`DELETE FROM auth_identity_pairs WHERE organization_id=? AND EXISTS(SELECT 1 FROM ${marker} WHERE id=?)`),args:[ctx.organizationId]});
 }
 return {before,after,global};
}
export async function releaseState(ctx,ob) {
 const notice=await one(ctx,'SELECT * FROM auth_identity_release_notices WHERE id=?',ob.source_id.slice(RELEASE_PREFIX.length));
 if(!notice)return {state:'cancelled'};
 if(notice.state==='erased')return {state:'completed',action:'membership_erased'};
 const pair=await one(ctx,'SELECT person_id FROM auth_identity_pairs WHERE handle=?',notice.handle);
 if(!pair)return {state:'completed',action:'membership_erased'};
 if(notice.state==='held') {
  const hold=await one(ctx,'SELECT released_at FROM auth_erasure_holds WHERE id=?',notice.hold_id);
  if(hold&&hold.released_at===null)return {state:'completed',action:'erasure_hold_recorded'};
 }
 return {state:'open',action:'erase_linked_membership_or_record_its_legal_hold'};
}
export async function releaseCandidates(ctx) {
 const owner=await one(ctx,"SELECT id FROM oa_operators WHERE role='owner' AND status='active' ORDER BY created_at,id LIMIT 1");
 if(!owner)return [];
 return (await all(ctx,'SELECT id,created_at FROM auth_identity_release_notices')).map(row=>({kind:'recovery',source_id:RELEASE_PREFIX+row.id,person_id:null,app_id:null,owner_id:owner.id,created_at:row.created_at}));
}
export async function releaseRead(ctx,request) {
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('owner_required',403);
 const notices=await all(ctx,'SELECT id,handle,erasure_reference AS erasureReference,state,hold_id AS holdId,created_at AS createdAt FROM auth_identity_release_notices ORDER BY created_at,id');
 return json({notices});
}
export async function releaseAction(ctx,request,data) {
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('owner_required',403);requireLocalEmail(ctx,s);
 if(!data||Object.keys(data).some(key=>!['noticeId','holdId'].includes(key))||typeof data.noticeId!=='string')fail('invalid_release_request');
 const notice=await one(ctx,'SELECT * FROM auth_identity_release_notices WHERE id=?',data.noticeId)||fail('release_notice_unavailable',404);
 const pair=await one(ctx,'SELECT person_id FROM auth_identity_pairs WHERE handle=?',notice.handle)||fail('membership_already_erased',409);
 const hold=await one(ctx,"SELECT id FROM auth_erasure_holds WHERE id=? AND released_at IS NULL AND (kind IN ('organization','installation') OR kind='person' AND target=?)",data.holdId,pair.person_id)||fail('matching_active_hold_required',409);
 const guard=authority(ctx,s,['owner']);
 const result=await ctx.db.prepare(`UPDATE auth_identity_release_notices SET state='held',hold_id=?,updated_at=? WHERE id=? AND ${guard.clause} AND EXISTS(SELECT 1 FROM auth_erasure_holds WHERE id=? AND released_at IS NULL) AND EXISTS(SELECT 1 FROM auth_identity_pairs WHERE handle=? AND person_id=?)`).bind(hold.id,ctx.now(),notice.id,...guard.args,hold.id,notice.handle,pair.person_id).run();
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('release_notice_changed',409);}
 await syncObligations(ctx);return json({state:'held',noticeId:notice.id});
}
// An owner may resolve the opaque handle only to the ordinary preview door in
// this employer. The preview carries no installation person id or link history.
export async function releasePerson(ctx,request,noticeId) {
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('owner_required',403);
 const row=await one(ctx,'SELECT p.person_id FROM auth_identity_release_notices n JOIN auth_identity_pairs p ON p.handle=n.handle WHERE n.id=?',noticeId)||fail('release_notice_unavailable',404);
 return row.person_id;
}
