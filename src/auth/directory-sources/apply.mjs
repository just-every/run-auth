import {one,all,run,random,fail,AuthError,json,auditDetail} from '../core.mjs';
import {authority,requireAuthority} from '../local-email.mjs';
import {applyAuthorizedPlan,onboardAuthorizedPerson} from '../workforce/people/apply.mjs';
import {setStatement} from '../workforce/people/fields.mjs';
import {loadDirectory} from '../workforce/people/load.mjs';
import {workforceCommand} from '../workforce/routes.mjs';
import {fencePerson} from '../links/logout.mjs';
import {personChanged,groupChanged} from '../provisioning/obligations.mjs';
import {reviewSnapshot,epochOf,nativePersonPlan} from './review.mjs';
import {combine,requireLiveSource,sourceOf,nativeSourceId} from './store.mjs';

function approvalGuard(source,snapshot) {
 return {clause:`EXISTS(SELECT 1 FROM auth_directory_snapshots snap JOIN auth_directory_sources ds ON ds.id=snap.source_id JOIN oa_operators custodian ON custodian.id=ds.created_by JOIN oa_operators approver ON approver.id=snap.approved_by WHERE snap.id=? AND snap.state='applying' AND ds.disabled_at IS NULL AND custodian.status='active' AND custodian.role IN ('owner','admin') AND custodian.version=ds.owner_version AND approver.status='active' AND approver.role IN ('owner','admin') AND approver.version=snap.approver_version AND snap.approved_digest IS NOT NULL)`,args:[snapshot.id]};
}
export async function approveSnapshot(ctx,s,data) {
 if(data.confirm!==true||typeof data.digest!=='string')fail('explicit_directory_preview_required',403);
 const review=await reviewSnapshot(ctx,s.person_id,data.snapshotId);
 if(review.source.id!==data.sourceId||!['staged','held','review_required'].includes(review.snapshot.state))fail('directory_snapshot_not_applicable',409);
 if(data.digest!==review.digest)fail('directory_preview_changed',409);
 if(review.held&&data.confirmHeld!==true)fail('explicit_held_directory_confirmation_required',403);
 if(!review.ok)return json({error:'directory_snapshot_refused',refusals:review.refusals},409);
 const live=await requireLiveSource(ctx,review.source),guard=combine(authority(ctx,s,['owner','admin']),live,{clause:'EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?) AND EXISTS(SELECT 1 FROM auth_directory_sources WHERE id=? AND revision=?)',args:[review.epoch,review.source.id,review.source.revision]});
 const statements=[ctx.db.prepare(`UPDATE auth_directory_snapshots SET state='applying',approved_by=?,approver_version=?,approved_digest=?,approved_at=?,current_epoch=?,error=NULL WHERE id=? AND state IN ('staged','held','review_required') AND ${guard.clause}`).bind(s.person_id,s.person_version,review.digest,ctx.now(),review.epoch,review.snapshot.id,...guard.args)];
 // Reapproval replaces only uncommitted work. A completed prefix is never replayed.
 statements.push(ctx.db.prepare(`DELETE FROM auth_directory_source_steps WHERE snapshot_id=? AND state='pending' AND EXISTS(SELECT 1 FROM auth_directory_snapshots WHERE id=? AND approved_digest=?)`).bind(review.snapshot.id,review.snapshot.id,review.digest));
 const offset=(await one(ctx,'SELECT COALESCE(MAX(idx),-1)+1 AS n FROM auth_directory_source_steps WHERE snapshot_id=? AND state!=?',review.snapshot.id,'pending')).n;
 review.changes.forEach((effect,idx)=>statements.push(ctx.db.prepare(`INSERT INTO auth_directory_source_steps(id,snapshot_id,idx,effect) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_directory_snapshots WHERE id=? AND approved_digest=? AND state='applying')`).bind(random(),review.snapshot.id,idx+offset,JSON.stringify(effect),review.snapshot.id,review.digest)));
 const done=await ctx.db.batch(statements);await requireAuthority(ctx,s,authority(ctx,s,['owner','admin']));if(!done[0].meta.changes)fail('directory_preview_changed',409);
 await auditDetail(ctx,s.person_id,'directory_snapshot_approved',review.snapshot.id,{sourceId:review.source.id,digest:review.digest,held:review.held,changes:review.changes.length});
 await executeDirectorySnapshot(ctx,review.snapshot.id,{sessionGuard:authority(ctx,s,['owner','admin'])});
 const current=await one(ctx,'SELECT state,error FROM auth_directory_snapshots WHERE id=?',review.snapshot.id);
 return json({sourceId:review.source.id,snapshotId:review.snapshot.id,...current,remote:'unverified'});
}
async function reconcile(ctx,step,effect) {
 if(effect.kind==='person'){
  const person=await one(ctx,'SELECT status FROM oa_operators WHERE id=?',step.target_id);
  if(person?.status==='inactive')await fencePerson(ctx,step.target_id);
  await personChanged(ctx,step.target_id,'directory_source_applied');
  for(const group of [...effect.plan.entries[0].groups.added,...effect.plan.entries[0].groups.removed])await groupChanged(ctx,group.id,[step.target_id],'directory_source_applied');
 }else if(step.target_id&&effect.kind!=='group_delete'){
  const members=(await all(ctx,'SELECT person_id FROM auth_group_members WHERE group_id=?',step.target_id)).map(row=>row.person_id);
  if(effect.personId&&!members.includes(effect.personId))members.push(effect.personId);
  await groupChanged(ctx,step.target_id,members,'directory_source_applied');
 }
 await run(ctx,"UPDATE auth_directory_source_steps SET state='completed',error=NULL WHERE id=? AND state='effects_pending'",step.id);
}
export async function executeDirectorySnapshot(ctx,snapshotId,{sessionGuard}={}) {
 const source=await sourceOf(ctx,(await one(ctx,'SELECT source_id FROM auth_directory_snapshots WHERE id=?',snapshotId))?.source_id);
 const steps=await all(ctx,"SELECT * FROM auth_directory_source_steps WHERE snapshot_id=? AND state IN ('pending','effects_pending') ORDER BY idx",snapshotId);
 for(const step of steps){
  try{
   const snapshot=await one(ctx,'SELECT * FROM auth_directory_snapshots WHERE id=?',snapshotId),effect=JSON.parse(step.effect);
   let live=approvalGuard(source,snapshot);if(sessionGuard)live=combine(live,sessionGuard);
   const assertLive=async()=>{if(!await one(ctx,`SELECT 1 WHERE ${live.clause}`,...live.args))fail('directory_approval_authority_changed',409);};
   await assertLive();
   if(step.state==='effects_pending'){await reconcile(ctx,step,effect);continue;}
   if(snapshot.current_epoch!==await epochOf(ctx))fail('directory_approved_target_changed',409);
   const operation=random(),claim=combine(live,{clause:"EXISTS(SELECT 1 FROM auth_directory_source_steps WHERE id=? AND state='pending') AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)",args:[step.id,snapshot.current_epoch]});
   const guard=combine(live,{clause:'EXISTS(SELECT 1 FROM auth_role_operations WHERE id=?)',args:[operation]});
   let personId=null,groupId=null,native;
   if(effect.kind==='person'){
    native=await nativePersonPlan(ctx,source,effect.raw,snapshot.approved_by,await loadDirectory(ctx));
    if(native.signature!==effect.signature||native.personId!==effect.personId||JSON.stringify(native.row)!==JSON.stringify(effect.row)||!native.plan.ok)fail('directory_approved_target_changed',409);
    personId=native.personId;
   }else if(effect.kind!=='group_create'){
    groupId=(await one(ctx,'SELECT group_id FROM auth_directory_source_groups WHERE source_id=? AND external_id=?',source.id,effect.externalId))?.group_id||fail('directory_source_group_changed',409);
    if(effect.kind==='member_add')personId=(await one(ctx,"SELECT person_id FROM auth_person_sources WHERE source='directory' AND source_id=?",await nativeSourceId(source.id,effect.userExternalId)))?.person_id||fail('directory_source_member_changed',409);
    else personId=effect.personId??null;
   }
   const receipt=(g,target)=>[
    ...(effect.kind==='person'&&!effect.personId&&effect.row.fields.name?[setStatement(ctx,g,target,'name','directory',effect.row.fields.name,snapshot.approved_by)]:[]),
    ctx.db.prepare(`UPDATE auth_directory_source_steps SET state='effects_pending',target_id=?,applied_at=? WHERE id=? AND state='pending' AND ${g.clause}`).bind(target,ctx.now(),step.id,...g.args),
   ];
   const actor={kind:'human',actorId:snapshot.approved_by,guard,assertAuthority:assertLive,receiptStatements:receipt,commit:async statements=>{
    const extras=[];
    if(effect.kind==='group_create')extras.push(ctx.db.prepare(`INSERT INTO auth_directory_source_groups(source_id,external_id,group_id) SELECT ?,?,id FROM auth_groups WHERE name=? AND ${guard.clause}`).bind(source.id,effect.externalId,effect.name,...guard.args));
    if(effect.kind!=='person')extras.push(ctx.db.prepare(`UPDATE auth_directory_source_steps SET state='effects_pending',target_id=${effect.kind==='group_create'?'(SELECT group_id FROM auth_directory_source_groups WHERE source_id=? AND external_id=?)':'?'},applied_at=? WHERE id=? AND state='pending' AND ${guard.clause}`).bind(...(effect.kind==='group_create'?[source.id,effect.externalId]:[groupId]),ctx.now(),step.id,...guard.args));
    const before=effect.kind==='group_delete'?[ctx.db.prepare(`DELETE FROM auth_directory_source_groups WHERE source_id=? AND external_id=? AND ${guard.clause}`).bind(source.id,effect.externalId,...guard.args)]:[];
    const done=await ctx.db.batch([
     ctx.db.prepare(`INSERT INTO auth_role_operations(id,actor_id,session_id,permission,subject_id,detail,created_at) SELECT ?,?,?,'directory.approved',?,?,? WHERE ${claim.clause}`).bind(operation,snapshot.approved_by,snapshot.id,source.id,JSON.stringify({snapshotId,digest:snapshot.approved_digest,step:step.id}),ctx.now(),...claim.args),
     ...before,...statements,...extras,
     ctx.db.prepare(`UPDATE auth_directory_snapshots SET current_epoch=(SELECT epoch FROM auth_role_epoch WHERE id=1) WHERE id=? AND EXISTS(SELECT 1 FROM auth_role_operations WHERE id=?)`).bind(snapshotId,operation),
    ]);
    if(!done[0].meta.changes)fail('directory_approved_target_changed',409);
    return done.slice(1+before.length,1+before.length+statements.length);
   }};
   if(effect.kind==='person'){
    if(personId)await applyAuthorizedPlan(ctx,actor,guard,native.dir??await loadDirectory(ctx),native.plan,{bulk:true});
    else{
     const result=await onboardAuthorizedPerson(ctx,actor,guard,await loadDirectory(ctx),{email:effect.row.email,name:effect.row.fields.name??effect.row.name,source:'directory',sourceId:native.sourceId,set:effect.row.fields,invite:false},()=>{});
     if(result.refused)fail('directory_person_refused',409);
    }
   }else if(effect.kind==='group_create')await workforceCommand(ctx,actor,'/groups/create',{name:effect.name});
   else if(effect.kind==='group_delete')await workforceCommand(ctx,actor,'/groups/delete',{id:groupId});
   else if(effect.kind==='group_rename'){
    await actor.commit([ctx.db.prepare(`UPDATE auth_groups SET name=? WHERE id=? AND ${guard.clause}`).bind(effect.name,groupId,...guard.args)]);
    await auditDetail(ctx,snapshot.approved_by,'directory_source_group_renamed',groupId,{sourceId:source.id,name:effect.name});
   }else await workforceCommand(ctx,actor,effect.kind==='member_add'?'/groups/add':'/groups/remove',{groupId,personId,reason:'Approved directory source membership'});
   const applied=await one(ctx,'SELECT * FROM auth_directory_source_steps WHERE id=?',step.id);
   if(applied.state==='effects_pending')await reconcile(ctx,applied,{...effect,personId});
  }catch(error){
   if(!(error instanceof AuthError))throw error;
   await run(ctx,"UPDATE auth_directory_snapshots SET state=?,error=? WHERE id=? AND state='applying'",error.status===503?'applying':'review_required',error.message,snapshotId);
   if(sessionGuard)throw error;return;
  }
 }
 await run(ctx,"UPDATE auth_directory_snapshots SET state='completed',error=NULL WHERE id=? AND state='applying' AND NOT EXISTS(SELECT 1 FROM auth_directory_source_steps WHERE snapshot_id=? AND state!='completed')",snapshotId,snapshotId);
}
