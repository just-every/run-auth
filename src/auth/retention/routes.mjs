import {all,one,random,requireSession,json,fail} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {retentionPolicy,validateRetentionPolicy,CLASSES,PREVIEW_WINDOW} from './policy.mjs';
import {retentionHolds,validateHold} from './holds.mjs';
import {retentionPlan,runView} from './plan.mjs';
import {queueRetention} from './maintenance.mjs';
export const RETENTION_READS=['/api/auth/retention','/api/auth/retention/preview','/api/auth/retention/export'];
export const isRetentionAction=path=>['/retention/settings','/retention/hold','/retention/preview'].includes(path);
const limitations=[
 'Current identities and active source bindings remain available. Profile expiry anonymizes terminated identities and removes their expired directory values; it does not erase the identity or its audit references.',
 'An unfinished operation protects its evidence period, which can retain more history than an exact subject match. Existing erasure holds conservatively stop all expiry in the employer.',
 'Model trace retention applies to model_ activity records. Auth currently produces no separate model transcript store.',
 'Storage region and processors are deployment choices. This API does not move data or certify US residency. Exports, delivered messages, downstream apps and external audit sinks remain with their respective owners.',
];
export async function retentionRead(ctx,request,path) {
 const s=await requireSession(ctx,request,true),policy=await retentionPolicy(ctx);
 if(path==='/api/auth/retention/preview')return json({policy,preview:await retentionPlan(ctx,policy),previewWindowMs:PREVIEW_WINDOW});
 if(path==='/api/auth/retention/export') {
  requireLocalEmail(ctx,s);const guard=authority(ctx,s,['owner','admin']);
  const id=new URL(request.url).searchParams.get('runId'),run=id?await one(ctx,"SELECT * FROM auth_retention_runs WHERE id=? AND status='queued'",id):await one(ctx,"SELECT * FROM auth_retention_runs WHERE status='queued'");
  if(!run)fail('retention_export_unavailable',404);
  await requireAuthority(ctx,s,guard);
  // Credential-bearing stores and session token hashes are absent from the
  // fixed plan projection. The audit contains only the opaque run reference.
  await ctx.db.prepare(`INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'retention_exported',?,? WHERE ${guard.clause}`).bind(s.person_id,run.id,ctx.now(),...guard.args).run();
  await requireAuthority(ctx,s,guard);
  return json({format:'auth-retention-export',version:1,createdAt:ctx.now(),run:runView(run),records:JSON.parse(run.plan),limitations},200,{'content-disposition':'attachment; filename="auth-retention.json"','x-content-type-options':'nosniff'});
 }
 const [holds,runs,expiryEvidence]=await Promise.all([retentionHolds(ctx),all(ctx,'SELECT id,status,policy_revision,created_at,delete_after,completed_at,summary,result FROM auth_retention_runs ORDER BY created_at DESC,id DESC LIMIT 100'),all(ctx,'SELECT id,table_name AS tableName,digest,run_id AS runId,expired_at AS expiredAt,signature FROM auth_retention_expiry ORDER BY expired_at DESC,id DESC LIMIT 200')]);
 return json({canManage:true,policy,classes:CLASSES,holds,runs:runs.map(runView),expiryEvidence,previewWindowMs:PREVIEW_WINDOW,storage:{controller:'employer',configuration:'deployment',choices:['Employer-selected US deployment and processor arrangement','Employer-selected non-US deployment and processor arrangement'],verifiedRegion:null},secretCustody:{encryption:'AES-GCM at rest for signing and connector credentials; HTTPS for production transport',access:'Organization-scoped hardware administrator doors; server-only secrets',rotation:'Existing signing-key and connector rotation doors',portableArchives:'Credential stores excluded by the shared store registry'},limitations});
}
export async function retentionAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_retention_request');
 const guard=authority(ctx,s,['owner','admin']);
 if(data.organizationId&&data.organizationId!==(ctx.organizationId??'root'))fail('retention_employer_scope_required',403);
 if(path==='/retention/preview') {
  await requireAuthority(ctx,s,guard);const run=await queueRetention(ctx,undefined,guard);await requireAuthority(ctx,s,guard);
  return json({ok:true,run:run?runView(run):null});
 }
 let changed;
 if(path==='/retention/settings') {
  const next=validateRetentionPolicy(data),current=await retentionPolicy(ctx),revision=current.revision+1;
  const marker=random(),statements=[
   ctx.db.prepare(`INSERT INTO auth_retention_policy(id,policy,updated_by,updated_at,revision) SELECT 1,?,?,?,? WHERE ${guard.clause} AND COALESCE((SELECT revision FROM auth_retention_policy WHERE id=1),0)=? ON CONFLICT(id) DO UPDATE SET policy=excluded.policy,updated_by=excluded.updated_by,updated_at=excluded.updated_at,revision=excluded.revision`).bind(JSON.stringify(next),s.person_id,ctx.now(),revision,...guard.args,current.revision),
   ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'retention_policy_changed',?,? WHERE changes()>0").bind(s.person_id,marker,ctx.now()),
   ctx.db.prepare("INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE changes()>0").bind(JSON.stringify({policy:next,revision,confirmation:true})),
   ctx.db.prepare(`UPDATE auth_retention_runs SET status='cancelled',completed_at=?,plan=NULL WHERE status='queued' AND policy_revision!=? AND EXISTS(SELECT 1 FROM auth_activity WHERE subject_id=? AND event='retention_policy_changed')`).bind(ctx.now(),revision,marker),
  ];
  [changed]=await ctx.db.batch(statements);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('retention_policy_changed',409);}
  return json({ok:true,policy:await retentionPolicy(ctx)});
 }
 if(data.release===true) {
  if(typeof data.id!=='string'||!data.id)fail('retention_hold_id_required');
  [changed]=await ctx.db.batch([
   ctx.db.prepare(`UPDATE auth_retention_holds SET released_by=?,released_at=? WHERE id=? AND released_at IS NULL AND ${guard.clause}`).bind(s.person_id,ctx.now(),data.id,...guard.args),
   ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'retention_hold_released',?,? WHERE changes()>0").bind(s.person_id,data.id,ctx.now()),
  ]);
 }else {
  const hold=validateHold(data,ctx.now()),id=random();
  [changed]=await ctx.db.batch([
   ctx.db.prepare(`INSERT INTO auth_retention_holds(id,kind,period_start,period_end,classes,reason,created_by,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${guard.clause}`).bind(id,hold.kind,hold.periodStart,hold.periodEnd,JSON.stringify(hold.classes),hold.reason,s.person_id,ctx.now(),...guard.args),
   ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'retention_hold_created',?,? WHERE changes()>0").bind(s.person_id,id,ctx.now()),
  ]);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('retention_hold_changed',409);}
  return json({ok:true,id,hold});
 }
 if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('retention_hold_unavailable',404);}
 return json({ok:true});
}
