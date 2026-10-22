import {maintainReviewReminders} from './reminders.mjs';
import {roleOrderAction,clearReductionAction,getRoleOrder} from './reductions.mjs';
import {one,all,random,json,fail,requireSession} from '../core.mjs';
import {authority,requireLocalEmail} from '../local-email.mjs';
import {accessSnapshot,keyOf,comparable} from './snapshot.mjs';
import {reviewView} from './items.mjs';

export const REVIEWS_READS=['/api/auth/reviews','/api/auth/reviews/export'];
export const isReviewAction=p=>['/reviews/create','/reviews/delegate','/reviews/close','/reviews/disable-schedule','/reviews/role-order','/reviews/reduction-clear'].includes(p);
const time=(v,code)=>{const n=typeof v==='number'?v:Date.parse(v);if(!Number.isSafeInteger(n))fail(code);return n;};
export const nextQuarter=(at,months)=>{const d=new Date(at),day=d.getUTCDate();d.setUTCDate(1);d.setUTCMonth(d.getUTCMonth()+months);const end=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+1,0)).getUTCDate();d.setUTCDate(Math.min(day,end));return d.getTime();};
async function reviewer(ctx,id) {return await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active'",String(id??''))??fail('active_reviewer_required');}
const event=(ctx,p,g,{reviewId,itemId=null,actorId,event,detail={}})=>p(`INSERT INTO auth_review_events(id,review_id,item_id,actor_id,event,detail,created_at) SELECT ?,?,?,?,?,?,? WHERE ${g.clause}`,random(),reviewId,itemId,actorId,event,JSON.stringify(detail),ctx.now(),...g.args);

async function createReview(ctx,s,settings,g,scheduleId=null) {
 const epoch=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 const id=random(),now=ctx.now(),items=await accessSnapshot(ctx,s),p=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const won={clause:'EXISTS(SELECT 1 FROM auth_reviews WHERE id=?)',args:[id]};
 // The role epoch protects the entire immutable snapshot, including changes
 // between its read and the single D1 transaction that creates the campaign.
 const scheduleStatements=settings.newSchedule?[p(`INSERT INTO auth_review_schedules(id,name,reviewer_id,interval_months,next_at,duration_ms,created_by,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,scheduleId,settings.name,settings.reviewerId,settings.newSchedule.intervalMonths,settings.newSchedule.nextAt,settings.dueAt-now,s.person_id,now,...g.args,epoch.epoch)]:[];
 const results=await ctx.db.batch([
  ...scheduleStatements,
  p(`INSERT OR IGNORE INTO auth_reviews(id,schedule_id,name,reviewer_id,period_start,period_end,due_at,created_by,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,id,scheduleId,settings.name,settings.reviewerId,settings.periodStart,settings.periodEnd,settings.dueAt,s.person_id,now,...g.args,epoch.epoch),
  ...items.map(i=>p(`INSERT INTO auth_review_items(id,review_id,subject_id,app_id,principal_type,principal_id,role,snapshot,reviewer_id) SELECT ?,?,?,?,?,?,?,?,? WHERE ${won.clause}`,random(),id,i.subject_id,i.app_id,i.principal_type,i.principal_id,i.role,JSON.stringify(i.snapshot),settings.reviewerId,id)),
  event(ctx,p,won,{reviewId:id,actorId:s.person_id,event:'started',detail:{items:items.length,scheduleId}}),
 ]);
 if(!results[scheduleStatements.length].meta.changes){if(scheduleId&&!settings.newSchedule)return null;fail('review_authority_changed',409);}
 return {id,items:items.length};
}
export async function reviewsModel(ctx,s) {
 const canManage=['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk');
 const rows=await all(ctx,canManage?'SELECT * FROM auth_reviews ORDER BY created_at DESC,id':`SELECT DISTINCT r.* FROM auth_reviews r JOIN auth_review_items i ON i.review_id=r.id WHERE i.reviewer_id=? ORDER BY r.created_at DESC,r.id`,...(canManage?[]:[s.person_id]));
 const reviews=[];
 for(const row of rows) {
  const view=await reviewView(ctx,s,row,canManage);
  if(canManage){
   const snapshot=await accessSnapshot(ctx,s),stored=await all(ctx,'SELECT * FROM auth_review_items WHERE review_id=?',row.id),keys=new Set(stored.map(keyOf));
   view.newAccess=snapshot.filter(i=>!keys.has(keyOf(i))).map(i=>i.snapshot);
   for(const item of view.items) {
    const current=snapshot.find(i=>keyOf(i)===keyOf(item));
    item.drift=item.drift||Boolean(current&&JSON.stringify(comparable(current.snapshot))!==JSON.stringify(comparable(item.snapshot)));
   }
  }
  reviews.push(view);
 }
 return {canManage,people:canManage?await all(ctx,"SELECT id,email,display_name AS name FROM oa_operators WHERE status='active' ORDER BY email"):[],apps:canManage?await Promise.all((await all(ctx,'SELECT id,name FROM auth_apps WHERE disabled_at IS NULL')).map(async a=>({...a,roleOrder:await getRoleOrder(ctx,a.id)}))):[],reviews,schedules:canManage?await all(ctx,'SELECT * FROM auth_review_schedules ORDER BY created_at'):[]};
}
export async function reviewsRead(ctx,request,path) {
 const s=await requireSession(ctx,request);
 if(path==='/api/auth/reviews')return json(await reviewsModel(ctx,s));
 // Export is an administrator action, including for an ordinary reviewer.
 await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const id=new URL(request.url).searchParams.get('id'),review=await one(ctx,'SELECT * FROM auth_reviews WHERE id=?',id??'')??fail('review_not_found',404);
 const view=await reviewView(ctx,s,review,true),g=authority(ctx,s,['owner','admin']);
 const current=await accessSnapshot(ctx,s),keys=new Set(view.items.map(keyOf));view.newAccess=current.filter(i=>!keys.has(keyOf(i))).map(i=>i.snapshot);
 const result=await ctx.db.prepare(`INSERT INTO auth_review_events(id,review_id,actor_id,event,detail,created_at) SELECT ?,?,?,'exported','{}',? WHERE ${g.clause}`).bind(random(),id,s.person_id,ctx.now(),...g.args).run();
 if(!result.meta.changes)fail('session_authority_changed',403);
 return json({format:'auth-access-review-v1',review:view,events:await all(ctx,"SELECT * FROM auth_review_events WHERE review_id=? AND event!='exported' ORDER BY created_at,id",id),claim:'Decision completion does not imply verified removal. This is evidence, not SOC 2 certification.'},200,{'content-disposition':'attachment; filename="access-review.json"'});
}
export async function reviewAction(ctx,request,path,data) {
 if(path==='/reviews/role-order')return roleOrderAction(ctx,request,data);
 if(path==='/reviews/reduction-clear')return clearReductionAction(ctx,request,data);
 const s=await requireSession(ctx,request),isAdmin=['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk');
 if(path==='/reviews/delegate') {
  const item=await one(ctx,'SELECT i.*,r.status FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id WHERE i.id=?',String(data.itemId??''))??fail('review_item_not_found',404);
  if(!isAdmin&&item.reviewer_id!==s.person_id)fail('reviewer_required',403);
  // Delegation changes who holds a decision. It is explicitly an administrator
  // write until the independent ordinary-delegation policy is approved.
  await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
  const to=await reviewer(ctx,data.reviewerId),reason=String(data.reason??'').trim();if(!reason||reason.length>500)fail('delegation_reason_required');
  if(to.id===item.subject_id)fail('self_approval_refused',403);
  const g=authority(ctx,s,['owner','admin']),p=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
  const [updated]=await ctx.db.batch([
   p(`UPDATE auth_review_items SET reviewer_id=? WHERE id=? AND reviewer_id=? AND decision IS NULL AND EXISTS(SELECT 1 FROM auth_reviews WHERE id=? AND status='open') AND ${g.clause}`,to.id,item.id,item.reviewer_id,item.review_id,...g.args),
   p(`INSERT INTO auth_review_events(id,review_id,item_id,actor_id,event,detail,created_at) SELECT ?,?,?,?,'delegated',?,? WHERE changes()>0`,random(),item.review_id,item.id,s.person_id,JSON.stringify({from:item.reviewer_id,to:to.id,reason}),ctx.now()),
  ]);
  if(!updated.meta.changes)fail('review_changed',409);return json({ok:true});
 }
 await requireSession(ctx,request,true);requireLocalEmail(ctx,s);const g=authority(ctx,s,['owner','admin']);
 if(path==='/reviews/create') {
  const name=String(data.name??'').trim();if(!name||name.length>120)fail('review_name_required');
  const to=await reviewer(ctx,data.reviewerId),dueAt=time(data.dueAt,'invalid_review_due'),periodStart=time(data.periodStart,'invalid_review_period'),periodEnd=time(data.periodEnd,'invalid_review_period');
  if(periodStart>=periodEnd||periodEnd>ctx.now()||dueAt<=ctx.now())fail('invalid_review_period');
  const intervalMonths=Number(data.intervalMonths??0);if(![0,1,3,6,12].includes(intervalMonths))fail('invalid_review_interval');
  const settings={name,reviewerId:to.id,dueAt,periodStart,periodEnd};
  let scheduleId=null;
  if(intervalMonths) {
   scheduleId=random();
   settings.newSchedule={intervalMonths,nextAt:nextQuarter(periodEnd,intervalMonths)};
  }
  return json(await createReview(ctx,s,settings,g,scheduleId),201);
 }
 if(path==='/reviews/disable-schedule') {
  const result=await ctx.db.prepare(`UPDATE auth_review_schedules SET enabled=0 WHERE id=? AND ${g.clause}`).bind(String(data.id??''),...g.args).run();
  if(!result.meta.changes)fail('schedule_not_found',404);return json({ok:true});
 }
 const epoch=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 const row=await one(ctx,"SELECT * FROM auth_reviews WHERE id=? AND status='open'",String(data.id??''))??fail('open_review_not_found',404),view=await reviewView(ctx,s,row,true);
 if(!view.completion.complete)return json({error:'review_remediation_unfinished',completion:view.completion},409);
 const result=await ctx.db.prepare(`UPDATE auth_reviews SET status='closed',closed_at=? WHERE id=? AND status='open' AND ${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?) AND NOT EXISTS(SELECT 1 FROM auth_review_items WHERE review_id=? AND decision IS NULL)`).bind(ctx.now(),row.id,...g.args,epoch.epoch,row.id).run();
 if(!result.meta.changes)fail('review_changed',409);return json({ok:true});
}
export async function maintainReviews(ctx) {
 await maintainReviewReminders(ctx);
 // Only consented recurring snapshots run automatically. They neither decide
 // access nor remove it, and stop if their accountable administrator leaves.
 for(const schedule of await all(ctx,'SELECT * FROM auth_review_schedules WHERE enabled=1 AND next_at<=? ORDER BY next_at,id',ctx.now())) {
  const owner=await one(ctx,"SELECT id,role FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin')",schedule.created_by);
  if(!owner||!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active'",schedule.reviewer_id)) {
   await ctx.db.prepare('UPDATE auth_review_schedules SET enabled=0 WHERE id=?').bind(schedule.id).run();continue;
  }
  const s={person_id:owner.id},g={clause:"EXISTS(SELECT 1 FROM auth_review_schedules WHERE id=? AND enabled=1 AND next_at=?) AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND status='active' AND role IN ('owner','admin'))",args:[schedule.id,schedule.next_at,owner.id]};
  if(!await one(ctx,'SELECT 1 FROM auth_reviews WHERE schedule_id=? AND period_end=?',schedule.id,schedule.next_at))await createReview(ctx,s,{name:schedule.name,reviewerId:schedule.reviewer_id,periodStart:nextQuarter(schedule.next_at,-schedule.interval_months),periodEnd:schedule.next_at,dueAt:ctx.now()+schedule.duration_ms},g,schedule.id);
  await ctx.db.prepare('UPDATE auth_review_schedules SET next_at=? WHERE id=? AND next_at=?').bind(nextQuarter(schedule.next_at,schedule.interval_months),schedule.id,schedule.next_at).run();
 }
 for(const row of await all(ctx,"SELECT * FROM auth_reviews WHERE status='open' AND due_at<=?",ctx.now())) {
  await ctx.db.prepare("INSERT INTO auth_review_events(id,review_id,event,detail,created_at) SELECT ?,?,'overdue_escalated','{\"action\":\"administrator_reassign_or_complete\"}',? WHERE NOT EXISTS(SELECT 1 FROM auth_review_events WHERE review_id=? AND event='overdue_escalated')").bind(random(),row.id,ctx.now(),row.id).run();
 }
}
