import {reviewActor,canManageReviews,canViewReviews,reviewAllowed,requireReviewScope,visibleReviewItem} from './authority.mjs';
import {roleState} from '../roles/state.mjs';
import {permitted} from '../roles/policy.mjs';
import {maintainReviewReminders} from './reminders.mjs';
import {roleOrderAction,clearReductionAction,getRoleOrder} from './reductions.mjs';
import {one,all,random,json,fail,requireSession} from '../core.mjs';
import {accessSnapshot,keyOf,comparable} from './snapshot.mjs';
import {reviewView} from './items.mjs';

export const REVIEWS_READS=['/api/auth/reviews','/api/auth/reviews/export'];
export const isReviewAction=p=>['/reviews/create','/reviews/delegate','/reviews/close','/reviews/disable-schedule','/reviews/role-order','/reviews/reduction-clear'].includes(p);
const time=(v,code)=>{const n=typeof v==='number'?v:Date.parse(v);if(!Number.isSafeInteger(n))fail(code);return n;};
export const nextQuarter=(at,months)=>{const d=new Date(at),day=d.getUTCDate();d.setUTCDate(1);d.setUTCMonth(d.getUTCMonth()+months);const end=new Date(Date.UTC(d.getUTCFullYear(),d.getUTCMonth()+1,0)).getUTCDate();d.setUTCDate(Math.min(day,end));return d.getTime();};
async function reviewer(ctx,id) {return await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active'",String(id??''))??fail('active_reviewer_required');}
const includesAdministrators=async(ctx,id)=>Boolean(await one(ctx,"SELECT 1 FROM auth_review_events WHERE review_id=? AND event='started' AND json_extract(detail,'$.includeAdministrators')=1",id));
const event=(ctx,p,g,{reviewId,itemId=null,actorId,event,detail={}})=>p(`INSERT INTO auth_review_events(id,review_id,item_id,actor_id,event,detail,created_at) SELECT ?,?,?,?,?,?,? WHERE ${g.clause}`,random(),reviewId,itemId,actorId,event,JSON.stringify(detail),ctx.now(),...g.args);

async function createReview(ctx,s,settings,g,scheduleId=null) {
 const epoch=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 const state=await roleState(ctx,s),id=random(),now=ctx.now(),items=(await accessSnapshot(ctx,s,{includeAdministrators:settings.includeAdministrators===true})).filter(i=>reviewAllowed(state,'reviews.manage',i)),p=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const won={clause:'EXISTS(SELECT 1 FROM auth_reviews WHERE id=?)',args:[id]};
 // The role epoch protects the entire immutable snapshot, including changes
 // between its read and the single D1 transaction that creates the campaign.
 const scheduleStatements=settings.newSchedule?[p(`INSERT INTO auth_review_schedules(id,name,reviewer_id,interval_months,next_at,duration_ms,created_by,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,scheduleId,settings.name,settings.reviewerId,settings.newSchedule.intervalMonths,settings.newSchedule.nextAt,settings.dueAt-now,s.person_id,now,...g.args,epoch.epoch)]:[];
 const results=await ctx.db.batch([
  ...scheduleStatements,
  p(`INSERT OR IGNORE INTO auth_reviews(id,schedule_id,name,reviewer_id,period_start,period_end,due_at,created_by,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,id,scheduleId,settings.name,settings.reviewerId,settings.periodStart,settings.periodEnd,settings.dueAt,s.person_id,now,...g.args,epoch.epoch),
  ...items.map(i=>p(`INSERT INTO auth_review_items(id,review_id,subject_id,app_id,principal_type,principal_id,role,snapshot,reviewer_id) SELECT ?,?,?,?,?,?,?,?,? WHERE ${won.clause}`,random(),id,i.subject_id,i.app_id,i.principal_type,i.principal_id,i.role,JSON.stringify(i.snapshot),settings.reviewerId,id)),
  event(ctx,p,won,{reviewId:id,actorId:s.person_id,event:'started',detail:{items:items.length,scheduleId,includeAdministrators:settings.includeAdministrators===true}}),
 ]);
 if(!results[scheduleStatements.length].meta.changes){if(scheduleId&&!settings.newSchedule)return null;fail('review_authority_changed',409);}
 return {id,items:items.length};
}
export async function reviewsModel(ctx,s) {
 const state=await roleState(ctx,s),hardware=JSON.parse(s.amr).includes('hwk'),canManage=hardware&&canManageReviews(state),canView=hardware&&canViewReviews(state);
 const rows=await all(ctx,canView?'SELECT * FROM auth_reviews ORDER BY created_at DESC,id':`SELECT DISTINCT r.* FROM auth_reviews r JOIN auth_review_items i ON i.review_id=r.id WHERE i.reviewer_id=? ORDER BY r.created_at DESC,r.id`,...(canView?[]:[s.person_id]));
 const reviews=[];
 for(const row of rows) {
  const view=await reviewView(ctx,s,row,canView,state);
  if(canView&&!view.items.length&&row.created_by!==s.person_id)continue;
  if(canView){
   const snapshot=(await accessSnapshot(ctx,s,{includeAdministrators:await includesAdministrators(ctx,row.id)})).filter(i=>visibleReviewItem(state,i)),stored=await all(ctx,'SELECT * FROM auth_review_items WHERE review_id=?',row.id),keys=new Set(stored.map(keyOf));
   view.newAccess=snapshot.filter(i=>!keys.has(keyOf(i))).map(i=>i.snapshot);
   for(const item of view.items) {
    const current=snapshot.find(i=>keyOf(i)===keyOf(item));
    item.drift=item.drift||Boolean(current&&JSON.stringify(comparable(current.snapshot))!==JSON.stringify(comparable(item.snapshot)));
   }
  }
  reviews.push(view);
 }
 return {canManage,people:canManage?[...state.dir.people.values()].filter(p=>p.status==='active'&&permitted(state,'reviews.manage',{personId:p.id,write:true})).map(p=>({id:p.id,email:p.email,name:p.name})):[],apps:canManage?await Promise.all((await all(ctx,'SELECT id,name FROM auth_apps WHERE disabled_at IS NULL')).filter(a=>permitted(state,'reviews.manage',{appId:a.id,write:true})).map(async a=>({...a,canPublishRoleOrder:state.legacy,roleOrder:await getRoleOrder(ctx,a.id)}))):[],reviews,schedules:canManage?await all(ctx,'SELECT * FROM auth_review_schedules WHERE created_by=? ORDER BY created_at',s.person_id):[]};
}
export async function reviewsRead(ctx,request,path) {
 const s=await requireSession(ctx,request);
 if(path==='/api/auth/reviews')return json(await reviewsModel(ctx,s));
 // Export is an administrator action, including for an ordinary reviewer.
 const exporter=await reviewActor(ctx,request,{permission:'reviews.export'});
 const id=new URL(request.url).searchParams.get('id'),review=await one(ctx,'SELECT * FROM auth_reviews WHERE id=?',id??'')??fail('review_not_found',404);
 const view=await reviewView(ctx,s,review,true);requireReviewScope(exporter.state,'reviews.export',view.items);const g=exporter.guard;
 const current=(await accessSnapshot(ctx,s,{includeAdministrators:await includesAdministrators(ctx,review.id)})).filter(i=>reviewAllowed(exporter.state,'reviews.export',i)),keys=new Set(view.items.map(keyOf));view.newAccess=current.filter(i=>!keys.has(keyOf(i))).map(i=>i.snapshot);
 const result=await ctx.db.prepare(`INSERT INTO auth_review_events(id,review_id,actor_id,event,detail,created_at) SELECT ?,?,?,'exported','{}',? WHERE ${g.clause}`).bind(random(),id,s.person_id,ctx.now(),...g.args).run();
 if(!result.meta.changes)fail('session_authority_changed',403);
 return json({format:'auth-access-review-v1',review:view,events:await all(ctx,"SELECT * FROM auth_review_events WHERE review_id=? AND event!='exported' ORDER BY created_at,id",id),claim:'Decision completion does not imply verified removal. This is evidence, not SOC 2 certification.'},200,{'content-disposition':'attachment; filename="access-review.json"'});
}
export async function reviewAction(ctx,request,path,data) {
 if(path==='/reviews/role-order')return roleOrderAction(ctx,request,data);
 if(path==='/reviews/reduction-clear')return clearReductionAction(ctx,request,data);
 const actor=await reviewActor(ctx,request),s=actor.s,state=actor.state,isAdmin=canManageReviews(state);
 if(path==='/reviews/delegate') {
  const item=await one(ctx,'SELECT i.*,r.status FROM auth_review_items i JOIN auth_reviews r ON r.id=i.review_id WHERE i.id=?',String(data.itemId??''))??fail('review_item_not_found',404);
  if(!isAdmin&&item.reviewer_id!==s.person_id)fail('reviewer_required',403);
  // Delegation changes who holds a decision. It is explicitly an administrator
  // write until the independent ordinary-delegation policy is approved.
  requireReviewScope(state,'reviews.manage',[item]);
  const to=await reviewer(ctx,data.reviewerId);if(!permitted(state,'reviews.manage',{personId:to.id,write:true}))fail('review_resource_outside_scope',403);const reason=String(data.reason??'').trim();if(!reason||reason.length>500)fail('delegation_reason_required');
  if(to.id===item.subject_id)fail('self_approval_refused',403);
  const g=actor.guard,p=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
  const [updated]=await ctx.db.batch([
   p(`UPDATE auth_review_items SET reviewer_id=? WHERE id=? AND reviewer_id=? AND decision IS NULL AND EXISTS(SELECT 1 FROM auth_reviews WHERE id=? AND status='open') AND ${g.clause}`,to.id,item.id,item.reviewer_id,item.review_id,...g.args),
   p(`INSERT INTO auth_review_events(id,review_id,item_id,actor_id,event,detail,created_at) SELECT ?,?,?,?,'delegated',?,? WHERE changes()>0`,random(),item.review_id,item.id,s.person_id,JSON.stringify({from:item.reviewer_id,to:to.id,reason}),ctx.now()),
  ]);
  if(!updated.meta.changes)fail('review_changed',409);return json({ok:true});
 }
 const g=actor.guard;
 if(path==='/reviews/create') {
  const name=String(data.name??'').trim();if(!name||name.length>120)fail('review_name_required');
  const to=await reviewer(ctx,data.reviewerId);if(!permitted(state,'reviews.manage',{personId:to.id,write:true}))fail('review_resource_outside_scope',403);const dueAt=time(data.dueAt,'invalid_review_due'),periodStart=time(data.periodStart,'invalid_review_period'),periodEnd=time(data.periodEnd,'invalid_review_period');
  if(periodStart>=periodEnd||periodEnd>ctx.now()||dueAt<=ctx.now())fail('invalid_review_period');
  const intervalMonths=Number(data.intervalMonths??0);if(![0,1,3,6,12].includes(intervalMonths))fail('invalid_review_interval');
  const settings={name,reviewerId:to.id,dueAt,periodStart,periodEnd,includeAdministrators:data.includeAdministrators===true};
  let scheduleId=null;
  if(intervalMonths) {
   scheduleId=random();
   settings.newSchedule={intervalMonths,nextAt:nextQuarter(periodEnd,intervalMonths)};
  }
  return json(await createReview(ctx,s,settings,g,scheduleId),201);
 }
 if(path==='/reviews/disable-schedule') {
  const schedule=await one(ctx,'SELECT * FROM auth_review_schedules WHERE id=?',String(data.id??''))??fail('schedule_not_found',404);
  const latest=await one(ctx,'SELECT * FROM auth_reviews WHERE schedule_id=? ORDER BY created_at DESC LIMIT 1',schedule.id);
  if(latest)requireReviewScope(state,'reviews.manage',(await reviewView(ctx,s,latest,true)).items);
  if(schedule.created_by!==s.person_id&&!state.legacy)fail('schedule_owner_required',403);
  const result=await ctx.db.prepare(`UPDATE auth_review_schedules SET enabled=0 WHERE id=? AND ${g.clause}`).bind(schedule.id,...g.args).run();
  if(!result.meta.changes)fail('schedule_not_found',404);return json({ok:true});
 }
 const epoch=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 const row=await one(ctx,"SELECT * FROM auth_reviews WHERE id=? AND status='open'",String(data.id??''))??fail('open_review_not_found',404),view=await reviewView(ctx,s,row,true);
 requireReviewScope(state,'reviews.manage',view.items);
 if(!view.completion.complete)return json({error:'review_remediation_unfinished',completion:view.completion},409);
 const result=await ctx.db.prepare(`UPDATE auth_reviews SET status='closed',closed_at=? WHERE id=? AND status='open' AND ${g.clause} AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?) AND NOT EXISTS(SELECT 1 FROM auth_review_items WHERE review_id=? AND decision IS NULL)`).bind(ctx.now(),row.id,...g.args,epoch.epoch,row.id).run();
 if(!result.meta.changes)fail('review_changed',409);return json({ok:true});
}
export async function maintainReviews(ctx) {
 await maintainReviewReminders(ctx);
 // Only consented recurring snapshots run automatically. They neither decide
 // access nor remove it, and stop if their accountable administrator leaves.
 for(const schedule of await all(ctx,'SELECT * FROM auth_review_schedules WHERE enabled=1 AND next_at<=? ORDER BY next_at,id',ctx.now())) {
  const owner=await one(ctx,"SELECT id,role FROM oa_operators WHERE id=? AND status='active'",schedule.created_by),liveState=owner?await roleState(ctx,{person_id:owner.id}):null;
  if(!owner||!canManageReviews(liveState)||!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active'",schedule.reviewer_id)) {
   await ctx.db.prepare('UPDATE auth_review_schedules SET enabled=0 WHERE id=?').bind(schedule.id).run();continue;
  }
  const s={person_id:owner.id},g={clause:"EXISTS(SELECT 1 FROM auth_review_schedules WHERE id=? AND enabled=1 AND next_at=?) AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND status='active' AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?))",args:[schedule.id,schedule.next_at,owner.id,liveState.epoch]};
  const previous=await one(ctx,'SELECT id FROM auth_reviews WHERE schedule_id=? ORDER BY period_end DESC LIMIT 1',schedule.id);
  if(!permitted(liveState,'reviews.manage',{personId:schedule.reviewer_id,write:true})){await ctx.db.prepare('UPDATE auth_review_schedules SET enabled=0 WHERE id=?').bind(schedule.id).run();continue;}
  if(!await one(ctx,'SELECT 1 FROM auth_reviews WHERE schedule_id=? AND period_end=?',schedule.id,schedule.next_at))await createReview(ctx,s,{name:schedule.name,reviewerId:schedule.reviewer_id,periodStart:nextQuarter(schedule.next_at,-schedule.interval_months),periodEnd:schedule.next_at,dueAt:ctx.now()+schedule.duration_ms,includeAdministrators:previous?await includesAdministrators(ctx,previous.id):false},g,schedule.id);
  await ctx.db.prepare('UPDATE auth_review_schedules SET next_at=? WHERE id=? AND next_at=?').bind(nextQuarter(schedule.next_at,schedule.interval_months),schedule.id,schedule.next_at).run();
 }
 for(const row of await all(ctx,"SELECT * FROM auth_reviews WHERE status='open' AND due_at<=?",ctx.now())) {
  await ctx.db.prepare("INSERT INTO auth_review_events(id,review_id,event,detail,created_at) SELECT ?,?,'overdue_escalated','{\"action\":\"administrator_reassign_or_complete\"}',? WHERE NOT EXISTS(SELECT 1 FROM auth_review_events WHERE review_id=? AND event='overdue_escalated')").bind(random(),row.id,ctx.now(),row.id).run();
 }
}
