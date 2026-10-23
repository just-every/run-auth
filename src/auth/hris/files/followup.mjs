import {one,all} from '../../core.mjs';
export async function hrFeedCandidates(ctx) {
 return (await all(ctx,`SELECT f.id,f.created_by,COALESCE(f.last_success_at,f.created_at) AS episode,f.schedule_ms FROM auth_hr_feeds f JOIN oa_operators p ON p.id=f.created_by
  WHERE f.disabled_at IS NULL AND p.status='active' AND p.version=f.owner_version AND p.role IN ('owner','admin') AND COALESCE(f.last_success_at,f.created_at)+2*f.schedule_ms<=?`,ctx.now()))
  .map(row=>({kind:'app_setup',source_id:'hr-feed:'+row.id+':'+row.episode,owner_id:row.created_by,hr_feed_id:row.id,episode:row.episode,created_at:row.episode+2*row.schedule_ms}));
}
export async function hrFeedSource(ctx,ob) {
 const binding=ob.hr_feed_id?{feed_id:ob.hr_feed_id,episode:ob.episode}:ob.id?await one(ctx,'SELECT feed_id,episode FROM auth_hr_feed_obligations WHERE obligation_id=?',ob.id):null;
 if(!binding)return null;
 const feed=await one(ctx,'SELECT * FROM auth_hr_feeds WHERE id=?',binding.feed_id);
 if(!feed||feed.disabled_at!==null)return {state:'cancelled'};
 if((feed.last_success_at??feed.created_at)!==binding.episode)return {state:'completed'};
 return {state:'open',action:'review_stale_hr_feed',error:'hr_feed_delivery_overdue'};
}
