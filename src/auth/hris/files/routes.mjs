import {reviewFile} from './review.mjs';
import {applyHrFile} from './apply.mjs';
import {all,one,random,hash,fail,json,requireSession,auditDetail,limit} from '../../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../../local-email.mjs';
import {loadDirectory} from '../../workforce/people/load.mjs';
import {normalize} from '../../workforce/people/fields.mjs';
import {MAX_BYTES,feedMapping,parseFeed} from './parse.mjs';
export const HR_FEEDS='/api/auth/hr-feeds';
export const isHrFeedAction=action=>['/hr-feeds/create','/hr-feeds/upload','/hr-feeds/disable','/hr-feeds/close-file','/hr-feeds/apply'].includes(action);
async function administrator(ctx,request,write=false) {
 const s=await requireSession(ctx,request,true);if(!['owner','admin'].includes(s.role))fail('administrator_required',403);
 if(write)requireLocalEmail(ctx,s);return s;
}
const liveFeed=(ctx,id)=>one(ctx,`SELECT f.* FROM auth_hr_feeds f JOIN oa_operators p ON p.id=f.created_by WHERE f.id=? AND f.disabled_at IS NULL AND f.token_hash IS NOT NULL AND p.status='active' AND p.role IN ('owner','admin') AND p.version=f.owner_version`,id);
const stale=(ctx,feed)=>ctx.now()>=(feed.last_success_at??feed.created_at)+2*feed.schedule_ms;
function publicFeed(ctx,feed) {
 return {id:feed.id,name:feed.name,schedule:feed.schedule_ms===3600000?'hourly':'daily',mapping:JSON.parse(feed.mapping),
  fingerprint:feed.fingerprint,terminationPercent:feed.termination_percent,lastReceivedAt:feed.last_received_at,lastSuccessfulReadAt:feed.last_success_at,
  stale:feed.disabled_at===null&&stale(ctx,feed),disabled:feed.disabled_at!==null,
  policy:'Files require an administrator review; ingestion never changes directory authority.'};
}
export async function hrFeedRead(ctx,request) {
 const s=await administrator(ctx,request),url=new URL(request.url),feedId=url.searchParams.get('feedId'),fileId=url.searchParams.get('fileId');
 const feeds=await all(ctx,'SELECT * FROM auth_hr_feeds ORDER BY created_at,id');
 const files=await all(ctx,`SELECT * FROM auth_hr_files ${feedId?'WHERE feed_id=?':''} ORDER BY received_at DESC,id DESC LIMIT 100`,...(feedId?[feedId]:[]));
 let preview=null;
 if(fileId) {
  const reviewed=await reviewFile(ctx,s,fileId);
  const {feed,records,edits,...publicPreview}=reviewed;preview=publicPreview;
 }
 const current=await requireSession(ctx,request,true);if(current.id!==s.id)fail('session_authority_changed',403);
 return json({feeds:feeds.map(feed=>publicFeed(ctx,feed)),files:files.map(file=>({...file,reasons:JSON.parse(file.reasons)})),preview},200,{'cache-control':'no-store'});
}
async function receive(ctx,feed,data,transport,guard) {
 if(typeof data.text!=='string'||new TextEncoder().encode(data.text).length>MAX_BYTES)fail('hr_file_too_large',413);
 if(typeof data.fileName!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.csv$/.test(data.fileName)||data.fileName.includes('..'))fail('invalid_hr_file_name');
 if(!await limit(ctx,'hr-feed:'+feed.id,60,3600000))fail('rate_limited',429);
 const digest=await hash(data.text),prior=await one(ctx,'SELECT id,state FROM auth_hr_files WHERE feed_id=? AND digest=?',feed.id,digest);
 if(prior)return json({fileId:prior.id,state:prior.state,replayed:true},202);
 const parsed=parseFeed(data.text,JSON.parse(feed.mapping)),reasons=[...parsed.errors],directory=await loadDirectory(ctx);
 for(const row of parsed.records)for(const [field,value] of Object.entries(row.fields)){try{await normalize(ctx,directory.defs.get(field),value);}catch{if(!reasons.includes('invalid_profile_field'))reasons.push('invalid_profile_field');}}
 const workers=[...directory.people.values()].filter(person=>person.role==='member'&&person.status==='active').length;
 const terminations=parsed.records.filter(row=>row.state==='terminated').length;
 if(terminations&&(!workers||terminations*100>workers*feed.termination_percent))reasons.push('termination_threshold_exceeded');
 const id=random(),state=reasons.length?'held':'staged',marker={clause:'EXISTS(SELECT 1 FROM auth_hr_files WHERE id=?)',args:[id]};
 const statements=[ctx.db.prepare(`INSERT INTO auth_hr_files(id,feed_id,digest,file_name,received_at,transport,state,reasons,row_count) SELECT ?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`).bind(id,feed.id,digest,data.fileName,ctx.now(),transport,state,JSON.stringify(reasons),parsed.records.length,...guard.args),
  ctx.db.prepare(`UPDATE auth_hr_feeds SET last_received_at=?,last_success_at=CASE WHEN ?=0 THEN ? ELSE last_success_at END WHERE id=? AND ${marker.clause}`).bind(ctx.now(),reasons.length,ctx.now(),feed.id,id),
  ...parsed.records.map((row,idx)=>ctx.db.prepare(`INSERT INTO auth_hr_file_rows(file_id,idx,source_id,record) SELECT ?,?,?,? WHERE ${marker.clause}`).bind(id,idx,feed.id+':'+row.sourceId,JSON.stringify(row),id)),
 ];
 let done;try{done=await ctx.db.batch(statements);}catch(error){
  if(/UNIQUE constraint failed/.test(String(error?.message))){const existing=await one(ctx,'SELECT id,state FROM auth_hr_files WHERE feed_id=? AND digest=?',feed.id,digest);if(existing)return json({fileId:existing.id,state:existing.state,replayed:true},202);}throw error;
 }
 if(!done[0].meta.changes)fail('hr_feed_authority_changed',409);
 await auditDetail(ctx,null,'hr_file_received',feed.id,{fileId:id,transport,state,reasons,rows:parsed.records.length});
 return json({fileId:id,state,reasons,rowCount:parsed.records.length},202);
}
export async function hrFeedIngress(ctx,request,data) {
 const match=/^AuthFeed ([A-Za-z0-9_-]{43})$/.exec(request.headers.get('authorization')??'');
 const feed=typeof data.feedId==='string'?await liveFeed(ctx,data.feedId):null;
 if(!feed||!match||feed.token_hash!==await hash(match[1])||request.headers.get('x-auth-sftp-fingerprint')!==feed.fingerprint)fail('hr_feed_credential_refused',401);
 const guard={clause:"EXISTS(SELECT 1 FROM auth_hr_feeds f JOIN oa_operators p ON p.id=f.created_by WHERE f.id=? AND f.disabled_at IS NULL AND f.token_hash=? AND p.status='active' AND p.role IN ('owner','admin') AND p.version=f.owner_version)",args:[feed.id,feed.token_hash]};
 return receive(ctx,feed,data,'sftp',guard);
}
export async function hrFeedAction(ctx,request,action,data) {
 const s=await administrator(ctx,request,true),guard=authority(ctx,s,['owner','admin']);
 if(action==='/hr-feeds/create') {
  const mapping=feedMapping(data.mapping),scheduleMs=data.schedule==='hourly'?3600000:data.schedule==='daily'?86400000:0;
  if(typeof data.name!=='string'||!data.name.trim()||data.name.length>80||!scheduleMs||typeof data.fingerprint!=='string'||!/^SHA256:[A-Za-z0-9+/]{43}$/.test(data.fingerprint)||data.confirm!==true)fail('invalid_hr_feed');
  const percent=data.terminationPercent??5;if(!Number.isInteger(percent)||percent<1||percent>50)fail('invalid_termination_threshold');
  const id=random(),credential=random(),digest=await hash(credential);
  const done=await ctx.db.prepare(`INSERT INTO auth_hr_feeds(id,name,schedule_ms,mapping,fingerprint,token_hash,termination_percent,created_by,owner_version,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`).bind(id,data.name.trim(),scheduleMs,JSON.stringify(mapping),data.fingerprint,digest,percent,s.person_id,s.person_version,ctx.now(),...guard.args).run();
  if(!done.meta.changes){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
  await auditDetail(ctx,s.person_id,'hr_feed_created',id,{schedule:data.schedule,terminationPercent:percent,policy:'review_only',consent:true});
  return json({id,ingressToken:credential,fingerprint:data.fingerprint,policy:'review_only'},201);
 }
 const feed=await liveFeed(ctx,String(data.feedId??''))||fail('hr_feed_not_found',404);
 if(action==='/hr-feeds/apply')return applyHrFile(ctx,request,s,data);
 if(action==='/hr-feeds/close-file') {
  if(data.confirm!==true)fail('explicit_hr_review_close_required',403);
  const done=await ctx.db.prepare(`UPDATE auth_hr_files SET state='reviewed' WHERE id=? AND feed_id=? AND ${guard.clause}`).bind(String(data.fileId??''),feed.id,...guard.args).run();
  if(!done.meta.changes){await requireAuthority(ctx,s,guard);fail('hr_file_not_found',404);}
  await auditDetail(ctx,s.person_id,'hr_file_review_closed',feed.id,{fileId:data.fileId,directoryChange:false});
  return json({reviewClosed:true,directoryChange:false});
 }
 if(action==='/hr-feeds/disable') {
  const result=await ctx.db.prepare(`UPDATE auth_hr_feeds SET disabled_at=?,token_hash=NULL WHERE id=? AND ${guard.clause}`).bind(ctx.now(),feed.id,...guard.args).run();
  if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('hr_feed_authority_changed',409);}
  await auditDetail(ctx,s.person_id,'hr_feed_disabled',feed.id,{});return json({disabled:true,credentialDestroyed:true});
 }
 return receive(ctx,feed,data,'upload',{clause:`${guard.clause} AND EXISTS(SELECT 1 FROM auth_hr_feeds WHERE id=? AND disabled_at IS NULL AND token_hash=?)`,args:[...guard.args,feed.id,feed.token_hash]});
}
