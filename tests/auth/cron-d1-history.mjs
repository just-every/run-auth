import {createRequire} from 'node:module';
import {readFile,readdir,realpath} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {statements} from './link/schema.mjs';
import {calendar} from '../../src/auth/obligations/calendar.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
export const DAY=86400000;
export const NOW=1800000000000;

// A local D1 with every migration applied, as the Worker's database is.
export async function openMigratedD1() {
 const require=createRequire(await realpath(join(root,'node_modules/wrangler/package.json')));
 const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-09-01',compatibilityFlags:['nodejs_compat'],d1Databases:{DB:'auth-cron-budget'}}));
 const db=await mf.getD1Database('DB'),directory=join(root,'migrations/core');
 for(const file of (await readdir(directory)).filter(name=>name.endsWith('.sql')).sort())for(const sql of statements(await readFile(join(directory,file),'utf8')))await db.prepare(sql).run();
 return {db,close:()=>mf.dispose()};
}

// Count the rows D1 itself reports reading and writing for every statement.
export function metered(db,log) {
 const record=meta=>log.push({read:meta?.rows_read??0,written:meta?.rows_written??0});
 const wrap=statement=>({
  statement,
  bind:(...values)=>wrap(statement.bind(...values)),
  all:async()=>{const result=await statement.all();record(result.meta);return result;},
  run:async()=>{const result=await statement.run();record(result.meta);return result;},
  first:async column=>{const result=await statement.all();record(result.meta);const row=result.results[0];return row===undefined?null:column?row[column]:row;},
  raw:async()=>{const result=await statement.all();record(result.meta);return result.results.map(row=>Object.values(row));},
 });
 return {
  prepare:sql=>wrap(db.prepare(sql)),
  batch:async statements=>{const results=await db.batch(statements.map(item=>item.statement));results.forEach(result=>record(result.meta));return results;},
  exec:sql=>db.exec(sql),
 };
}
export const total=log=>({read:log.reduce((sum,item)=>sum+item.read,0),written:log.reduce((sum,item)=>sum+item.written,0),statements:log.length});

// An installation that has run for `days` days: a small company's people, then
// every append-only record its daily traffic leaves behind. Finished work is
// finished; only the last few days of each kind are still open.
export async function seedHistory(db,{days,people=40}) {
 const stamp=(daysAgo,slot=0)=>NOW-daysAgo*DAY-slot*60000;
 const batch=[];const push=(sql,...values)=>batch.push(db.prepare(sql).bind(...values));
 const flush=async()=>{for(let at=0;at<batch.length;at+=50)await db.batch(batch.slice(at,at+50));batch.length=0;};
 push("INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES('owner','owner@example.com','Owner','owner','active',1,?)",stamp(days+30));
 for(let i=0;i<people;i++)push("INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) VALUES(?,?,?,?,?,1,?)",`p${i}`,`p${i}@example.com`,`Person ${i}`,i<2?'admin':'member','active',stamp(days+20));
 push("INSERT INTO auth_apps(id,name,entity_id,acs,name_id_format,name_id_source,sign,digest,created_by,created_at,updated_at,protocol) VALUES('app','App','https://app.example.com','https://app.example.com/acs','persistent','person_id','response','sha256','owner',?,?,'oidc')",stamp(days+10),stamp(days+10));
 push("INSERT INTO auth_oidc_clients(app_id,client_id,auth_method,redirect_uris,require_pkce,subject_type,backchannel_logout_uri,id_token_alg) VALUES('app','client','none','[]',1,'public','https://app.example.com/logout','ES256')");
 push("INSERT INTO auth_resource_apis(id,app_id,name,audience,policy,created_by,created_at,updated_at) VALUES('api','app','Api','https://api.example.com','{}','owner',?,?)",stamp(days+10),stamp(days+10));
 push("INSERT INTO auth_admin_service_apps(id,client_id,name,purpose,owner_id,jwks,scopes,resources,created_by,created_at,expires_at) VALUES('svc','svc-client','Agent','test','owner','{}','[]','[]','owner',?,?)",stamp(days+10),NOW+DAY*300);
 push("INSERT INTO auth_delegated_agents(id,client_id,service_app_id,name,registered_by,registered_owner_version,created_at,expires_at) VALUES('agent','agent-client','svc','Agent','owner',1,?,?)",stamp(days+10),NOW+DAY*300);
 push("INSERT INTO auth_directory_sources(id,kind,mode,name,organization_binding,fields,created_by,owner_version,created_at,last_read_at,next_poll_at) VALUES('dir','scim','pull','Directory','root','{}','owner',1,?,?,?)",stamp(days+10),NOW-60000,NOW+DAY);
 await flush();
 const obligation=(kind,source,ownerId,state,at)=>push("INSERT INTO auth_obligations(id,kind,source_id,owner_id,next_action,calendar,deadline_at,next_due_at,state,stop_rule,escalation_rule,created_at,stopped_at) VALUES(?,?,?,?,'review_source',?,?,?,?,'source_satisfied_cancelled_or_authority_expired','stop_at_deadline',?,?)",`ob-${source}`,kind,source,ownerId,JSON.stringify(calendar()),at+DAY,at+DAY,state,at,at+3600000);
 for(let day=0;day<days;day++)for(let slot=0;slot<6;slot++) {
  const n=day*6+slot,at=stamp(day,slot*100),person=`p${n%people}`;
  const subject=JSON.stringify({type:'person',id:person}),data=JSON.stringify({group:'g'+(n%4)});
  push("INSERT INTO auth_events(id,type,version,subject,data,occurred_at) VALUES(?,?,1,?,?,?)",`evt-${n}`,slot===0?'group.member_added':['person.invited','person.activated','person.role_changed','app.assigned','group.member_removed'][slot-1],subject,data,at);
 }
 for(let day=0;day<days;day++) {
  const open=day<2;
  for(let slot=0;slot<5;slot++) {
   const n=day*5+slot,at=stamp(day,slot*100);
   push("INSERT INTO auth_oidc_logouts(id,client_id,person_id,sid,jti,attempts,next_attempt_at,created_at,finished_at,outcome) VALUES(?,'client',?,?,?,1,?,?,?,'delivered')",`lo-${n}`,`p${n%people}`,`sid-${n}`,`jti-${n}`,at,at,at+1000);
  }
  for(let slot=0;slot<2;slot++) {
   const n=day*2+slot,at=stamp(day,slot*100),live=false;
   push("INSERT INTO auth_refresh_families(id,client_id,api_id,person_id,person_version,session_id,profile_revision,api_revision,app_version,scopes,jkt,device_name,current_hash,generation,created_at,last_used_at,idle_expires_at,absolute_expires_at,revoked_at,reason,logout_queued_at) VALUES(?,'client','api',?,1,?,1,1,1,'[]','jkt','device',?,1,?,?,?,?,?,?,?)",`rf-${n}`,`p${n%people}`,`sid-${n}`,`hash-${n}`,at,at,live?NOW+DAY:at+DAY,live?NOW+30*DAY:at+30*DAY,live?null:at+3600000,live?null:'sign_out',live?null:at+3600000);
   push("INSERT INTO auth_refresh_credentials(token_hash,family_id,generation,created_at,consumed_at) VALUES(?,?,0,?,?)",`hash-${n}-0`,`rf-${n}`,at,at+1000);
  }
  for(let slot=0;slot<3;slot++) {
   const n=day*3+slot,at=stamp(day,slot*100),id=`ni-${n}`;
   push("INSERT INTO auth_security_notice_intents(id,person_id,grant_id,recipient_email,context,created_at,state) VALUES(?,?,'grant','p@example.com','{}',?,'accepted')",id,`p${n%people}`,at);
   obligation('app_setup','security-notice:'+id,'owner','completed',at);
  }
  {
   const at=stamp(day,0),id=`ar-${day}`;
   push("INSERT INTO auth_access_requests(id,app_id,person_id,purpose,duration_ms,decider_id,policy_revision,created_at,state,decided_by,decided_at,expires_at) VALUES(?,'app',?,'work',?,'owner',1,?,?,?,?,?)",id,`p${day%people}`,DAY,at,open?'pending':day%2?'denied':'expired_verified',open?null:'owner',open?null:at+3600000,open?null:at+DAY);
   obligation('app_setup','access-request:'+id,'owner',open?'open':'completed',at);
   const link=`lr-${day}`;
   push("INSERT INTO auth_link_requests(id,origin,interface,app,key_changed,first_seen,punycode,requested_by,created_at,expires_at,decided_by,decided_at,outcome) VALUES(?,'https://app.example.com','oidc','App',0,1,0,'owner',?,?,'owner',?,'linked')",link,at,at+3600000,at+600000);
   obligation('app_setup',link,'owner','completed',at);
   const task=`dt-${day}`;
   push("INSERT INTO auth_delegated_tasks(id,agent_id,agent_revision,service_revision,organization_id,accountable_id,accountable_version,app_id,app_version,native_epoch,role_epoch,effect,effect_digest,before_created_by,before_created_at,created_at,expires_at,state,completed_at,execution_id) VALUES(?,'agent',1,1,'root',?,1,'app',1,1,1,'{}','digest','owner',?,?,?,'completed',?,?)",task,`p${day%people}`,at,at,at+DAY,at+3600000,'exec-'+task);
   obligation('delegated_assignment',task,`p${day%people}`,'completed',at);
   push("INSERT INTO auth_directory_snapshots(id,source_id,digest,payload,complete,state,reasons,created_at) VALUES(?,'dir',?,'{}',1,'applied','[]',?)",`snap-${day}`,`digest-${day}`,at);
  }
  await flush();
 }
 // A review every ten days: twenty items each, every one decided, with the
 // reminder and decision events they leave behind.
 for(let review=0;review<Math.ceil(days/10);review++) {
  const at=stamp(review*10+5);
  push("INSERT INTO auth_reviews(id,name,reviewer_id,period_start,period_end,due_at,created_by,created_at,status,closed_at) VALUES(?,'Quarter','owner',?,?,?,'owner',?,'closed',?)",`rv-${review}`,at-90*DAY,at,at+14*DAY,at,at+3*DAY);
  for(let item=0;item<20;item++) {
   const id=`ri-${review}-${item}`;
   push("INSERT INTO auth_review_items(id,review_id,subject_id,app_id,principal_type,principal_id,role,snapshot,reviewer_id,decision,decided_by,decided_at) VALUES(?,?,?,'app','person',?,'member','{}','owner','keep','owner',?)",id,`rv-${review}`,`p${item}`,`p${item}`,at+DAY);
   for(const name of ['review_reminder_occurrence','review_reminder_dispatching','review_reminder_accepted'])push("INSERT INTO auth_review_events(id,review_id,item_id,event,detail,created_at) VALUES(?,?,?,?,?,?)",`${id}:${name}`,`rv-${review}`,id,name,JSON.stringify({scheduledDue:at,recipientId:'owner'}),at+DAY/2);
   obligation('app_setup','review-item:'+id,'owner','completed',at);
  }
  await flush();
 }
 push("INSERT INTO auth_role_cases(id,person_id,reason,state,opened_by,created_at,updated_at) VALUES('case-0','p0','lost device','closed','owner',?,?)",stamp(days-1>0?days-1:1),stamp(days-1>0?days-1:1));
 obligation('recovery','case-0','owner','completed',stamp(days-1>0?days-1:1));
 await flush();
}
