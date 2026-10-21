import {computedValues,scimValues} from '../mapping/program.mjs';
// Provisioning obligations: what Auth still has to make true in an app, pushed
// on the event and kept open until a read-back shows it. Each records the event,
// dispatch and remote-verified times. Access ends locally before any of this:
// assignment and person status are checked at every sign-in.
import {one,all,run,random,audit} from '../core.mjs';
import {assignment,appSubjects} from '../workforce/directory.mjs';
import {scim,ok,retryable,findOne,connectorOf,USER,GROUP,PATCH} from './scim.mjs';
import {emit} from '../events/store.mjs';

const BACKOFF=[30000,60000,300000,900000,3600000],CLAIM=120000,BATCH=50;
// SCIM resource endpoints (RFC 7644 section 3.2).
const USERS='/Users',GROUPS='/Groups',userPath=id=>`${USERS}/${encodeURIComponent(id)}`,groupPath=id=>`${GROUPS}/${encodeURIComponent(id)}`;
export const ESCALATE_AFTER=900000;

const kick=(ctx,appId)=>{const work=dispatch(ctx,appId);if(ctx.waitUntil)ctx.waitUntil(work);else return work;};
export async function queue(ctx,appId,subjects,reason) {
 if(!subjects.length||!await connectorOf(ctx,appId))return;
 const now=ctx.now();
 await ctx.db.batch(subjects.flatMap(([type,id])=>[
  ctx.db.prepare("UPDATE auth_provisioning SET state='superseded' WHERE app_id=? AND subject_type=? AND subject_id=? AND state IN ('pending','failed','blocked')").bind(appId,type,id),
  ctx.db.prepare("INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at) VALUES(?,?,?,?,?,?,'pending',?)").bind(random(),appId,type,id,reason,now,now),
 ]));
 await kick(ctx,appId);
}
const groupsOf=async(ctx,appId,connector)=>connector?.push_groups?(await all(ctx,"SELECT principal_id AS id FROM auth_app_assignments WHERE app_id=? AND principal_type='group' UNION SELECT subject_id FROM auth_scim_accounts WHERE app_id=? AND subject_type='group'",appId,appId)).map(g=>['group',g.id]):[];

// Everything an app should hold, after a connector or assignment change.
export async function queueApp(ctx,appId,reason) {
 const connector=await connectorOf(ctx,appId);if(!connector)return;
 await queue(ctx,appId,[...(await appSubjects(ctx,appId)).map(id=>['person',id]),...await groupsOf(ctx,appId,connector)],reason);
}
// A person's status changed: every app that has or should have their account.
export async function personChanged(ctx,personId,reason) {
 const apps=await all(ctx,`SELECT DISTINCT c.app_id FROM auth_scim_connectors c WHERE EXISTS(SELECT 1 FROM auth_scim_accounts s WHERE s.app_id=c.app_id AND s.subject_type='person' AND s.subject_id=?)
  OR EXISTS(SELECT 1 FROM auth_app_assignments a LEFT JOIN auth_group_members m ON a.principal_type='group' AND m.group_id=a.principal_id WHERE a.app_id=c.app_id AND ((a.principal_type='person' AND a.principal_id=?) OR m.person_id=?))`,personId,personId,personId);
 for(const {app_id} of apps){const connector=await connectorOf(ctx,app_id);await queue(ctx,app_id,[['person',personId],...(connector.push_groups?(await all(ctx,"SELECT a.principal_id AS id FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group' AND m.person_id=?",app_id,personId)).map(g=>['group',g.id]):[])],reason);}
}
// A group's members changed: its members and the group itself in every app it is assigned to.
export async function groupChanged(ctx,groupId,personIds,reason) {
 for(const {app_id} of await all(ctx,"SELECT app_id FROM auth_app_assignments WHERE principal_type='group' AND principal_id=?",groupId)) {
  const connector=await connectorOf(ctx,app_id);if(!connector)continue;
  await queue(ctx,app_id,[...personIds.map(id=>['person',id]),...(connector.push_groups?[['group',groupId]]:[])],reason);
 }
}

// What the app should hold for one person: an active user with these attributes, or nothing active.
export async function desiredPerson(ctx,appId,personId) {
 const person=await one(ctx,'SELECT id,email,display_name FROM oa_operators WHERE id=?',personId);
 const assigned=person&&await assignment(ctx,appId,personId);
 if(!assigned)return {active:false,person};
 const name=(person.display_name||person.email).trim(),space=name.lastIndexOf(' ');
 const computed=await computedValues(ctx,appId,personId),mapped=scimValues(computed?.scim);
 return {active:true,person,role:assigned.role,user:{schemas:[USER],externalId:person.id,userName:person.email,displayName:name,name:{formatted:name,givenName:space>0?name.slice(0,space):name,familyName:space>0?name.slice(space+1):''},emails:[{value:person.email,type:'work',primary:true}],active:true,...(assigned.role?{roles:[{value:assigned.role,primary:true}]}:{}),...mapped,...(computed?.username?{userName:computed.username}:{})}};
}
const includesValue=(remote,desired)=>desired&&typeof desired==='object'?Object.entries(desired).every(([k,v])=>includesValue(remote?.[k],v)):remote===desired;
const sameUser=(remote,desired)=>remote&&includesValue(remote,desired)&&(remote.roles??[]).map(r=>r.value).join()===(desired.roles??[]).map(r=>r.value).join();
const account=(ctx,appId,type,id)=>one(ctx,'SELECT * FROM auth_scim_accounts WHERE app_id=? AND subject_type=? AND subject_id=?',appId,type,id);
const saveAccount=(ctx,appId,type,id,remote,state)=>run(ctx,'INSERT INTO auth_scim_accounts(app_id,subject_type,subject_id,remote_id,state,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(app_id,subject_type,subject_id) DO UPDATE SET remote_id=excluded.remote_id,state=excluded.state,updated_at=excluded.updated_at',appId,type,id,remote,state,ctx.now());

// Outcome: {verified, operation} or {retry|fail|block, response|error}. `wrote` marks dispatch.
async function applyPerson(ctx,connector,ob,wrote) {
 const appId=connector.app_id,desired=await desiredPerson(ctx,appId,ob.subject_id);let held=await account(ctx,appId,'person',ob.subject_id);
 if(desired.active) {
  let operation='update';if(held?.state==='deleted')held=null;
  if(!held) {
   // Adopt only an account Auth made (same externalId); never take one over by name.
   const mine=await findOne(ctx,connector,'Users','externalId',desired.user.externalId);if(!ok(mine.response))return {retry:mine.response};
   if(mine.found){await saveAccount(ctx,appId,'person',ob.subject_id,mine.found.id,'active');held=await account(ctx,appId,'person',ob.subject_id);}
   else {
    const named=await findOne(ctx,connector,'Users','userName',desired.user.userName);if(!ok(named.response))return {retry:named.response};
    if(named.found)return {block:'remote_account_exists'};
    wrote();const created=await scim(ctx,connector,'POST',USERS,desired.user);
    if(created.status===409)return {block:'remote_account_exists'};
    if(!ok(created)||!created.body?.id)return retryable(created)?{retry:created}:{fail:created};
    await saveAccount(ctx,appId,'person',ob.subject_id,created.body.id,'active');held=await account(ctx,appId,'person',ob.subject_id);operation='create';
   }
  }
  if(operation==='update') {
   wrote();const {schemas,...value}=desired.user;
   // No app role now: remove one the account had, rather than leave it.
   const patched=await scim(ctx,connector,'PATCH',userPath(held.remote_id),{schemas:[PATCH],Operations:[{op:'replace',value},...(value.roles?[]:[{op:'remove',path:'roles'}])]});
   if(patched.status===404){await run(ctx,'DELETE FROM auth_scim_accounts WHERE app_id=? AND subject_type=? AND subject_id=?',appId,'person',ob.subject_id);return {retry:patched,error:'remote_account_missing'};}
   if(!ok(patched))return retryable(patched)?{retry:patched}:{fail:patched};
   await saveAccount(ctx,appId,'person',ob.subject_id,held.remote_id,'active');
  }
  const read=await scim(ctx,connector,'GET',userPath(held.remote_id));
  if(!ok(read))return retryable(read)?{retry:read}:{fail:read};
  return sameUser(read.body,desired.user)?{verified:true,operation}:{retry:read,error:'remote_state_differs'};
 }
 if(!held||held.state==='deleted')return {verified:true,operation:'none'};
 const path=userPath(held.remote_id);
 if(connector.deprovision==='delete') {
  wrote();const removed=await scim(ctx,connector,'DELETE',path);
  if(!ok(removed)&&removed.status!==404)return retryable(removed)?{retry:removed}:{fail:removed};
  const read=await scim(ctx,connector,'GET',path);
  if(read.status!==404)return retryable(read)||ok(read)?{retry:read,error:'remote_account_still_present'}:{fail:read};
  await saveAccount(ctx,appId,'person',ob.subject_id,held.remote_id,'deleted');return {verified:true,operation:'delete'};
 }
 wrote();const patched=await scim(ctx,connector,'PATCH',path,{schemas:[PATCH],Operations:[{op:'replace',value:{active:false}}]});
 if(patched.status===404){await saveAccount(ctx,appId,'person',ob.subject_id,held.remote_id,'deleted');return {verified:true,operation:'deactivate'};}
 if(!ok(patched))return retryable(patched)?{retry:patched}:{fail:patched};
 const read=await scim(ctx,connector,'GET',path);
 if(read.status===404){await saveAccount(ctx,appId,'person',ob.subject_id,held.remote_id,'deleted');return {verified:true,operation:'deactivate'};}
 if(!ok(read))return retryable(read)?{retry:read}:{fail:read};
 if(read.body?.active!==false)return {retry:read,error:'remote_account_still_active'};
 await saveAccount(ctx,appId,'person',ob.subject_id,held.remote_id,'inactive');return {verified:true,operation:'deactivate'};
}

async function applyGroup(ctx,connector,ob,wrote) {
 const appId=connector.app_id,group=await one(ctx,'SELECT id,name FROM auth_groups WHERE id=?',ob.subject_id);
 const assigned=group&&await one(ctx,"SELECT 1 FROM auth_app_assignments a JOIN auth_apps p ON p.id=a.app_id WHERE a.app_id=? AND a.principal_type='group' AND a.principal_id=? AND p.disabled_at IS NULL",appId,group.id);
 const held=await account(ctx,appId,'group',ob.subject_id);
 if(!assigned) {
  if(!held||held.state==='deleted')return {verified:true,operation:'none'};
  wrote();const removed=await scim(ctx,connector,'DELETE',groupPath(held.remote_id));
  if(!ok(removed)&&removed.status!==404)return retryable(removed)?{retry:removed}:{fail:removed};
  await saveAccount(ctx,appId,'group',ob.subject_id,held.remote_id,'deleted');return {verified:true,operation:'delete'};
 }
 const members=(await all(ctx,"SELECT s.remote_id FROM auth_group_members m JOIN auth_scim_accounts s ON s.app_id=? AND s.subject_type='person' AND s.subject_id=m.person_id AND s.state='active' JOIN oa_operators o ON o.id=m.person_id AND o.status='active' WHERE m.group_id=? ORDER BY s.remote_id",appId,group.id)).map(m=>m.remote_id);
 let remote=held&&held.state!=='deleted'?held.remote_id:null,operation='update';
 if(!remote) {
  wrote();const created=await scim(ctx,connector,'POST',GROUPS,{schemas:[GROUP],displayName:group.name,externalId:group.id,members:members.map(value=>({value}))});
  if(created.status===409)return {block:'remote_group_exists'};
  if(!ok(created)||!created.body?.id)return retryable(created)?{retry:created}:{fail:created};
  remote=created.body.id;operation='create';await saveAccount(ctx,appId,'group',group.id,remote,'active');
 } else {
  wrote();const patched=await scim(ctx,connector,'PATCH',groupPath(remote),{schemas:[PATCH],Operations:[{op:'replace',value:{displayName:group.name,members:members.map(value=>({value}))}}]});
  if(!ok(patched))return retryable(patched)?{retry:patched}:{fail:patched};
 }
 const read=await scim(ctx,connector,'GET',groupPath(remote));
 if(!ok(read))return retryable(read)?{retry:read}:{fail:read};
 const got=(read.body?.members??[]).map(m=>m.value).sort().join();
 return got===members.join()&&read.body?.displayName===group.name?{verified:true,operation}:{retry:read,error:'remote_state_differs'};
}

const delay=(ob,response)=>{const after=Number(response?.retryAfter);return Number.isFinite(after)&&after>0?Math.min(after*1000,3600000):BACKOFF[Math.min(ob.attempts,BACKOFF.length-1)];};
export async function dispatch(ctx,appId=null) {
 const due=await all(ctx,`SELECT * FROM auth_provisioning WHERE state='pending' AND next_attempt_at<=? AND (claimed_until IS NULL OR claimed_until<=?)${appId?' AND app_id=?':''} ORDER BY CASE subject_type WHEN 'person' THEN 0 ELSE 1 END,event_at LIMIT ${BATCH}`,ctx.now(),ctx.now(),...(appId?[appId]:[]));
 for(const row of due) {
  const ob=await one(ctx,"UPDATE auth_provisioning SET claimed_until=? WHERE id=? AND state='pending' AND (claimed_until IS NULL OR claimed_until<=?) RETURNING *",ctx.now()+CLAIM,row.id,ctx.now());
  if(!ob)continue;
  const connector=await connectorOf(ctx,ob.app_id);
  if(!connector){await run(ctx,"UPDATE auth_provisioning SET state='failed',last_error='connector_removed',claimed_until=NULL WHERE id=?",ob.id);continue;}
  let wroteAt=ob.dispatched_at;const wrote=()=>{wroteAt??=ctx.now();};
  const outcome=await (ob.subject_type==='person'?applyPerson:applyGroup)(ctx,connector,ob,wrote).catch(error=>({retry:{status:0},error:String(error?.message||'error').slice(0,120)}));
  const now=ctx.now(),status=(outcome.retry??outcome.fail)?.status??null,error=outcome.error??outcome.block??(outcome.fail||outcome.retry?`http_${status}`:null);
  if(outcome.verified)await run(ctx,"UPDATE auth_provisioning SET state='verified',operation=?,dispatched_at=COALESCE(?,dispatched_at,?),verified_at=?,attempts=attempts+1,last_status=NULL,last_error=NULL,claimed_until=NULL WHERE id=?",outcome.operation,wroteAt,now,now,ob.id);
  else await run(ctx,"UPDATE auth_provisioning SET state=?,dispatched_at=?,attempts=attempts+1,next_attempt_at=?,last_status=?,last_error=?,claimed_until=NULL WHERE id=?",outcome.retry?'pending':outcome.block?'blocked':'failed',wroteAt,now+delay(ob,outcome.retry),status,error,ob.id);
  await run(ctx,`UPDATE auth_scim_connectors SET ${outcome.verified?'last_success_at=?,last_error=NULL':'last_error=?'} WHERE app_id=?`,outcome.verified?now:error,ob.app_id);
  // A person's new account may complete a pushed group's membership.
  if(outcome.verified&&ob.subject_type==='person'&&connector.push_groups&&outcome.operation!=='none')for(const g of await all(ctx,"SELECT a.principal_id AS id FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id WHERE a.app_id=? AND a.principal_type='group' AND m.person_id=?",ob.app_id,ob.subject_id))await requeueGroup(ctx,ob.app_id,g.id);
  if(outcome.fail||outcome.block)await audit(ctx,null,'provisioning_failed',ob.app_id);
  // Reported only once known: verified by read-back, or failed and still open.
  if(outcome.verified||outcome.fail||outcome.block)await emit(ctx,outcome.verified?'provisioning.verified':'provisioning.failed',{type:ob.subject_type,id:ob.subject_id},{app:ob.app_id,operation:outcome.operation??null,reason:ob.reason,error:outcome.verified?null:error,eventAt:new Date(ob.event_at).toISOString()});
 }
}
async function requeueGroup(ctx,appId,groupId) {
 if(await one(ctx,"SELECT 1 FROM auth_provisioning WHERE app_id=? AND subject_type='group' AND subject_id=? AND state='pending' AND dispatched_at IS NULL",appId,groupId))return;
 await ctx.db.batch([
  ctx.db.prepare("UPDATE auth_provisioning SET state='superseded' WHERE app_id=? AND subject_type='group' AND subject_id=? AND state IN ('pending','failed','blocked')").bind(appId,groupId),
  ctx.db.prepare("INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at) VALUES(?,?,'group',?,'member_provisioned',?,'pending',?)").bind(random(),appId,groupId,ctx.now(),ctx.now()),
 ]);
}

// Drift: read every remote user page; anything Auth manages that differs from
// what it should be is queued. Accounts Auth did not make are left alone.
export async function reconcile(ctx,appId) {
 const connector=await connectorOf(ctx,appId);if(!connector)return null;
 const seen=new Set(),drift=new Set();let start=1,pages=0,total=0;
 for(;pages<50;pages++) {
  const page=await scim(ctx,connector,'GET',`/Users?startIndex=${start}&count=100`);
  if(!ok(page))return {ok:false,status:page.status,pages};
  const resources=page.body?.Resources??[];total=page.body?.totalResults??0;
  for(const remote of resources) {
   const mine=await one(ctx,"SELECT subject_id FROM auth_scim_accounts WHERE app_id=? AND subject_type='person' AND remote_id=?",appId,remote.id);
   const personId=mine?.subject_id??(remote.externalId&&await one(ctx,'SELECT id FROM oa_operators WHERE id=?',remote.externalId)?remote.externalId:null);
   if(!personId)continue;seen.add(personId);
   const desired=await desiredPerson(ctx,appId,personId);
   if(desired.active?!sameUser(remote,desired.user):remote.active!==false)drift.add(personId);
  }
  start+=resources.length;if(!resources.length||start>total)break;
 }
 for(const id of await appSubjects(ctx,appId))if(!seen.has(id)&&(await desiredPerson(ctx,appId,id)).active)drift.add(id);
 await run(ctx,'UPDATE auth_scim_connectors SET last_reconciled_at=? WHERE app_id=?',ctx.now(),appId);
 await queue(ctx,appId,[...drift].map(id=>['person',id]),'reconcile');
 return {ok:true,remoteUsers:total,pages:pages+1,drift:drift.size};
}

// What a sync would do, read only: per person and group, the operation and the
// attributes pushed. Collisions show up when dispatch meets them (state blocked).
export async function preview(ctx,appId) {
 const connector=await connectorOf(ctx,appId),rows=[];
 for(const id of await appSubjects(ctx,appId)) {
  const desired=await desiredPerson(ctx,appId,id),held=await account(ctx,appId,'person',id);
  const operation=desired.active?(held&&held.state!=='deleted'?'update':'create'):(!held||held.state==='deleted'?'none':connector?.deprovision==='delete'?'delete':'deactivate');
  rows.push({type:'person',id,email:desired.person?.email??null,operation,destructive:['delete','deactivate'].includes(operation),attributes:desired.active?{userName:desired.user.userName,displayName:desired.user.displayName,role:desired.role??null,active:true}:{active:false}});
 }
 for(const [,id] of await groupsOf(ctx,appId,connector)){const g=await one(ctx,'SELECT name FROM auth_groups WHERE id=?',id),held=await account(ctx,appId,'group',id);rows.push({type:'group',id,name:g?.name??null,operation:!g?'delete':held&&held.state!=='deleted'?'update':'create',destructive:!g});}
 return rows;
}

// The due work for the scheduled handler: retries, then a daily reconciliation
// (a new connector's first is a day after the full push it made on connecting).
export async function maintainProvisioning(ctx) {
 await dispatch(ctx);
 for(const c of await all(ctx,'SELECT app_id FROM auth_scim_connectors WHERE COALESCE(last_reconciled_at,created_at)<=?',ctx.now()-86400000))await reconcile(ctx,c.app_id).catch(()=>null);
}
