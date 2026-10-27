import {syncObligations} from '../obligations/sources.mjs';
import {one,all,run,json,fail,requireSession,random,auditDetail} from '../core.mjs';
import {seal} from '../keys.mjs';
import {requireRolePermission,assertGuard,permitted} from '../roles/policy.mjs';
import {automationUrl} from './network.mjs';
import {connectionAuthority,loadAutomation} from './authority.mjs';
import {createRun,executeRun} from './engine.mjs';

export const AUTOMATIONS_READ='/api/auth/automations';
export const isAutomationAction=path=>['/automations/connect','/automations/save','/automations/dry-run','/automations/prepare','/automations/approve','/automations/execute','/automations/revoke'].includes(path);
const text=(v,n=120)=>typeof v==='string'&&v.trim()&&v.length<=n?v.trim():fail('invalid_automation_configuration');
function paths(raw) {
 if(!Array.isArray(raw)||raw.length!==2||raw.some(p=>typeof p!=='string'||!/^\/[A-Za-z0-9/_-]*$/.test(p)||p.startsWith('//')||p.length>200))fail('invalid_automation_paths');
 return raw;
}
export async function automationsModel(ctx,s) {
 const guard=await requireRolePermission(ctx,s,'automations.manage',{write:false});
 const connections=(await all(ctx,'SELECT id,name,origin,token_url,paths,group_id,granted_to,version,revoked_at FROM auth_automation_connections WHERE granted_to=?',s.person_id)).filter(c=>permitted(guard.state,'automations.manage',{groupId:c.group_id}));
 const allowed=new Set(connections.map(c=>c.id));
 const automations=(await all(ctx,'SELECT * FROM auth_automations')).filter(a=>allowed.has(a.id)).map(a=>({...a,config:JSON.parse(a.config)}));
 const runs=(await all(ctx,'SELECT id,automation_id,automation_version,connection_version,person_id,state,approved_by,error,created_at FROM auth_automation_runs ORDER BY created_at DESC,id DESC LIMIT 100')).filter(r=>allowed.has(r.automation_id)&&permitted(guard.state,'automations.manage',{personId:r.person_id}));
 const steps=(await all(ctx,'SELECT * FROM auth_automation_steps')).filter(step=>runs.some(r=>r.id===step.run_id));
 await assertGuard(ctx,guard);
 return {connections:connections.map(c=>({...c,paths:JSON.parse(c.paths)})),automations,runs:runs.map(r=>({...r,steps:steps.filter(step=>step.run_id===r.id)})),groups:guard.state.dir.groups.filter(g=>permitted(guard.state,'automations.manage',{groupId:g.id,write:true})).map(g=>({id:g.id,name:g.name})),people:[...guard.state.dir.people.values()].filter(p=>permitted(guard.state,'automations.manage',{personId:p.id,write:true})).map(p=>({id:p.id,name:p.name,email:p.email}))};
}
export async function automationsRead(ctx,request) {return json(await automationsModel(ctx,await requireSession(ctx,request)));}
export async function automationAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request);
 if(path==='/automations/connect') {
  const guard=await requireRolePermission(ctx,s,'automations.manage',{groupId:text(data.groupId),write:true});
  if(data.grant!==true)fail('automation_explicit_grant_required',403);
  if(!guard.state.dir.groups.some(g=>g.id===data.groupId))fail('group_not_found',404);
  const origin=automationUrl(ctx,text(data.origin,2000));
  if(new URL(origin).pathname!=='/')fail('invalid_automation_origin');
  const tokenUrl=automationUrl(ctx,text(data.tokenUrl,2000));
  // Connection authority is limited to one host, two exact POST destinations,
  // one group, and the named administrator making this explicit grant.
  if(new URL(tokenUrl).origin!==new URL(origin).origin)fail('automation_token_outside_grant',403);
  const id=random(),credentials={clientId:text(data.clientId,256),clientSecret:text(data.clientSecret,4096),scope:text(data.scope,500),signingKey:text(data.signingKey,4096)};
  const result=await run(ctx,`INSERT INTO auth_automation_connections(id,name,origin,token_url,paths,group_id,granted_to,sealed_credentials,created_by,created_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`,id,text(data.name),new URL(origin).origin,tokenUrl,JSON.stringify(paths(data.paths)),data.groupId,s.person_id,await seal(ctx,'automation:'+id,credentials),s.person_id,ctx.now(),...guard.args);
  if(!result.meta.changes){await assertGuard(ctx,guard);fail('automation_authority_changed',409);}
  await auditDetail(ctx,s.person_id,'automation_connection_granted',id,{groupId:data.groupId});
  return json({id},201);
 }
 const id=text(data.automationId??data.id,100);
 const c=await one(ctx,'SELECT * FROM auth_automation_connections WHERE id=?',id)||fail('automation_not_found',404);
 const personId=data.personId?text(data.personId,100):null;
 const guard=await connectionAuthority(ctx,s,c,personId);
 if(path==='/automations/revoke') {
  const changed=await run(ctx,`UPDATE auth_automation_connections SET revoked_at=?,version=version+1 WHERE id=? AND ${guard.clause}`,ctx.now(),id,...guard.args);
  if(!changed.meta.changes)fail('automation_authority_changed',409);
  await auditDetail(ctx,s.person_id,'automation_connection_revoked',id,{});return json({ok:true});
 }
 if(path==='/automations/save') {
  const requested=paths(data.paths),granted=JSON.parse(c.paths);
  if(requested.some(p=>!granted.includes(p)))fail('automation_step_outside_grant',403);
  const responseField=text(data.responseField,40);if(!/^[A-Za-z][A-Za-z0-9_]*$/.test(responseField))fail('invalid_automation_response_field');
  const config=JSON.stringify({trigger:'group.member_added',paths:requested,responseField});
  const changed=(await ctx.db.batch([ctx.db.prepare(`INSERT INTO auth_automations(id,name,version,config,updated_by,updated_at) SELECT ?,?,1,?,?,? WHERE ${guard.clause} ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=version+1,config=excluded.config,updated_by=excluded.updated_by,updated_at=excluded.updated_at WHERE auth_automations.version=?`).bind(id,text(data.name),config,s.person_id,ctx.now(),...guard.args,Number(data.version??0)),ctx.db.prepare('INSERT INTO auth_automation_versions(automation_id,version,name,config,created_by,created_at) SELECT id,version,name,config,updated_by,updated_at FROM auth_automations WHERE id=? AND changes()>0').bind(id)]))[0];
  if(!changed.meta.changes)fail('automation_version_changed',409);
  await auditDetail(ctx,s.person_id,'automation_version_published',id,{});return json({id},201);
 }
 const {a}=await loadAutomation(ctx,id);
 if(path==='/automations/dry-run'||path==='/automations/prepare') {
  if(!personId)fail('automation_person_required');
  const dry=path==='/automations/dry-run',runId=await createRun(ctx,a,c,personId,{dry,guard});
  await auditDetail(ctx,s.person_id,dry?'automation_dry_run':'automation_run_prepared',runId,{personId,automationId:id,version:a.version});
  return json({id:runId,state:dry?'dry_run':'awaiting_approval',outboundCalls:0,intended:JSON.parse(a.config).paths.map((path,i)=>({step:i+1,method:'POST',destination:new URL(path,c.origin).href,input:i===0?{personId}:{personId,responseId:'Value from step one'}}))},201);
 }
 const r=await one(ctx,'SELECT * FROM auth_automation_runs WHERE id=? AND automation_id=?',text(data.runId,100),id)||fail('automation_run_not_found',404);
 const scoped=await connectionAuthority(ctx,s,c,r.person_id);
 if(path==='/automations/execute'){const outcome=await executeRun(ctx,r.id,request);await syncObligations(ctx);return json(outcome);}
 if(path!=='/automations/approve')fail('not_found',404);
 if(data.confirm!==r.id)fail('automation_exact_approval_required',403);
 if(r.automation_version!==a.version||r.connection_version!==c.version)fail('automation_approval_changed',409);
 const p=await one(ctx,"SELECT version FROM oa_operators WHERE id=? AND status='active'",r.person_id);
 if(!p||p.version!==r.person_version)fail('automation_person_changed',409);
 const changed=await run(ctx,`UPDATE auth_automation_runs SET state='approved',approved_by=?,session_id=?,epoch=?,approved_at=? WHERE id=? AND state='awaiting_approval' AND ${scoped.clause} AND EXISTS(SELECT 1 FROM auth_automations WHERE id=? AND version=?)`,s.person_id,s.id,scoped.state.epoch,ctx.now(),r.id,...scoped.args,a.id,a.version);
 if(!changed.meta.changes)fail('automation_approval_changed',409);
 await auditDetail(ctx,s.person_id,'automation_run_approved',r.id,{personId:r.person_id,version:a.version});
 return json({id:r.id,state:'approved'});
}
