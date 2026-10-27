import {one,all,run,random,fail} from '../core.mjs';
import {unseal} from '../keys.mjs';
import {executionAuthority,loadAutomation} from './authority.mjs';
import {requestJson,signedHeaders} from './network.mjs';

export async function createRun(ctx,a,c,personId,{eventId=null,dry=false,guard=null}={}) {
 const person=await one(ctx,"SELECT id,version FROM oa_operators WHERE id=? AND status IN ('active','invited')",personId)||fail('automation_person_unavailable',409);
 const id=random();
 const results=await ctx.db.batch([ctx.db.prepare(`INSERT OR IGNORE INTO auth_automation_runs(id,automation_id,automation_version,connection_version,person_id,person_version,event_id,state,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${guard?.clause??'1'}`).bind(id,a.id,a.version,c.version,person.id,person.version,eventId,dry?'dry_run':'awaiting_approval',ctx.now(),...(guard?.args??[])),...[1,2].map(n=>ctx.db.prepare("INSERT INTO auth_automation_steps(run_id,ordinal,state) SELECT ?,?,'intended' WHERE EXISTS(SELECT 1 FROM auth_automation_runs WHERE id=?)").bind(id,n,id))]);
 if(!results[0].meta.changes){if(eventId)return null;fail('automation_authority_changed',409);}
 return id;
}
// A native membership event only prepares work. It never grants consent to run.
export async function automationEvent(ctx,type,subject,data,eventId,occurredAt=ctx.now()) {
 if(type!=='group.member_added'||subject.type!=='person')return;
 if(!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status IN ('active','invited')",subject.id))return;
 for(const row of await all(ctx,'SELECT a.id FROM auth_automations a JOIN auth_automation_connections c ON c.id=a.id WHERE c.group_id=? AND c.revoked_at IS NULL AND a.updated_at<=?',data.group??'',occurredAt)) {
  const {a,c}=await loadAutomation(ctx,row.id);
  await createRun(ctx,a,c,subject.id,{eventId});
 }
}
async function finish(ctx,r,state,error=null) {
 await ctx.db.batch([
  ctx.db.prepare("UPDATE auth_automation_runs SET state=?,error=?,finished_at=?,lease_until=NULL WHERE id=? AND state IN ('running','approved')").bind(state,error,ctx.now(),r.id),
  ctx.db.prepare("UPDATE auth_automation_steps SET state=?,error=?,finished_at=? WHERE run_id=? AND state='running'").bind(state==='invalidated'?'failed':state,error,ctx.now(),r.id),
 ]);
}
export async function executeRun(ctx,id,request=null) {
 let r=await one(ctx,'SELECT * FROM auth_automation_runs WHERE id=?',id)||fail('automation_run_not_found',404);
 if(r.state!=='approved')fail('automation_exact_approval_required',409);
 let authority;
 try{authority=await executionAuthority(ctx,r,request);}catch(error){await finish(ctx,r,'invalidated','automation_authority_changed');throw error;}
 const {guard}=authority;
 const won=await run(ctx,`UPDATE auth_automation_runs SET state='running',lease_until=? WHERE id=? AND state='approved' AND ${guard.clause}`,ctx.now()+60000,id,...guard.args);
 if(!won.meta.changes)fail('automation_authority_changed',409);
 let effectStarted=false;
 try {
  const {c,config}=authority;
  const credentials=await unseal(ctx,'automation:'+c.id,c.sealed_credentials);
  // The credential and access token exist only in this call's server memory.
  await executionAuthority(ctx,r);
  const token=(await requestJson(ctx,c.token_url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:credentials.clientId,client_secret:credentials.clientSecret,scope:credentials.scope}).toString()})).value;
  if(typeof token.access_token!=='string'||token.access_token.length>4096||!token.access_token||/[\r\n]/.test(token.access_token)||String(token.token_type).toLowerCase()!=='bearer')fail('automation_token_invalid',502);
  let responseId;
  for(const ordinal of [1,2]) {
   const held=await executionAuthority(ctx,r);
   const url=new URL(config.paths[ordinal-1],c.origin).href;
   const body=JSON.stringify(ordinal===1?{personId:r.person_id}:{personId:r.person_id,responseId});
   const started=await run(ctx,`UPDATE auth_automation_steps SET state='running',started_at=? WHERE run_id=? AND ordinal=? AND state='intended' AND ${held.guard.clause}`,ctx.now(),id,ordinal,...held.guard.args);
   if(!started.meta.changes)fail('automation_authority_changed',409);
   effectStarted=true;
   const headers=await signedHeaders(credentials.signingKey,id,ordinal,url,body,ctx.now());
   headers.authorization='Bearer '+token.access_token;
   const result=await requestJson(ctx,url,{method:'POST',headers,body});
   if(ordinal===1) {
    responseId=result.value?.[config.responseField];
    if(typeof responseId!=='string'||!responseId||responseId.length>256||/[\x00-\x1f]/.test(responseId)||[token.access_token,credentials.clientSecret,credentials.signingKey,credentials.clientId].some(secret=>secret&&responseId.includes(secret)))fail('automation_response_invalid',502);
   }
   await run(ctx,"UPDATE auth_automation_steps SET state='completed',status=?,finished_at=? WHERE run_id=? AND ordinal=? AND state='running'",result.status,ctx.now(),id,ordinal);
   effectStarted=false;
  }
  await finish(ctx,r,'completed');
 } catch {
  // A transport error or refusal can occur after the peer applied an effect.
  // Never record raw provider errors, tokens, response bodies, or retry blindly.
  await finish(ctx,r,effectStarted?'uncertain':'failed',effectStarted?'remote_effect_unverified':'automation_execution_refused');
 }
 return one(ctx,'SELECT id,state,error FROM auth_automation_runs WHERE id=?',id);
}
export async function maintainAutomations(ctx) {
 const missed=await all(ctx,`SELECT e.id,e.subject,e.data,e.occurred_at FROM auth_events e WHERE e.type='group.member_added' AND EXISTS(SELECT 1 FROM oa_operators p WHERE p.id=json_extract(e.subject,'$.id') AND p.status IN ('active','invited')) AND EXISTS(SELECT 1 FROM auth_automations a JOIN auth_automation_connections c ON c.id=a.id WHERE c.revoked_at IS NULL AND c.group_id=json_extract(e.data,'$.group') AND a.updated_at<=e.occurred_at AND NOT EXISTS(SELECT 1 FROM auth_automation_runs r WHERE r.automation_id=a.id AND r.event_id=e.id)) ORDER BY e.seq LIMIT 100`);
 for(const e of missed)await automationEvent(ctx,'group.member_added',JSON.parse(e.subject),JSON.parse(e.data),e.id,e.occurred_at);
 for(const r of await all(ctx,"SELECT * FROM auth_automation_runs WHERE state='running' AND lease_until<=?",ctx.now()))await finish(ctx,r,'uncertain','interrupted_remote_effect_unverified');
 for(const r of await all(ctx,"SELECT id FROM auth_automation_runs WHERE state='approved' ORDER BY created_at LIMIT 10")) {
  try{await executeRun(ctx,r.id);}catch{/* Authority loss is retained as an invalidated run. */}
 }
}
export async function automationCandidates(ctx) {
 return all(ctx,"SELECT 'app_setup' AS kind,'automation:'||id AS source_id,person_id,created_at FROM auth_automation_runs WHERE state IN ('failed','uncertain','invalidated')");
}
export async function automationSource(ctx,ob) {
 if(ob.kind!=='app_setup'||!ob.source_id?.startsWith('automation:'))return null;
 const r=await one(ctx,'SELECT state,error FROM auth_automation_runs WHERE id=?',ob.source_id.slice(11));
 return r?{state:'open',action:'review_automation_remote_effect_before_new_approval',error:r.error}:{state:'cancelled'};
}
