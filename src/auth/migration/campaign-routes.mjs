import {all,one,run,random,requireSession,json,fail,auditDetail} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {configuredProvider,configurationHash,matchesConfiguredPin} from '../domain-policy.mjs';
import {CAMPAIGNS,campaignCurrent,campaignPeople} from './campaign-state.mjs';
import {syncObligations} from '../obligations/sources.mjs';

async function administrator(ctx,request,write=false) {
 const s=await requireSession(ctx,request,true);
 if(!['owner','admin'].includes(s.role))fail('administrator_required',403);
 if(write)requireLocalEmail(ctx,s);
 return s;
}
const csvCell=value=>{const raw=String(value??''),text=/^[=+\-@\t\r]/.test(raw)?"'"+raw:raw;return '"'+text.replaceAll('"','""')+'"';};
export async function campaignModel(ctx) {
 const rows=await all(ctx,'SELECT * FROM auth_campaigns ORDER BY created_at DESC,id');
 const campaigns=[];
 for(const row of rows) {
  const people=await campaignPeople(ctx,row),counts=Object.fromEntries(['passkey_ready','pending','overdue','exempt','unavailable'].map(state=>[state,people.filter(person=>person.state===state).length]));
  campaigns.push({...row,current:await campaignCurrent(ctx,row),remaining:people.filter(person=>!['passkey_ready','exempt'].includes(person.state)).length,secondsToCutover:Math.max(0,Math.ceil((row.cutover_at-ctx.now())/1000)),counts,people});
 }
 return {campaigns,campaignProviders:(ctx.upstreamProviders??[]).map(provider=>({id:provider.id,label:provider.label||provider.id,preset:provider.preset})),campaignManagers:await all(ctx,"SELECT id,email,display_name FROM oa_operators WHERE status='active' ORDER BY email")};
}
export async function campaignRead(ctx,request) {
 await administrator(ctx,request);
 const url=new URL(request.url);
 if(url.pathname.endsWith('/export.csv')) {
  const campaign=await one(ctx,'SELECT * FROM auth_campaigns WHERE id=?',url.searchParams.get('campaign')??'')||fail('campaign_not_found',404);
  const rows=(await campaignPeople(ctx,campaign)).filter(person=>!['passkey_ready','exempt'].includes(person.state));
  return new Response([['name','work_email','state','manager','factors','deadline_utc'],...rows.map(person=>[person.display_name,person.email,person.state,person.manager_email??'',person.factors.join(' '),new Date(campaign.deadline_at).toISOString()])].map(row=>row.map(csvCell).join(',')).join('\r\n')+'\r\n',{headers:{'content-type':'text/csv; charset=utf-8','content-disposition':'attachment; filename="campaign-stragglers.csv"','cache-control':'no-store','x-content-type-options':'nosniff'}});
 }
 return json(await campaignModel(ctx));
}
export async function campaignAction(ctx,request,path,data) {
 const s=await administrator(ctx,request,true),guard=authority(ctx,s,['owner','admin']);
 if(path===CAMPAIGNS+'/create') {
  if(data.confirm!==true)fail('campaign_confirmation_required');
  if(typeof data.name!=='string'||!data.name.trim()||data.name.length>100)fail('invalid_campaign');
  for(const field of ['startsAt','deadlineAt','cutoverAt'])if(!Number.isSafeInteger(data[field]))fail('invalid_campaign_window');
  if(data.startsAt<data.deadlineAt-180*86400000||data.startsAt>data.deadlineAt||data.deadlineAt>data.cutoverAt||data.cutoverAt<=ctx.now())fail('invalid_campaign_window');
  for(const field of ['employeeConsent','managerConsent','administratorConsent'])if(typeof data[field]!=='boolean')fail('campaign_explicit_consent_required');
  const provider=configuredProvider(ctx,data.providerId);
  if(!provider||!await matchesConfiguredPin(ctx,provider))fail('campaign_provider_unavailable',409);
  const batch=await one(ctx,'SELECT * FROM auth_import_batches WHERE id=? AND undone_at IS NULL',data.batchId)||fail('batch_unavailable',404);
  const source=provider.preset==='microsoft'?'microsoft':provider.preset==='okta'?'okta':null;
  if(source&&batch.source_system!==source)fail('campaign_source_mismatch');
  const selected=[data.rows??[]].flat().map(Number);
  if(!selected.length||selected.length>200||new Set(selected).size!==selected.length)fail('campaign_cohort_required');
  const rows=[];
  for(const idx of selected) {
   const row=await one(ctx,`SELECT r.*,p.version,p.role,p.status AS person_status FROM auth_import_rows r JOIN oa_operators p ON p.id=r.person_id WHERE r.batch_id=? AND r.idx=? AND r.status='admitted' AND COALESCE(r.disabled,0)=0 AND r.source_id IS NOT NULL AND r.source_id!='' AND p.email=r.email AND p.role='member' AND p.status IN ('active','invited') AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL)`,batch.id,idx);
   if(!row||rows.some(other=>other.source_id===row.source_id||other.person_id===row.person_id))fail('campaign_staged_member_required',409);
   if(provider.subjectEmails?.[row.source_id]!==row.email)fail('campaign_subject_association_required',409);
   let manager=null;
   if(data.managerId)manager=await one(ctx,"SELECT id FROM oa_operators WHERE id=? AND status='active' AND id!=?",data.managerId,row.person_id)||fail('campaign_manager_unavailable');
   if(data.managerConsent&&!manager)fail('campaign_manager_required');
   rows.push({...row,manager_id:manager?.id??null});
  }
  const id=random(),pin=await configurationHash(provider);
  const cohort=JSON.stringify(rows.map(row=>({idx:row.idx,personId:row.person_id,subject:row.source_id,email:row.email,version:row.version})));
  const check={clause:guard.clause+" AND (SELECT COUNT(*) FROM json_each(?) j JOIN auth_import_rows r ON r.batch_id=? AND r.idx=json_extract(j.value,'$.idx') JOIN auth_import_batches b ON b.id=r.batch_id JOIN oa_operators p ON p.id=r.person_id WHERE b.undone_at IS NULL AND r.person_id=json_extract(j.value,'$.personId') AND r.source_id=json_extract(j.value,'$.subject') AND r.email=json_extract(j.value,'$.email') AND r.status='admitted' AND COALESCE(r.disabled,0)=0 AND p.version=json_extract(j.value,'$.version') AND p.role='member' AND p.status IN ('active','invited') AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL))=?",args:[...guard.args,cohort,batch.id,rows.length]};
  const statements=[ctx.db.prepare(`INSERT INTO auth_campaigns(id,name,provider_id,configuration_hash,batch_id,starts_at,deadline_at,cutover_at,created_by,owner_version,created_at,employee_consent,manager_consent,administrator_consent) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE ${check.clause} AND NOT EXISTS(SELECT 1 FROM auth_campaigns WHERE provider_id=?)`).bind(id,data.name.trim(),provider.id,pin,batch.id,data.startsAt,data.deadlineAt,data.cutoverAt,s.person_id,s.person_version,ctx.now(),Number(data.employeeConsent),Number(data.managerConsent),Number(data.administratorConsent),...check.args,provider.id)];
  for(const row of rows)statements.push(ctx.db.prepare('INSERT INTO auth_campaign_people(campaign_id,person_id,source_subject,email,manager_id) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_campaigns WHERE id=?)').bind(id,row.person_id,row.source_id,row.email,row.manager_id,id));
  const result=await ctx.db.batch(statements);
  if(!result[0].meta.changes){await requireAuthority(ctx,s,guard);fail('campaign_registration_changed',409);}
  await auditDetail(ctx,s.person_id,'campaign_created',id,{cohort:rows.length,startsAt:data.startsAt,deadlineAt:data.deadlineAt,cutoverAt:data.cutoverAt,consent:{employee:data.employeeConsent,manager:data.managerConsent,administrator:data.administratorConsent}});
  await syncObligations(ctx);
  return json({id,cohort:rows.length},201);
 }
 const campaign=await one(ctx,'SELECT * FROM auth_campaigns WHERE id=?',data.campaignId)||fail('campaign_not_found',404);
 if(path===CAMPAIGNS+'/cancel') {
  const changed=await run(ctx,`UPDATE auth_campaigns SET cancelled_at=? WHERE id=? AND cancelled_at IS NULL AND ${guard.clause}`,ctx.now(),campaign.id,...guard.args);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('campaign_changed',409);}
  await auditDetail(ctx,s.person_id,'campaign_cancelled',campaign.id,{});await syncObligations(ctx);return json({ok:true});
 }
 if(path===CAMPAIGNS+'/exempt') {
  if(data.confirm!==true||typeof data.reason!=='string'||!data.reason.trim()||data.reason.length>300)fail('campaign_exemption_reason_required');
  const changed=await run(ctx,`UPDATE auth_campaign_people SET exempt_at=?,exemption_reason=? WHERE campaign_id=? AND person_id=? AND exempt_at IS NULL AND ${guard.clause}`,ctx.now(),data.reason.trim(),campaign.id,data.personId,...guard.args);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('campaign_person_unavailable',409);}
  await auditDetail(ctx,s.person_id,'campaign_person_exempted',campaign.id,{personId:data.personId,reason:data.reason.trim()});await syncObligations(ctx);return json({ok:true});
 }
 fail('not_found',404);
}
