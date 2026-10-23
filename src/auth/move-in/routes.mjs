import {invokeHooks} from '../hooks/index.mjs';
// Move-in administration: stage a directory export, admit reviewed rows as
// ordinary invitations, send those invitations, and undo what is still untouched.
// Every handler authorizes its own request; every write carries the session's
// authority clause, so a lapsed proof or revoked session commits nothing.
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {random,hash,one,all,run,requireSession,json,fail,auditDetail} from '../core.mjs';
import {sendInvitation} from '../admin.mjs';
import {requireAccountRank} from '../ranks.mjs';
import {parseExport,MoveInError,MAX_FILE_BYTES} from './parse.mjs';
import {classify,stagedShape} from './review.mjs';

const ADMIN=['owner','admin'];
async function administrator(ctx,request) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 return {s,guard:authority(ctx,s,ADMIN)};
}
const openBatch=async(ctx,id)=>await one(ctx,'SELECT * FROM auth_import_batches WHERE id=? AND undone_at IS NULL',String(id||''))||fail('batch_unavailable',404);
const people=ctx=>all(ctx,'SELECT id,email,role FROM oa_operators');

// The upload carries the file text, so it has its own larger body limit.
export async function stage(ctx,request) {
 const {s,guard}=await administrator(ctx,request);
 if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
 if(!(request.headers.get('content-type')||'').startsWith('application/json'))fail('unsupported_content_type',415);
 const limit=MAX_FILE_BYTES*6+4096;
 if(Number(request.headers.get('content-length')||0)>limit)fail('file_too_large',413);
 const body=await request.text();if(body.length>limit)fail('file_too_large',413);
 let data;try{data=JSON.parse(body);}catch{fail('invalid_json');}
 if(!data||typeof data!=='object')fail('invalid_json');
 let parsed;
 try {parsed=parseExport({fileName:data.fileName,text:data.text,exportDate:data.exportDate});}
 catch(error) {if(error instanceof MoveInError)return json({error:error.code,message:error.message},error.code==='file_too_large'?413:400);throw error;}
 const fileHash=await hash(data.text);
 // The same file staged again adds nothing while its batch is open; after an
 // undo it starts a new batch, stored as hash#batch (see migration 0015).
 const open=(id='')=>one(ctx,'SELECT id FROM auth_import_batches WHERE substr(file_hash,1,43)=? AND undone_at IS NULL AND id!=?',fileHash,id);
 const earlier=await open();
 if(earlier)return json({batchId:earlier.id,duplicate:true});
 const id=random(),now=ctx.now(),rows=classify(ctx,parsed.rows,await people(ctx));
 const stored=await one(ctx,'SELECT 1 FROM auth_import_batches WHERE file_hash=?',fileHash)?`${fileHash}#${id}`:fileHash;
 const statements=[ctx.db.prepare(`INSERT INTO auth_import_batches(id,source_system,format,file_name,file_hash,export_date,row_count,created_by,created_at) SELECT ?,?,?,?,?,?,?,?,? WHERE ${guard.clause} ON CONFLICT DO NOTHING`).bind(id,parsed.sourceSystem,parsed.format,parsed.fileName,stored,parsed.exportDate,rows.length,s.person_id,now,...guard.args)];
 for(let start=0;start<rows.length;start+=250) {
  const chunk=rows.slice(start,start+250).map((r,i)=>({i:start+i,s:r.sourceId,e:r.email,n:r.displayName,d:r.disabled===null?null:r.disabled?1:0,g:JSON.stringify(r.groups),r:JSON.stringify(r.reasons)}));
  statements.push(ctx.db.prepare("INSERT INTO auth_import_rows(batch_id,idx,source_id,email,display_name,disabled,groups,status,reasons) SELECT ?,json_extract(value,'$.i'),json_extract(value,'$.s'),json_extract(value,'$.e'),json_extract(value,'$.n'),json_extract(value,'$.d'),json_extract(value,'$.g'),'staged',json_extract(value,'$.r') FROM json_each(?) WHERE EXISTS(SELECT 1 FROM auth_import_batches WHERE id=?)").bind(id,JSON.stringify(chunk),id));
 }
 for(const [index,row] of rows.entries())if(row.profileHistory?.length)statements.push(ctx.db.prepare('INSERT INTO auth_import_history(batch_id,idx,email,history) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM auth_import_batches WHERE id=?)').bind(id,index,row.email,JSON.stringify(row.profileHistory),id));
 statements.push(ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'move_in_staged',?,? WHERE EXISTS(SELECT 1 FROM auth_import_batches WHERE id=?)").bind(s.person_id,id,now,id));
 await ctx.db.batch(statements);
 if(!await one(ctx,'SELECT id FROM auth_import_batches WHERE id=?',id)) {
  const raced=await open(id);
  if(raced)return json({batchId:raced.id,duplicate:true});
  await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);
 }
 return json({batchId:id,rows:rows.length,source:parsed.sourceSystem},201);
}

// Admission is the People page invitation and nothing more: an invited member,
// no proof, no password, factor, role, group permission, session or mail.
async function admit(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),batch=await openBatch(ctx,data.batchId);
 const wanted=new Set([data.rows??[]].flat().map(Number));
 const rows=classify(ctx,(await all(ctx,'SELECT * FROM auth_import_rows WHERE batch_id=? ORDER BY idx',batch.id)).map(stagedShape),await people(ctx));
 const admitted=[],skipped=[],taken=new Set();
 for(const row of rows) {
  if(!wanted.has(row.idx)||row.status!=='staged')continue;
  if(!row.admittable||taken.has(row.email)){skipped.push({email:row.email,reasons:row.admittable?['duplicate_in_file']:row.reasons});continue;}
  const extension=await invokeHooks(ctx,'user_import',{sourceId:row.sourceId??String(row.idx),email:row.email,name:row.displayName||row.email});
  const liveGuard=authority(ctx,s,['owner','admin']);
  const id=random(),now=ctx.now(),created=`EXISTS(SELECT 1 FROM oa_operators WHERE id=?)`;
  const statements=[
   ctx.db.prepare(`INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE ${liveGuard.clause} ON CONFLICT(email) DO NOTHING`).bind(id,row.email,extension.profile?.name??row.displayName??row.email,now,...liveGuard.args),
   ctx.db.prepare(`UPDATE auth_import_rows SET status='admitted',person_id=?,admitted_at=? WHERE batch_id=? AND idx=? AND status='staged' AND ${created}`).bind(id,now,batch.id,row.idx,id),
  ];
  if(['auth0','google','custom'].includes(batch.source_system)&&row.sourceId)statements.push(ctx.db.prepare(`INSERT OR IGNORE INTO auth_former_subjects(source_system,subject,person_id,batch_id,created_at) SELECT ?,?,?,?,? WHERE ${created}`).bind(batch.source_system,row.sourceId,id,batch.id,now,id));
  statements.push(ctx.db.prepare(`UPDATE auth_import_history SET person_id=? WHERE batch_id=? AND idx=? AND ${created}`).bind(id,batch.id,row.idx,id));
  const [inserted]=await ctx.db.batch(statements);
  if(inserted.meta.changes){admitted.push(row.email);taken.add(row.email);continue;}
  await requireAuthority(ctx,s,liveGuard);skipped.push({email:row.email,reasons:['existing_person']});
 }
 if(admitted.length)await auditDetail(ctx,s.person_id,'move_in_admitted',batch.id,{admitted,skipped});
 return json({admitted:admitted.length,skipped});
}

// Mail goes only to people this batch admitted who are still unaccepted invitations.
async function invite(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),batch=await openBatch(ctx,data.batchId);
 const rows=await all(ctx,"SELECT r.idx,p.email FROM auth_import_rows r JOIN oa_operators p ON p.id=r.person_id WHERE r.batch_id=? AND r.status='admitted' AND r.invited_at IS NULL AND p.status='invited' ORDER BY r.idx",batch.id);
 const invited=[],failed=[];
 for(const row of rows) {
  const marked=await run(ctx,`UPDATE auth_import_rows SET invited_at=? WHERE batch_id=? AND idx=? AND invited_at IS NULL AND ${guard.clause}`,ctx.now(),batch.id,row.idx,...guard.args);
  if(!marked.meta.changes){await requireAuthority(ctx,s,guard);continue;}
  try {await sendInvitation(ctx,row.email);invited.push(row.email);}
  catch {await run(ctx,'UPDATE auth_import_rows SET invited_at=NULL WHERE batch_id=? AND idx=?',batch.id,row.idx);failed.push(row.email);}
 }
 if(invited.length||failed.length)await auditDetail(ctx,s.person_id,'move_in_invitations_sent',batch.id,{invited,failed});
 return json({invited:invited.length,failed});
}

// A person is safe to remove only while nothing has happened to them since admission.
function safe(row) {
 const id=row.person_id,none=(table,column='person_id')=>`NOT EXISTS(SELECT 1 FROM ${table} WHERE ${column}=?)`;
 const tables=[['auth_emails'],['auth_sessions'],['oa_sessions','operator_id'],['oa_tokens','operator_id'],['oa_external_identities','operator_id'],['auth_upstream_proofs'],['auth_passkeys'],['auth_recoveries'],['auth_grants'],['auth_codes'],['auth_subjects']];
 return {clause:[`EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND status='invited' AND role='member')`,...tables.map(([t,c])=>none(t,c)),'NOT EXISTS(SELECT 1 FROM auth_activity WHERE actor_id=? OR subject_id=? OR (subject_id=? AND created_at>=?))'].join(' AND '),
  args:[id,...tables.map(()=>id),id,id,row.email,row.admitted_at]};
}
async function keptReasons(ctx,row) {
 const person=await one(ctx,'SELECT status,role FROM oa_operators WHERE id=?',row.person_id);
 if(!person)return ['removed_elsewhere'];
 const any=async(...queries)=>{for(const [table,column='person_id'] of queries)if(await one(ctx,`SELECT 1 FROM ${table} WHERE ${column}=?`,row.person_id))return true;return false;};
 const reasons=[];
 if(await any(['auth_emails'],['auth_sessions'],['oa_sessions','operator_id'],['auth_upstream_proofs'],['oa_external_identities','operator_id']))reasons.push('signed_in');
 if(await any(['auth_passkeys']))reasons.push('passkey');
 if(await any(['auth_grants'],['auth_codes'],['auth_subjects']))reasons.push('app_grant');
 if(person.status!=='invited'||person.role!=='member')reasons.push('status_changed');
 if(await any(['auth_recoveries'],['oa_tokens','operator_id'])||await one(ctx,'SELECT 1 FROM auth_activity WHERE actor_id=? OR subject_id=? OR (subject_id=? AND created_at>=?)',row.person_id,row.person_id,row.email,row.admitted_at))reasons.push('later_activity');
 return reasons.length?reasons:['changed_during_undo'];
}
async function undo(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),batch=await openBatch(ctx,data.batchId);
 const rows=await all(ctx,"SELECT r.idx,r.person_id,r.admitted_at,p.email FROM auth_import_rows r JOIN oa_operators p ON p.id=r.person_id WHERE r.batch_id=? AND r.status='admitted' ORDER BY r.idx",batch.id);
 const removed=[],kept=[];
 for(const row of rows) {
  // One transaction: each statement rechecks the same conditions and authority.
  const check=safe(row),when=(sql,...args)=>ctx.db.prepare(`${sql} AND ${check.clause} AND ${guard.clause}`).bind(...args,...check.args,...guard.args);
  const results=await ctx.db.batch([
   when('DELETE FROM auth_former_subjects WHERE person_id=?',row.person_id),
   when('DELETE FROM auth_challenges WHERE person_id=?',row.person_id),
   when("UPDATE auth_import_rows SET status='undone',person_id=NULL WHERE batch_id=? AND idx=?",batch.id,row.idx),
   when('DELETE FROM oa_operators WHERE id=?',row.person_id),
  ]);
  if(results[3].meta.changes){removed.push(row.email);continue;}
  await requireAuthority(ctx,s,guard);kept.push({email:row.email,reasons:await keptReasons(ctx,row)});
 }
 const report={removed,kept};
 const closed=await run(ctx,`UPDATE auth_import_batches SET undone_at=?,undo_report=? WHERE id=? AND undone_at IS NULL AND ${guard.clause}`,ctx.now(),JSON.stringify(report),batch.id,...guard.args);
 if(!closed.meta.changes)await requireAuthority(ctx,s,guard);
 await auditDetail(ctx,s.person_id,'move_in_undone',batch.id,report);
 return json(report);
}

export async function moveInAction(ctx,request,path,data) {
 if(path==='/move-in/admit')return admit(ctx,request,data);
 if(path==='/move-in/invite')return invite(ctx,request,data);
 if(path==='/move-in/undo')return undo(ctx,request,data);
 fail('not_found',404);
}

// Old Auth0 subject to Auth email, for app owners to rebind deliberately.
const cell=value=>{const text=String(value??'');const safe=/^[=+\-@\t\r]/.test(text)?`'${text}`:text;return /[",\r\n]/.test(safe)?`"${safe.replace(/"/g,'""')}"`:safe;};
export async function formerSubjects(ctx,request) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 let guard=authority(ctx,s,ADMIN);
 const batch=await one(ctx,'SELECT * FROM auth_import_batches WHERE id=?',new URL(request.url).searchParams.get('batch')||'')||fail('batch_unavailable',404);
 const rows=await all(ctx,'SELECT f.person_id,f.subject,p.email,p.status FROM auth_former_subjects f JOIN oa_operators p ON p.id=f.person_id WHERE f.batch_id=? ORDER BY p.email',batch.id);
 for(const row of rows)guard=await requireAccountRank(ctx,s,row.person_id,guard);
 await requireAuthority(ctx,s,guard);
 const csv=[['former_subject','auth_email','auth_status','source','export_date'],...rows.map(r=>[r.subject,r.email,r.status,batch.source_system,batch.export_date])].map(r=>r.map(cell).join(',')).join('\r\n')+'\r\n';
 return new Response(csv,{headers:{'content-type':'text/csv; charset=utf-8','content-disposition':`attachment; filename="former-subjects-${batch.export_date}.csv"`,'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'}});
}

export async function moveInModel(ctx,request) {
 const batches=await all(ctx,"SELECT b.id,b.source_system,b.format,b.file_name,b.export_date,b.row_count,b.created_at,b.undone_at,p.email AS created_by_email,(SELECT count(*) FROM auth_import_rows r WHERE r.batch_id=b.id AND r.status='admitted') AS admitted FROM auth_import_batches b LEFT JOIN oa_operators p ON p.id=b.created_by ORDER BY b.created_at DESC");
 const id=new URL(request.url).searchParams.get('batch');
 const batch=id?await one(ctx,'SELECT * FROM auth_import_batches WHERE id=?',id):null;
 if(!batch)return {moveIn:{batches,batch:null,rows:[]}};
 const rows=classify(ctx,(await all(ctx,'SELECT * FROM auth_import_rows WHERE batch_id=? ORDER BY idx',batch.id)).map(stagedShape),await people(ctx));
 const histories=await all(ctx,'SELECT idx,history FROM auth_import_history WHERE batch_id=?',batch.id);
 for(const row of rows){const history=histories.find(item=>item.idx===row.idx);if(history)row.profileHistory=JSON.parse(history.history);}
 const subjects=await one(ctx,'SELECT count(*) AS n FROM auth_former_subjects WHERE batch_id=?',batch.id);
 return {moveIn:{batches,batch:{id:batch.id,source_system:batch.source_system,format:batch.format,file_name:batch.file_name,export_date:batch.export_date,created_at:batch.created_at,undone_at:batch.undone_at,undo_report:batch.undo_report?JSON.parse(batch.undo_report):null,former_subjects:subjects.n},rows}};
}
