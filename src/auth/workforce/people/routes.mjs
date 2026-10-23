import {invokeHooks} from '../../hooks/index.mjs';
// The workforce directory's doors: People and the admin API both land here, so
// every edit meets the same validation and audit. Reads need a passkey
// administrator; every write also needs this session's fresh local email proof,
// rechecked with its authority in the committing statements.
import {one,json,fail,requireSession,auditDetail} from '../../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../../local-email.mjs';
import {loadDirectory} from './load.mjs';
import {planEdits} from './plan.mjs';
import {applyPlan,onboardPerson} from './apply.mjs';
import {feedEdits} from './feed.mjs';
import {filterPeople,searchView,groupsView,attributesView} from './model.mjs';
import {setRule,changeOwner} from './rules.mjs';
import {CUSTOM_NAME,SOURCES} from './fields.mjs';

const WRITES=['/directory/onboard','/directory/apply','/directory/edit','/directory/source','/directory/resolve','/directory/attributes','/groups/rule','/groups/owners/add','/groups/owners/remove'];
export const isDirectoryAction=path=>path==='/directory/preview'||WRITES.includes(path);
export const DIRECTORY_READS=['/api/auth/directory','/api/auth/directory/groups'];

// Edits named one by one, or by a filter with one change for everyone it finds.
function expand(dir,data) {
 if(Array.isArray(data.edits))return data.edits;
 const filter=data.filter;
 if(!filter||typeof filter!=='object')fail('invalid_edits');
 return filterPeople(dir,{q:filter.q,state:filter.state,group:filter.group,conflicted:filter.conflicted,fields:filter.fields}).map(p=>({personId:p.id,source:data.source,set:data.set,state:data.state,email:undefined}));
}
const refused=(plan)=>json({error:'edit_refused',refusals:plan.entries.flatMap(e=>e.refusals.map(r=>`${e.email??e.personId}: ${r}`)),plan},409);

export async function directoryRead(ctx,request,path) {
 await requireSession(ctx,request,true);
 const dir=await loadDirectory(ctx),url=new URL(request.url),p=url.searchParams;
 if(path==='/api/auth/directory/groups')return json({groups:groupsView(dir)});
 const fields=Object.fromEntries([...p].filter(([k])=>k.startsWith('f.')).map(([k,v])=>[k.slice(2),v]));
 return json({...searchView(dir,{q:p.get('q'),state:p.get('state'),group:p.get('group'),conflicted:p.get('conflicts')==='1',fields,limit:p.get('limit'),offset:p.get('offset')}),attributes:attributesView(dir)});
}

export async function directoryAction(ctx,request,path,data,{notify,additionalGuard}) {
 const s=await requireSession(ctx,request,true);
 const dir=await loadDirectory(ctx);
 if(path==='/directory/preview'){const plan=await planEdits(ctx,dir,expand(dir,data),s.person_id);return json({plan});}
 requireLocalEmail(ctx,s);
 let guard=authority(ctx,s,['owner','admin']);
 if(additionalGuard)guard={clause:`(${guard.clause}) AND (${additionalGuard.clause})`,args:[...guard.args,...additionalGuard.args]};
 const run=async(edits,{bulk=false,digest}={})=>{
  const plan=await planEdits(ctx,dir,edits,s.person_id);
  if(digest!==undefined&&digest!==plan.digest)fail('preview_changed',409);
  if(!plan.ok)return {refusal:refused(plan)};
  return {plan,results:await applyPlan(ctx,s,guard,dir,plan,{bulk})};
 };
 if(path==='/directory/onboard') {
  // A form sends each value beside the name and email; the API may send them under `set`.
  const set={...data.set};for(const [key,value] of Object.entries(data))if(!['name','email','kind'].includes(key)&&dir.defs.has(key)&&value!=='')set[key]=value;
  const result=await onboardPerson(ctx,s,guard,dir,{...data,set},notify);
  if(result.refused)return json({error:'onboard_refused',refusals:result.refused,...(result.personId?{personId:result.personId}:{})},409);
  return json({id:result.personId,plan:result.plan},201);
 }
 if(path==='/directory/apply'){
  if(typeof data.digest!=='string')fail('preview_required');
  const done=await run(expand(dir,data),{bulk:true,digest:data.digest});
  return done.refusal??json({ok:true,results:done.results,summary:done.plan.summary});
 }
 if(path==='/directory/edit'){
  const done=await run([{personId:data.personId,source:data.source,set:data.set,state:data.state,email:data.email}]);
  return done.refusal??json({ok:true,entry:done.plan.entries[0],changed:done.results[0].changed});
 }
 if(path==='/directory/source') {
  let records=data.records;
  if(!feedEdits(dir,data.source,records))fail('invalid_records');
  if(data.preview!==true){
   records=[];
   for(const record of data.records){const extension=await invokeHooks(ctx,'user_import',{sourceId:record.sourceId,email:record.email,name:record.fields?.name});records.push({...record,fields:{...record.fields,...(extension.profile?.name?{name:extension.profile.name}:{})}});}
  }
  guard=authority(ctx,s,['owner','admin']);
  const fed=feedEdits(dir,data.source,records);if(!fed)fail('invalid_records');
  const plan=fed.edits.length?await planEdits(ctx,dir,fed.edits,s.person_id):{entries:[],ok:true,summary:{people:0},digest:null};
  const ok={...plan,entries:plan.entries.filter(e=>!e.refusals.length)};
  if(data.preview===true)return json({preview:true,outcomes:fed.outcomes.map(({edit,...o})=>o),plan});
  const results=ok.entries.length?await applyPlan(ctx,s,guard,dir,ok,{bulk:true}):[];
  const outcomes=fed.outcomes.map(({edit,...o})=>{const e=edit===undefined?null:plan.entries[edit];return e?.refusals.length?{...o,outcome:'refused',refusals:e.refusals}:o;});
  return json({ok:true,outcomes,applied:results.filter(r=>r.changed).length,conflicts:ok.entries.flatMap(e=>e.conflicts.map(c=>({personId:e.personId,...c})))});
 }
 if(path==='/directory/resolve') {
  // Accept a source's value: the values ranked above it stop overriding it.
  const keep=String(data.keep||''),field=String(data.field||''),person=dir.people.get(String(data.personId||''))??fail('person_not_found',404);
  if(!['hr','directory'].includes(keep)||!dir.defs.has(field))fail('invalid_resolution');
  const above=SOURCES.slice(0,SOURCES.indexOf(keep));
  if(!person.fields.get(field)?.some(v=>v.source===keep)||!person.fields.get(field).some(v=>above.includes(v.source)))fail('nothing_to_resolve',409);
  for(const source of above) {
   if(!(await loadDirectory(ctx)).people.get(person.id).fields.get(field)?.some(v=>v.source===source))continue;
   const fresh=await loadDirectory(ctx),plan=await planEdits(ctx,fresh,[{personId:person.id,source,set:{[field]:null}}],s.person_id);
   await applyPlan(ctx,s,guard,fresh,plan);
  }
  await auditDetail(ctx,s.person_id,'directory_conflict_resolved',person.id,{field,keep});
  return json({ok:true});
 }
 if(path==='/directory/attributes') {
  const name=String(data.name||'').trim().toLowerCase(),label=String(data.label||'').trim().slice(0,80),type=String(data.type||'text'),visibility=data.visibility==='admin'?'admin':'employee';
  if(!CUSTOM_NAME.test(name)||!label||!['text','number','boolean','date','choice'].includes(type))fail('invalid_attribute');
  const choices=type==='choice'?(Array.isArray(data.choices)?data.choices.map(c=>String(c).trim().toLowerCase()).filter(Boolean).slice(0,50):[]):null;
  if(type==='choice'&&!choices.length)fail('invalid_attribute');
  const held=await one(ctx,'SELECT type,choices FROM auth_attribute_defs WHERE name=?',name);
  if(held&&(held.type!==type||(held.choices??null)!==(choices?JSON.stringify(choices):null)))fail('attribute_type_fixed',409);
  const done=await ctx.db.prepare(`INSERT INTO auth_attribute_defs(name,label,type,choices,visibility,employee_editable,created_by,created_at) SELECT ?,?,?,?,?,?,?,? WHERE ${guard.clause} ON CONFLICT(name) DO UPDATE SET label=excluded.label,visibility=excluded.visibility,employee_editable=excluded.employee_editable`).bind(name,label,type,choices?JSON.stringify(choices):null,visibility,data.employeeEditable===true?1:0,s.person_id,ctx.now(),...guard.args).run();
  if(!done.meta.changes){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
  await auditDetail(ctx,s.person_id,'attribute_defined',name,{label,type,visibility,employeeEditable:data.employeeEditable===true});
  return json({key:'x.'+name},201);
 }
 if(path==='/groups/rule')return json(await setRule(ctx,s,guard,dir,data));
 return json(await changeOwner(ctx,s,guard,dir,data,path==='/groups/owners/add'));
}
