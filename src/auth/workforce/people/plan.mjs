// What a set of directory edits would do, without doing it: the field changes
// by source, state changes, email changes, groups gained and lost, apps gained
// and lost, and what each refuses. Preview and apply share this, so a bulk edit
// and a single edit meet the same validation. The digest names the exact plan.
import {AuthError,email as normalizeEmail,hash} from '../../core.mjs';
import {FEED_SOURCES,normalize,written,effective,conflicts,winning} from './fields.mjs';
import {ruleGroupsFor,because} from './groups.mjs';
import {appsFor,groupIdsOf} from './load.mjs';

const SOURCES=['manual',...FEED_SOURCES];
const STATES=['active','suspended','terminated'];
const MAX_EDITS=500;

async function planFields(ctx,dir,person,source,set) {
 let fields=person.fields;const writes=[],refusals=[];
 for(const [key,raw] of Object.entries(set??{})) {
  const spec=dir.defs.get(key);
  if(!spec){refusals.push('unknown_field:'+key);continue;}
  let value=null;
  if(raw!==null)try{value=await normalize(ctx,spec,raw);}catch(error){if(!(error instanceof AuthError))throw error;refusals.push(`${error.message}:${key}`);continue;}
  if(key==='manager'&&value){
   if(value===person.id){refusals.push('manager_cycle:manager');continue;}
   const seen=new Set([person.id]);let at=value;
   while(at&&!seen.has(at)){seen.add(at);at=winning(dir.people.get(at)?.fields,'manager')?.value;}
   if(at===person.id){refusals.push('manager_cycle:manager');continue;}
  }
  const held=fields.get(key)?.find(v=>v.source===source)?.value??null;
  if(held===value)continue;
  fields=written(fields,key,source,value);writes.push({field:key,source,value});
 }
 return {fields,writes,refusals};
}
function planEmail(ctx,dir,person,actorId,raw) {
 const address=normalizeEmail(raw);
 if(!address||(!ctx.local&&/\.(localhost|test|invalid)$/.test(address)))return {refusal:'invalid_email'};
 if(address===person.email)return {};
 const other=dir.byEmail.get(address);
 if(other)return {refusal:other.state==='terminated'||other.state==='suspended'?'email_belongs_to_former_worker':'email_in_use'};
 if(person.role==='owner')return {refusal:'owner_email_fixed'};
 if(person.id===actorId)return {refusal:'cannot_change_own_email'};
 return {change:{from:person.email,to:address}};
}
function planState(ctx,dir,person,actorId,to) {
 if(!STATES.includes(to))return {refusal:'invalid_state'};
 const from=person.state;
 if(to===from||(from==='invited'&&to==='active'))return {};
 if(person.role==='owner')return {refusal:'owner_state_fixed'};
 if(person.id===actorId)return {refusal:'cannot_change_own_state'};
 if(from==='invited')return {refusal:'invitation_not_accepted'};
 if(to==='suspended'&&from!=='active')return {refusal:'person_not_active'};
 if(to==='active'&&dir.cancelled.has(person.id))return {refusal:'invitation_was_removed'};
 return {change:{from,to,kind:to==='active'?(from==='terminated'?'rehire':'restore'):to==='terminated'?'terminate':'suspend'}};
}

// One edit: {personId, source?, set?, email?, state?, bind?}. The entry is the preview.
export async function planEdit(ctx,dir,edit,actorId) {
 const person=dir.people.get(String(edit.personId||''));
 if(!person)return {personId:String(edit.personId||''),refusals:['person_not_found']};
 const source=edit.source??'manual',refusals=[];
 if(!SOURCES.includes(source))refusals.push('invalid_source');
 const set=await planFields(ctx,dir,person,SOURCES.includes(source)?source:'manual',edit.set);refusals.push(...set.refusals);
 const mail=edit.email!==undefined?planEmail(ctx,dir,person,actorId,edit.email):{};if(mail.refusal)refusals.push(mail.refusal);
 const state=edit.state!==undefined?planState(ctx,dir,person,actorId,edit.state):{};if(state.refusal)refusals.push(state.refusal);
 const bind=edit.bind&&FEED_SOURCES.includes(edit.bind.source)?edit.bind:null;
 if(bind){
  const owner=dir.sources.get(`${bind.source}:${bind.sourceId}`),held=dir.sourceIds.get(`${bind.source}:${person.id}`);
  if(owner&&owner!==person.id)refusals.push('source_id_in_use');
  else if(held&&held!==bind.sourceId)refusals.push('source_id_immutable');
 }
 const before=effective(person.fields,dir.defs),after=effective(set.fields,dir.defs);
 const beforeGroups=groupIdsOf(dir,person.id),afterGroups=new Set(beforeGroups),groups={added:[],removed:[]};
 const wanted=new Set(ruleGroupsFor(dir,person.id,after).map(g=>g.id));
 for(const g of dir.ruleGroups) {
  const row=dir.members.get(g.id)?.get(person.id);
  if(wanted.has(g.id)&&!row){afterGroups.add(g.id);groups.added.push({id:g.id,name:g.name,why:because(g.rule,after)});}
  else if(!wanted.has(g.id)&&row?.source==='rule'){afterGroups.delete(g.id);groups.removed.push({id:g.id,name:g.name});}
 }
 const beforeActive=person.status==='active',afterActive=state.change?state.change.to==='active':beforeActive;
 const was=beforeActive?appsFor(dir,person.id,beforeGroups):new Map(),now=afterActive?appsFor(dir,person.id,afterGroups):new Map();
 const apps={gained:[],lost:[],roleChanged:[]};
 for(const [id,a] of now)if(!was.has(id))apps.gained.push({appId:id,app:a.app,role:a.role??null});else if((was.get(id).role??null)!==(a.role??null))apps.roleChanged.push({appId:id,app:a.app,from:was.get(id).role??null,to:a.role??null});
 for(const [id,a] of was)if(!now.has(id))apps.lost.push({appId:id,app:a.app});
 const changes=Object.keys({...before,...after}).filter(k=>before[k]!==after[k]).sort().map(field=>({field,from:before[field]??null,to:after[field]??null,source:winning(set.fields,field)?.source??null}));
 const nameNow=after.name??person.name;
 const priorConflicts=new Set(conflicts(person.fields).map(c=>c.field));
 return {personId:person.id,email:person.email,name:person.name,source,state:state.change??null,emailChange:mail.change??null,
  nameChange:nameNow!==person.name?{from:person.name,to:nameNow}:null,writes:set.writes,changes,bind,
  conflicts:conflicts(set.fields).map(c=>({...c,introduced:!priorConflicts.has(c.field)})),groups,apps,refusals};
}

// Digest of the exact plan: the people, their versions and values it was read against, and every effect.
export async function planEdits(ctx,dir,edits,actorId) {
 if(!Array.isArray(edits)||!edits.length||edits.length>MAX_EDITS)throw new AuthError('invalid_edits');
 const entries=[];
 for(const edit of edits)entries.push(await planEdit(ctx,dir,edit,actorId));
 const seen=new Set();
 for(const e of entries){if(seen.has(e.personId+':'+e.source))e.refusals.push('duplicate_edit');seen.add(e.personId+':'+e.source);}
 const basis=entries.map(e=>({...e,version:dir.people.get(e.personId)?.version??null,held:JSON.stringify([...(dir.people.get(e.personId)?.fields??[])])}));
 return {entries,ok:entries.every(e=>!e.refusals.length),summary:{people:entries.length,refused:entries.filter(e=>e.refusals.length).length,
  changed:entries.filter(e=>e.writes?.length||e.state||e.emailChange).length,groupsGained:entries.reduce((n,e)=>n+(e.groups?.added.length??0),0),groupsLost:entries.reduce((n,e)=>n+(e.groups?.removed.length??0),0),
  destructive:entries.filter(e=>e.state&&e.state.to!=='active').length},digest:await hash(JSON.stringify(basis))};
}
