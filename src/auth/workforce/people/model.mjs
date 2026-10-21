// What administrators read of the directory: people with where each value came
// from, the conflicts between sources, and each group's members with the reason
// each is there.
import {conflicts} from './fields.mjs';
import {loadDirectory} from './load.mjs';
import {matches,because} from './groups.mjs';
import {appsFor,groupIdsOf} from './load.mjs';

export function personView(dir,p) {
 const values=dir.values(p),groupIds=groupIdsOf(dir,p.id);
 const fields={};
 for(const [field,list] of p.fields)fields[field]={value:list[0].value,source:list[0].source,also:list.slice(1)};
 for(const [key,spec] of dir.defs)if(spec.default!==undefined&&!fields[key])fields[key]={value:spec.default,source:'default',also:[]};
 return {id:p.id,email:p.email,name:p.name,role:p.role,status:p.status,state:p.state,terminatedAt:p.terminatedAt??null,
  sourceIds:Object.fromEntries(['hr','directory'].flatMap(s=>dir.sourceIds.has(`${s}:${p.id}`)?[[s,dir.sourceIds.get(`${s}:${p.id}`)]]:[])),
  fields,conflicts:conflicts(p.fields),
  groups:dir.groups.filter(g=>groupIds.has(g.id)).map(g=>{const row=dir.members.get(g.id).get(p.id);return {id:g.id,name:g.name,via:row.source,...(row.source==='rule'?{why:because(g.rule,values)}:{})};}),
  apps:p.status==='active'?[...appsFor(dir,p.id,groupIds).values()]:[]};
}

// Search and filter, as People and the API use them: text on name and email, state, group, any field's exact value.
export function filterPeople(dir,{q,state,group,conflicted,fields={}}={}) {
 const text=String(q??'').trim().toLowerCase();
 return [...dir.people.values()].filter(p=>{
  if(text&&!`${p.name} ${p.email}`.toLowerCase().includes(text))return false;
  if(state&&p.state!==state)return false;
  if(group&&!dir.members.get(group)?.has(p.id))return false;
  if(conflicted&&!conflicts(p.fields).length)return false;
  const values=dir.values(p);
  return Object.entries(fields).every(([k,v])=>String(values[k]??'').toLowerCase()===String(v).toLowerCase());
 });
}
export function searchView(dir,params) {
 const found=filterPeople(dir,params),limit=Math.min(Math.max(Number(params.limit)||100,1),200),offset=Math.max(Number(params.offset)||0,0);
 return {total:found.length,people:found.slice(offset,offset+limit).map(p=>personView(dir,p))};
}
export const attributesView=dir=>[...dir.defs.values()].map(({key,label,type,choices,visibility,employeeEditable,standard})=>({key,label,type,choices:choices??null,visibility,employeeEditable,standard}));

export function groupsView(dir) {
 const email=id=>dir.people.get(id)?.email??null;
 return dir.groups.map(g=>{
  const rows=[...dir.members.get(g.id).values()];
  return {id:g.id,name:g.name,rule:g.rule,
   owners:dir.owners.filter(o=>o.group_id===g.id).map(o=>({id:o.person_id,email:email(o.person_id)})),
   apps:dir.assignments.filter(a=>a.principal_type==='group'&&a.principal_id===g.id).map(a=>({appId:a.app_id,app:a.app,role:a.role})),
   members:rows.map(m=>{const p=dir.people.get(m.person_id),values=p&&dir.values(p);return {id:m.person_id,email:p?.email??null,via:m.source,addedBy:email(m.added_by),addedAt:m.added_at,
    ...(g.rule?{matchesRule:matches(g.rule,values),...(matches(g.rule,values)?{why:because(g.rule,values)}:{})}:{})};}),
   excluded:[...dir.exclusions.values()].filter(x=>x.group_id===g.id).map(x=>({id:x.person_id,email:email(x.person_id),reason:x.reason,by:email(x.set_by),at:x.set_at}))};
 });
}
// What the People page renders.
export async function directoryModel(ctx) {
 const dir=await loadDirectory(ctx);
 return {people:[...dir.people.values()].map(p=>personView(dir,p)),groups:groupsView(dir),attributes:attributesView(dir)};
}
