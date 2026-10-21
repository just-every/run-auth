// Directory fields: a typed catalogue (standard and administrator-defined), one
// value per source, the effective value by source precedence, and the
// conflicts where sources disagree. Nothing here merges people by email.
import {one,all,fail} from '../../core.mjs';

// Highest precedence first: an administrator's override, then the HR system, the
// directory feed, and last the employee's own entry.
export const SOURCES=['manual','hr','directory','self'];
export const FEED_SOURCES=['hr','directory'];
const OWNING=['manual','hr','directory'];
const text=max=>({type:'text',max});
export const STANDARD={
 name:{label:'Name',...text(160),employeeEditable:true},
 kind:{label:'Worker type',type:'choice',choices:['employee','contractor','service'],default:'employee'},
 employment_type:{label:'Employment',type:'choice',choices:['w2','1099','other']},
 title:{label:'Job title',...text(120)},
 department:{label:'Department',...text(120)},
 location:{label:'Location',...text(120)},
 manager:{label:'Manager',type:'person'},
 start_date:{label:'Start date',type:'date'},
 end_date:{label:'End date',type:'date'},
};
export const CUSTOM_NAME=/^[a-z][a-z0-9_]{0,31}$/;

export async function definitions(ctx) {
 const defs=new Map(Object.entries(STANDARD).map(([key,spec])=>[key,{key,standard:true,visibility:'employee',employeeEditable:false,...spec}]));
 for(const row of await all(ctx,'SELECT * FROM auth_attribute_defs ORDER BY name'))defs.set('x.'+row.name,{key:'x.'+row.name,label:row.label,type:row.type,choices:row.choices?JSON.parse(row.choices):undefined,visibility:row.visibility,employeeEditable:Boolean(row.employee_editable),standard:false});
 return defs;
}
export const specOf=(defs,key)=>defs.get(key)??fail('unknown_field');

const validDate=value=>/^\d{4}-\d{2}-\d{2}$/.test(value)&&new Date(value+'T00:00:00Z').toISOString().startsWith(value);
// The stored text for a value of the field's type, or the refusal.
export async function normalize(ctx,spec,raw) {
 const value=typeof raw==='string'?raw.trim():typeof raw==='number'||typeof raw==='boolean'?String(raw):'';
 if(!value)fail('invalid_value');
 if(spec.type==='text'){if(value.length>(spec.max??200))fail('invalid_value');return value;}
 if(spec.type==='number'){if(!/^-?\d{1,15}(?:\.\d{1,6})?$/.test(value))fail('invalid_value');return value;}
 if(spec.type==='boolean'){if(!['true','false'].includes(value))fail('invalid_value');return value;}
 if(spec.type==='date'){if(!validDate(value))fail('invalid_value');return value;}
 if(spec.type==='choice'){const choice=spec.choices.find(c=>c===value.toLowerCase());if(!choice)fail('invalid_value');return choice;}
 if(spec.type==='person'){if(!await one(ctx,'SELECT 1 FROM oa_operators WHERE id=?',value))fail('manager_not_found');return value;}
 fail('invalid_value');
}

// Every person's values by field: [{source,value}], highest precedence first.
export async function valuesByPerson(ctx) {
 const people=new Map();
 for(const row of await all(ctx,'SELECT person_id,field,source,value FROM auth_person_fields')) {
  const fields=people.get(row.person_id)??people.set(row.person_id,new Map()).get(row.person_id);
  (fields.get(row.field)??fields.set(row.field,[]).get(row.field)).push({source:row.source,value:row.value});
 }
 for(const fields of people.values())for(const list of fields.values())list.sort((a,b)=>SOURCES.indexOf(a.source)-SOURCES.indexOf(b.source));
 return people;
}
// fields: Map(field -> [{source,value}]); the plain effective values, with defaults.
export function effective(fields,defs) {
 const out={};
 for(const [key,spec] of defs)if(spec.default!==undefined)out[key]=spec.default;
 for(const [field,list] of fields??[])out[field]=list[0].value;
 return out;
}
export const winning=(fields,field)=>fields?.get(field)?.[0]??null;

// Fields whose owning sources disagree: what wins, and what it overrides.
export function conflicts(fields) {
 const found=[];
 for(const [field,list] of fields??[]) {
  const owning=list.filter(v=>OWNING.includes(v.source));
  if(new Set(owning.map(v=>v.value)).size>1)found.push({field,effective:owning[0],others:owning.slice(1).filter(v=>v.value!==owning[0].value)});
 }
 return found.sort((a,b)=>a.field.localeCompare(b.field));
}
// Who holds a field against the employee: the highest owning source, if any.
export const owner=(fields,field)=>fields?.get(field)?.find(v=>OWNING.includes(v.source))?.source??null;

// The field map after one source writes: null clears that source's value.
export function written(fields,field,source,value) {
 const next=new Map([...(fields??[])].map(([k,list])=>[k,list.map(v=>({...v}))]));
 const list=(next.get(field)??[]).filter(v=>v.source!==source);
 if(value!==null)list.push({source,value});
 list.sort((a,b)=>SOURCES.indexOf(a.source)-SOURCES.indexOf(b.source));
 if(list.length)next.set(field,list);else next.delete(field);
 return next;
}

export const setStatement=(ctx,guard,personId,field,source,value,by)=>ctx.db.prepare(`INSERT INTO auth_person_fields(person_id,field,source,value,set_by,set_at) SELECT ?,?,?,?,?,? WHERE ${guard.clause} ON CONFLICT(person_id,field,source) DO UPDATE SET value=excluded.value,set_by=excluded.set_by,set_at=excluded.set_at`).bind(personId,field,source,value,by,ctx.now(),...guard.args);
export const clearStatement=(ctx,guard,personId,field,source)=>ctx.db.prepare(`DELETE FROM auth_person_fields WHERE person_id=? AND field=? AND source=? AND ${guard.clause}`).bind(personId,field,source,...guard.args);
