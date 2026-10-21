// Explicit directory projection: credentials, sessions and private runtime state
// never enter the language's context, even for an administrator's preview.
import {loadDirectory} from '../workforce/people/load.mjs';
export async function mappingDirectory(ctx) {
 const dir=await loadDirectory(ctx);
 const fields=Object.fromEntries([...dir.defs].map(([k,v])=>[k,v.type]));
 Object.assign(fields,{email:'text',name:'text',person_id:'text',first_name:'text',last_name:'text'});
 const schema={fields,manager:fields};
 const values=p=>{
  if(!p)return Object.fromEntries(Object.keys(fields).map(k=>[k,null]));
  const out={...Object.fromEntries(Object.keys(fields).map(k=>[k,null])),...dir.values(p)};
  const name=out.name??p.name??'',space=name.lastIndexOf(' ');
  for(const [key,type] of Object.entries(fields))if(out[key]!==null){if(type==='number')out[key]=Number(out[key]);else if(type==='boolean')out[key]=out[key]==='true';}
  return {...out,email:p.email,name,person_id:p.id,first_name:space>0?name.slice(0,space):name,last_name:space>0?name.slice(space+1):null};
 };
 const context=p=>{
  const f=values(p),sources={};
  for(const source of ['manual','hr','directory','self'])sources[source]=Object.fromEntries([...p.fields].flatMap(([k,vs])=>vs.filter(v=>v.source===source).map(v=>[k,v.value])));
  for(const values of Object.values(sources))for(const [key,value] of Object.entries(values)){if(fields[key]==='number')values[key]=Number(value);else if(fields[key]==='boolean')values[key]=value==='true';}
  return {fields:f,sources,manager:values(dir.people.get(f.manager)),groups:dir.groups.filter(g=>dir.members.get(g.id)?.has(p.id)).map(g=>g.name)};
 };
 return {dir,schema,context};
}
