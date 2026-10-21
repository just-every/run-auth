import {all,fail} from '../core.mjs';

// Identifiers come exclusively from SQLite's own schema, never a request.
export const quoted=value=>'"'+String(value).replaceAll('"','""')+'"';
const allowed=name=>/^(?:auth_|oa_|rer_|oc_)[a-zA-Z0-9_]+$/.test(name);
export const erasureTable=name=>name.startsWith('auth_erasure_');
export async function schema(ctx) {
 if(ctx.db.scopeMetadata)return (await ctx.db.scopeMetadata()).filter(t=>allowed(t.name));
 if(ctx.organizationId&&ctx.organizationId!=='root')fail('erasure_namespace_metadata_required',503);
 const tables=await all(ctx,"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
 return Promise.all(tables.filter(t=>allowed(t.name)).map(async({name})=>({name,
  columns:await all(ctx,`PRAGMA table_info(${quoted(name)})`),foreignKeys:await all(ctx,`PRAGMA foreign_key_list(${quoted(name)})`),
 })));
}
export async function snapshot(ctx) {
 const tables=await schema(ctx),stores=new Map();
 for(const table of tables) {
  if(erasureTable(table.name)&&!['auth_erasure_policy','auth_erasure_holds'].includes(table.name))continue;
  stores.set(table.name,{...table,rows:await all(ctx,`SELECT * FROM ${quoted(table.name)}`)});
 }
 return stores;
}
export function rowKey(table,row) {
 const primary=table.columns.filter(c=>c.pk).sort((a,b)=>a.pk-b.pk);
 const keys=primary.length?primary:table.columns;
 if(!keys.length)fail('erasure_store_key_required',503);
 return {clause:keys.map(c=>`${quoted(c.name)} IS ?`).join(' AND '),args:keys.map(c=>row[c.name])};
}
// Children precede their parents. A cyclic schema is refused before any write.
export function deletionOrder(stores) {
 const result=[],visiting=new Set(),done=new Set();
 const visit=name=>{
  if(done.has(name))return;if(visiting.has(name))fail('erasure_store_cycle',503);
  visiting.add(name);
  for(const child of stores.values())if(child.name!==name&&child.foreignKeys.some(f=>f.table===name))visit(child.name);
  visiting.delete(name);done.add(name);result.push(name);
 };
 for(const name of stores.keys())visit(name);
 return result;
}
