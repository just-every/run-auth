import {all,fail} from '../core.mjs';
import {managedStore,registeredOrganizations,resolveStore,StoreRegistryError} from '../stores.mjs';

// Identifiers come exclusively from SQLite's own schema, never a request.
export const quoted=value=>'"'+String(value).replaceAll('"','""')+'"';
export const erasureTable=name=>name.startsWith('auth_erasure_');
function checked(tables,organizations=[],scoped=false) {
 try {
  // Validate the whole inventory before reading a single managed data row.
  // Root previews validate other namespaces but never inspect their directory.
  return tables.filter(table=> {
   const store=resolveStore(table.name,organizations);
   if(!store)return false;
   if(scoped&&(store.namespace||!store.scoped))fail('erasure_namespace_metadata_required',503);
   for(const reference of table.foreignKeys??[])if(managedStore(reference.table)) {
    const parent=resolveStore(reference.table,organizations);
    if(scoped&&parent.namespace)fail('erasure_namespace_metadata_required',503);
   }
   return !store.namespace&&!store.name.startsWith('agent_door_')&&!store.name.startsWith('bs_');
  });
 }catch(error) {
  if(error instanceof StoreRegistryError)fail('erasure_unknown_store',503);
  throw error;
 }
}
async function scopedSchema(ctx) {
 if(typeof ctx.organizationId!=='string'||!/^[a-f0-9]{32}$/.test(ctx.organizationId))fail('erasure_namespace_metadata_required',503);
 let organizations;
 try {
  organizations=registeredOrganizations(await all(ctx,'SELECT id,namespace,status FROM auth_organizations WHERE id=?',ctx.organizationId));
 }catch(error) {
  if(error instanceof StoreRegistryError)fail('erasure_unknown_store',503);
  throw error;
 }
 if(organizations.length!==1)fail('erasure_namespace_metadata_required',503);
 const namespace=organizations[0].namespace;
 const [metadata,physical]=await Promise.all([
  ctx.db.scopeMetadata(),
  all(ctx,"SELECT name FROM sqlite_master WHERE type='table' AND substr(name,1,?)=? ORDER BY name",namespace.length,namespace),
 ]);
 // A namespace-only store is not necessarily present in the root schema from
 // which scopeMetadata was built. Validate its physical inventory as well.
 checked(physical,organizations);
 const selected=checked(metadata,[],true),logical=new Set(physical.map(table=>resolveStore(table.name,organizations).name));
 if(logical.size!==selected.length||selected.some(table=>!logical.has(table.name.toLowerCase())))fail('erasure_namespace_metadata_required',503);
 return selected;
}
export async function schema(ctx) {
 if(ctx.db.scopeMetadata)return scopedSchema(ctx);
 if(ctx.organizationId&&ctx.organizationId!=='root')fail('erasure_namespace_metadata_required',503);
 const tables=await all(ctx,"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
 const organizations=tables.some(t=>/^org_/i.test(t.name))
  ? await all(ctx,'SELECT id,namespace,status FROM auth_organizations') : [];
 const selected=checked(tables,organizations);
 const metadata=await Promise.all(selected.map(async({name})=>({name,
  columns:await all(ctx,`PRAGMA table_info(${quoted(name)})`),foreignKeys:await all(ctx,`PRAGMA foreign_key_list(${quoted(name)})`),
 })));
 return checked(metadata,organizations);
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
