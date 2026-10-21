// Auth's export and import on Base's portability engine. Export first writes a
// signed grant map into the database, so the archive carries it; import checks
// every client and person against the destination's own rules before restoring.
// Runtime modules load lazily: this adapter must load before `rer install`.
import { createRequire } from 'node:module';
import { link, lstat, unlink } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { localPortability } from '@runeditrun/rer/portability';
import { fileRecords } from '@runeditrun/rer/modules/portability/files';
import { readSettings } from '@runeditrun/rer/adapter-settings';
import { RerError } from '@runeditrun/rer/errors';
import { portableTables, registeredOrganizations, resolveStore, StoreRegistryError } from '../../src/auth/stores.mjs';

// Base still owns the archive, journal fence and atomic restore. Its default
// inclusion is replaced with the same explicit store decisions erasure uses.
// Even a store created after preflight cannot silently enter an archive.
export const POLICY = {
 product: 'identity-auth',
 includeTables: portableTables(),
 excludeTables: ['%'],
 requiredConfiguration: ['AUTH_ENCRYPTION_KEY'],
};
function registryFailure(error) {
 if(error instanceof StoreRegistryError)throw new RerError('restore_refused',`Restore/export refused (${error.code}): the managed store inventory requires review.`,4);
 throw error;
}
function installationArchiveAuthority(organizations,direction) {
 // Every employer currently provisioned by Auth is isolated. Installation
 // ownership is hosting/reset authority, never authority over its directory.
 // An employer-owner archive/restore door remains AUTH-TRANSFER-002 work.
 if(organizations.some(organization=>organization.status==='active'))throw new RerError('restore_refused',
  `Installation ${direction} refused (isolated_organization_${direction}_forbidden): an active isolated employer exists. Installation roles have no authority to ${direction} its directory. Separate employer-owner-authorized archives and restores are not yet shipped (AUTH-TRANSFER-002).`,4);
}
export function organizationPolicy(organizations=[],direction='export') {
 try {
  const registered=registeredOrganizations(organizations);installationArchiveAuthority(registered,direction);
  return {...POLICY,includeTables:portableTables(registered)};
 }catch(error){registryFailure(error);}
}
const engineFor=(organizations,direction)=>localPortability({database:'auth',policy:organizationPolicy(organizations,direction)});

function checkStores(names,organizations,portable=false) {
 for(const name of names) {
  const store=resolveStore(name,organizations);
  if(portable&&(!store||!store.portable))throw new StoreRegistryError('nonportable_store',name);
 }
}
async function inventory(db) {
 const tables=(await db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all()).results.map(row=>row.name);
 // A genuinely empty restore destination has no organization registry yet;
 // Base applies the product migrations before its own destination validation.
 const organizations=registeredOrganizations(tables.includes('auth_organizations')
  ? (await db.prepare('SELECT id,namespace,status FROM auth_organizations ORDER BY id').all()).results : []);
 checkStores(tables,organizations);
 return organizations;
}

async function withDatabase(root, work) {
 const { getPlatformProxy } = createRequire(join(root, 'package.json'))('wrangler');
 const proxy = await getPlatformProxy({ configPath: join(root, 'wrangler.jsonc'), persist: { path: join(root, '.wrangler/state/v3') }, remoteBindings: false });
 try { return await work(proxy.env.DB); } finally { await proxy.dispose(); }
}
const settings = async root => (await readSettings(root, { file: '.dev.vars' })).values;

async function exportAuth(context) {
 let organizations;
 try{organizations=await withDatabase(context.root,inventory);installationArchiveAuthority(organizations,'export');}catch(error){registryFailure(error);}
 try {await lstat(context.path);throw new RerError('restore_refused','Export requires a new archive path.',4);}
 catch(error){if(error.code!=='ENOENT')throw error;}
 const vars = await settings(context.root);
 const { writeGrantMap, issuerOf } = await import('../../src/auth/links/grant-map.mjs');
 const map = await withDatabase(context.root, async db => {
  const ctx = { db, secret: vars.AUTH_ENCRYPTION_KEY, now: Date.now, local: vars.AUTH_LOCAL === 'true' };
  // The issuer apps last discovered; a local install that never served discovery uses its own origin.
  ctx.origin = await issuerOf(ctx) ?? vars.AUTH_ORIGIN;
  return writeGrantMap(ctx);
 });
 context.store.report(`Signed grant map: ${map.sectors} apps, ${map.subjects} pairwise subjects, ${map.former} former subjects.`);
 // Base owns construction, snapshot cleanup and its private output file. Keep
 // that output unpublished until the final live authority/inventory check.
 const unpublished=context.path+'.'+crypto.randomUUID()+'.unpublished';
 try {
  const result=await engineFor(organizations,'export').export({...context,path:unpublished});
  const current=await withDatabase(context.root,inventory);installationArchiveAuthority(current,'export');
  checkStores(result.tables.map(table=>table.name),organizations,true);
  checkStores(result.exclusions.tables,current);
  await link(unpublished,context.path);
  return {...result,output:relative(context.root,context.path),grantMap:map};
 }catch(error){registryFailure(error);}
 finally {await unlink(unpublished).catch(error=>{if(error.code!=='ENOENT')throw error;});}
}

// A local install serves only loopback apps and a hosted one never does; a dev
// persona never becomes a real person.
export function refusal(table, row, local, validateClientOrigin) {
 if (table === 'auth_clients') {
  try { validateClientOrigin({ local }, row.origin); } catch { return `app ${row.origin} cannot be served by this ${local ? 'local' : 'hosted'} install`; }
 }
 if (table === 'oa_operators' && /@dev\.localhost$/i.test(String(row.email)) && row.status !== 'inactive') return `dev persona ${row.email}`;
 return null;
}
async function importAuth(context) {
 // rer import restores into this checkout: local unless its settings say it is configured as hosted.
 const local = (await settings(context.root).catch(() => ({}))).AUTH_LOCAL !== 'false', { validateClientOrigin } = await import('../../src/auth/core.mjs');
 const organizations=[];let manifest;
 for await (const record of fileRecords(context.path)) {
  if(record.kind==='manifest')manifest=record;
  for (const item of record.kind === 'part' ? record.items : []) {
   if(item.kind==='row'&&item.table==='auth_organizations')organizations.push(item.row);
  }
 }
 try {
  registeredOrganizations(organizations);installationArchiveAuthority(organizations,'import');
  checkStores(manifest.tables.map(table=>table.name),organizations,true);
  checkStores(manifest.excludedTables,organizations);
  for(const table of manifest.tables)checkStores(table.dependencies,organizations,true);
  // Registry rows are authenticated by the complete archive before namespace
  // translation. Apply Auth's admission checks to every organization's rows.
  for await(const record of fileRecords(context.path))for(const item of record.kind==='part'?record.items:[])if(item.kind==='row') {
   const store=resolveStore(item.table,organizations);
   if(!store?.portable)throw new StoreRegistryError('nonportable_store',item.table);
   const reason=refusal(store.name,item.row,local,validateClientOrigin);
   if(reason)throw new RerError('restore_refused',`Restore refused (auth_import): ${reason}.`,4);
  }
  const destination=await withDatabase(context.root,inventory);installationArchiveAuthority(destination,'import');
 }catch(error){registryFailure(error);}
 return engineFor(organizations,'import').import(context);
}
export const portability = { export: exportAuth, import: importAuth };
