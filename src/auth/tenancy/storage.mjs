import {fail} from '../core.mjs';

// Schema names, SQL text and raw D1 statements stay inside this module. A scoped
// handle exposes only D1's query interface, never its underlying global handle.
const schemas = new WeakMap();
const statements = new WeakMap();
const databaseScopes = new WeakMap();
const BATCH_SIZE = 50;
const tenantTable = name => /^(?:auth_|oa_|rer_)/i.test(name)
 && !['auth_organizations','auth_domain_claims'].includes(name.toLowerCase());
const quoted = name => '"' + name.replaceAll('"', '""') + '"';

function namespaceFor(id) {
 if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) throw new Error('invalid_organization_id');
 return `org_${id}_`;
}

// Lex SQL rather than replacing substrings: values, comments and bind parameter
// names must retain their bytes. Quoted identifiers retain their quote style.
function tokens(sql) {
 if (typeof sql !== 'string') throw new TypeError('SQL must be a string');
 const result = [];
 let i = 0;
 while (i < sql.length) {
  const start = i, c = sql[i];
  let name, kind = 'other', quote;
  if (sql.startsWith('--', i)) {
   i = sql.indexOf('\n', i + 2);
   if (i < 0) i = sql.length;
   kind = 'comment';
  } else if (sql.startsWith('/*', i)) {
   const end = sql.indexOf('*/', i + 2);
   if (end < 0) throw new Error('unterminated_sql_comment');
   i = end + 2;
   kind = 'comment';
  } else if (c === "'" || c === '"' || c === '`' || c === '[') {
   quote = c;
   const close = c === '[' ? ']' : c;
   let value = '', closed = false;
   i++;
   while (i < sql.length) {
    if (sql[i] !== close) { value += sql[i++]; continue; }
    if (sql[i + 1] === close) { value += close; i += 2; continue; }
    i++;
    closed = true;
    break;
   }
   if (!closed) throw new Error('unterminated_sql_quote');
   kind = c === "'" ? 'literal' : 'identifier';
   if (kind === 'identifier') name = value;
  } else if (/[:@$]/.test(c) && /[\w$]/.test(sql[i + 1] ?? '')) {
   i++;
   while (i < sql.length && /[\w$]/.test(sql[i])) i++;
   kind = 'parameter';
  } else if (/[a-z_\u0080-\uffff]/i.test(c)) {
   i++;
   while (i < sql.length && /[\w$\u0080-\uffff]/.test(sql[i])) i++;
   kind = 'identifier';
   name = sql.slice(start, i);
  } else {
   i++;
   if (/\s/.test(c)) kind = 'space';
  }
  result.push({text: sql.slice(start, i), kind, name, quote});
 }
 return result;
}

function rewrite(sql, names, create = false) {
 const lexed = tokens(sql);
 let createKeyword;
 if (create) {
  const words = lexed.filter(t => t.kind !== 'comment' && t.kind !== 'space');
  let index = 1;
  if (words[index]?.name?.toUpperCase() === 'UNIQUE') index++;
  createKeyword = words[index];
  if (words[0]?.name?.toUpperCase() !== 'CREATE'
   || !['TABLE', 'INDEX', 'TRIGGER'].includes(createKeyword?.name?.toUpperCase())) {
   throw new Error('unsupported_organization_schema');
  }
  if (words[index + 1]?.name?.toUpperCase() === 'IF') createKeyword = undefined;
 }
 return lexed.map(token => {
  const key = token.name?.toLowerCase();
  const replacement = key && names.get(key);
  let value = token.text;
  if (replacement) {
   if (token.quote === '[') value = `[${replacement.replaceAll(']', ']]')}]`;
   else if (token.quote) value = token.quote + replacement.replaceAll(token.quote, token.quote.repeat(2)) + token.quote;
   else value = replacement;
  }
  return value + (token === createKeyword ? ' IF NOT EXISTS' : '');
 }).join('');
}

async function currentSchema(db, namespace) {
 const {results} = await db.prepare(
  "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index','trigger') AND sql IS NOT NULL AND (lower(tbl_name) GLOB 'auth_*' OR lower(tbl_name) GLOB 'oa_*' OR lower(tbl_name) GLOB 'rer_*' OR substr(lower(name),1,?)=?) ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END,rowid"
 ).bind(namespace.length, namespace).all();
 const tableNames = new Set(results.filter(row => row.type === 'table' && tenantTable(row.name)).map(row => row.name.toLowerCase()));
 const objects = results.filter(row => tableNames.has(row.tbl_name.toLowerCase()));
 const names = new Map(objects.map(row => [row.name.toLowerCase(), namespace + row.name]));
 const existing = new Set(results.map(row => row.name.toLowerCase()));
 const missing = objects.filter(row => !existing.has((namespace + row.name).toLowerCase()));
 return {objects, names, tableNames, missing};
}

async function createSchema(db, schema) {
 const queries = schema.missing.map(row => db.prepare(rewrite(row.sql, schema.names, true)));
 // D1 batches are transactional. Chunks leave the registry pending throughout
 // provisioning, so a partially created organization cannot be opened.
 for (let offset = 0; offset < queries.length; offset += BATCH_SIZE) {
  await db.batch(queries.slice(offset, offset + BATCH_SIZE));
 }
}

function singletonSeeds(db, organization, schema) {
 const seeds = [
  ['auth_lifecycle_epoch', '(id,epoch) VALUES(1,1) ON CONFLICT(id) DO NOTHING'],
  ['auth_admin_api_epoch', '(id,version) VALUES(1,1) ON CONFLICT(id) DO NOTHING'],
  ['auth_role_epoch', '(id,epoch) VALUES(1,1) ON CONFLICT(id) DO NOTHING'],
  ['auth_erasure_policy', `(singleton,configured,policy,updated_by,updated_at) VALUES(1,0,'{"mode":"explicit-owner-confirmation","automaticDeletion":false,"heldData":"refuse-erasure","audit":"anonymized","remote":"separate-until-verified"}',NULL,0) ON CONFLICT(singleton) DO NOTHING`],
 ];
 return seeds.filter(([table]) => schema.tableNames.has(table)
  && (organization.status === 'pending' || schema.missing.some(row => row.name.toLowerCase() === table)))
  .map(([table, values]) => db.prepare(`INSERT INTO ${organization.namespace}${table}${values}`));
}

async function scopeMetadata(db, namespace, schema) {
 const logical = new Map([...schema.names].map(([name, physical]) => [physical.toLowerCase(), name]));
 return Promise.all(schema.objects.filter(row => row.type === 'table').map(async row => {
  const physical = quoted(namespace + row.name);
  const [columns, foreignKeys] = await Promise.all([
   db.prepare(`PRAGMA table_info(${physical})`).all(),
   db.prepare(`PRAGMA foreign_key_list(${physical})`).all(),
  ]);
  return {
   name: row.name,
   columns: columns.results.map(({name, pk, notnull, type}) => ({name, pk, notnull, type})),
   foreignKeys: foreignKeys.results.map(({table, from, to}) => ({table: logical.get(table.toLowerCase()) ?? table, from, to})),
  };
 }));
}

/** A synchronous D1 facade. Prefer organizationDatabase to validate readiness
 * and bring newly added tables into the namespace before obtaining the facade.
 * The registry's namespace must be derived from its validated organization id.
 */
export function scopedDatabase(db, organization, retained = false) {
 const namespace = namespaceFor(organization.id);
 if (organization.namespace !== namespace || organization.status !== (retained ? 'erased' : 'active')) throw new Error('organization_not_ready');
 const schema = schemas.get(organization);
 if (!schema) throw new Error('organization_schema_required');
 const names = schema.names;
 const scope = {};
 const wrap = raw => {
  const statement = {
   bind: (...values) => wrap(raw.bind(...values)),
   first: (...args) => raw.first(...args),
   all: (...args) => raw.all(...args),
   run: (...args) => raw.run(...args),
   raw: (...args) => raw.raw(...args),
  };
  statements.set(statement, {raw, scope});
  return statement;
 };
 const facade = {
  prepare: sql => wrap(db.prepare(rewrite(sql, names))),
  batch: batch => {
   if (!Array.isArray(batch)) throw new TypeError('D1 batch requires an array');
   const raw = batch.map(statement => {
    const entry = statements.get(statement);
    if (!entry || entry.scope !== scope) throw new Error('organization_statement_scope');
    return entry.raw;
   });
   // Never split application batches: concurrency guards and writes must commit
   // together, or the caller must explicitly choose separate transactions.
   return db.batch(raw);
  },
  exec: sql => db.exec(rewrite(sql, names)),
  scopeMetadata: async () => scopeMetadata(db, namespace, schema),
 };
 databaseScopes.set(facade,{db,scope});
 return facade;
}

/** Open only a fully provisioned organization, cloning newly added tables and
 * their indexes/triggers from the current installed schema on every open.
 */
export async function organizationDatabase(db, id) {
 if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) return null;
 const organization = await db.prepare("SELECT id,name,namespace,created_by,created_at,status FROM auth_organizations WHERE id=? AND status='active'").bind(id).first();
 if (!organization) return null;
 if (organization.namespace !== namespaceFor(id)) throw new Error('invalid_organization_namespace');
 const schema = await currentSchema(db, organization.namespace);
 await createSchema(db, schema);
 const seed = singletonSeeds(db, organization, schema);
 if (seed.length) await db.batch(seed);
 schemas.set(organization, schema);
 return {db: scopedDatabase(db, organization), organization};
}

// Erased issuers never reopen their public routes. Installation-owner erasure
// custody uses this internal handle only for anonymous receipts and sealed retry
// work; it neither provisions a schema nor creates a new identity/session.
export async function erasedOrganizationDatabase(db, id) {
 if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) return null;
 const organization = await db.prepare("SELECT id,namespace,status FROM auth_organizations WHERE id=? AND status='erased'").bind(id).first();
 if (!organization) return null;
 const schema = await currentSchema(db, organization.namespace);
 schemas.set(organization, schema);
 return {db: scopedDatabase(db, organization, true), organization};
}

/** Reserve a unique id before DDL, then publish readiness only after every
 * table, index, trigger and essential fresh singleton exists. Failed attempts
 * remain pending and cannot be opened or have their identity reused.
 */
export async function provisionOrganization(db, {id = crypto.randomUUID().replaceAll('-', ''), name, createdBy, now = Date.now()}) {
 const namespace = namespaceFor(id);
 if (typeof name !== 'string' || !name.trim() || name.trim().length > 200) throw new Error('invalid_organization_name');
 if (typeof createdBy !== 'string' || !createdBy || !Number.isSafeInteger(now)) throw new Error('invalid_organization_creator');
 const organization = {id, name: name.trim(), namespace, created_by: createdBy, created_at: now, status: 'pending'};
 // Base claims import_job before staging and holds it until complete/abort;
 // applying alone is insufficient because a failed finalize returns to staging.
 // Keep this check in the reservation statement so a concurrent import cannot
 // pass between a JavaScript preflight and the first organization write.
 const reserved = await db.prepare("INSERT INTO auth_organizations(id,name,namespace,created_by,created_at,status) SELECT ?,?,?,?,?,'pending' WHERE NOT EXISTS(SELECT 1 FROM rer_portability_state WHERE id=1 AND (import_job IS NOT NULL OR applying<>0))")
  .bind(id, organization.name, namespace, createdBy, now).run();
 if (!reserved.meta.changes) fail('organization_unavailable_importing', 409);
 const schema = await currentSchema(db, namespace);
 await createSchema(db, schema);
 await db.batch([
  ...singletonSeeds(db, organization, schema),
  db.prepare("UPDATE auth_organizations SET status='active' WHERE id=? AND namespace=? AND status='pending'").bind(id, namespace),
 ]);
 organization.status = 'active';
 schemas.set(organization, schema);
 return {db: scopedDatabase(db, organization), organization};
}

// Erasure changes both a selected employer and the installation-wide archive
// fence in one transaction. Ordinary handlers keep the scope-only batch door.
export function batchWithInstallation(scoped, local, installation, before = []) {
 const selected=databaseScopes.get(scoped);
 if(!selected)return scoped.batch([...before,...local,...installation]);
 const unwrap=statement=>{const entry=statements.get(statement);if(!entry||entry.scope!==selected.scope)throw new Error('organization_statement_scope');return entry.raw;};
 return selected.db.batch([...before,...local.map(unwrap),...installation]);
}
