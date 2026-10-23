CREATE TABLE auth_migration_bridges (
 id TEXT PRIMARY KEY, url TEXT NOT NULL, sealed_credential TEXT,
 state TEXT NOT NULL CHECK(state IN ('active','disabled')) DEFAULT 'active',
 created_by TEXT NOT NULL REFERENCES oa_operators(id), owner_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, disabled_at INTEGER
);
CREATE TABLE auth_migration_subjects (
 bridge_id TEXT NOT NULL REFERENCES auth_migration_bridges(id), source_system TEXT NOT NULL,
 source_subject TEXT NOT NULL, person_id TEXT NOT NULL UNIQUE REFERENCES oa_operators(id),
 email TEXT NOT NULL, person_version INTEGER NOT NULL, batch_id TEXT NOT NULL REFERENCES auth_import_batches(id),
 completed_at INTEGER, PRIMARY KEY(bridge_id,source_subject)
);
CREATE TABLE auth_import_history (
 batch_id TEXT NOT NULL REFERENCES auth_import_batches(id), idx INTEGER NOT NULL,
 email TEXT, person_id TEXT REFERENCES oa_operators(id), history TEXT NOT NULL, PRIMARY KEY(batch_id,idx)
);
