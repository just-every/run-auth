-- Source credentials admit observations; exact human approval alone admits changes.
CREATE TABLE auth_directory_sources (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, mode TEXT NOT NULL,
 name TEXT NOT NULL, base_url TEXT, organization_binding TEXT NOT NULL,
 sealed_credential TEXT, ingress_hash TEXT, fields TEXT NOT NULL,
 created_by TEXT NOT NULL, owner_version INTEGER NOT NULL,
 created_at INTEGER NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
 last_read_at INTEGER, next_poll_at INTEGER, last_error TEXT, disabled_at INTEGER
);
CREATE TABLE auth_directory_snapshots (
 id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES auth_directory_sources(id),
 digest TEXT NOT NULL, payload TEXT NOT NULL, complete INTEGER NOT NULL,
 state TEXT NOT NULL, reasons TEXT NOT NULL, created_at INTEGER NOT NULL,
 approved_by TEXT, approver_version INTEGER, approved_digest TEXT,
 approved_at INTEGER, current_epoch INTEGER, error TEXT,
 UNIQUE(source_id,digest)
);
CREATE TABLE auth_directory_resources (
 source_id TEXT NOT NULL REFERENCES auth_directory_sources(id),
 resource_type TEXT NOT NULL, external_id TEXT NOT NULL,
 document TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(source_id,resource_type,external_id)
);
CREATE TABLE auth_directory_source_groups (
 source_id TEXT NOT NULL REFERENCES auth_directory_sources(id),
 external_id TEXT NOT NULL, group_id TEXT NOT NULL REFERENCES auth_groups(id),
 PRIMARY KEY(source_id,external_id), UNIQUE(group_id)
);
CREATE TABLE auth_directory_source_steps (
 id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES auth_directory_snapshots(id),
 idx INTEGER NOT NULL, effect TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', target_id TEXT, applied_at INTEGER, error TEXT,
 UNIQUE(snapshot_id,idx)
);
CREATE INDEX auth_directory_source_pending ON auth_directory_source_steps(state,snapshot_id,idx);
