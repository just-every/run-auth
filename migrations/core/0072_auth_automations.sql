-- Connection custody and exact per-run approval stay in this installation.
CREATE TABLE auth_automation_connections (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 origin TEXT NOT NULL,
 token_url TEXT NOT NULL,
 paths TEXT NOT NULL,
 group_id TEXT NOT NULL REFERENCES auth_groups(id),
 granted_to TEXT NOT NULL REFERENCES oa_operators(id),
 sealed_credentials TEXT NOT NULL,
 version INTEGER NOT NULL DEFAULT 1,
 revoked_at INTEGER,
 created_by TEXT NOT NULL REFERENCES oa_operators(id),
 created_at INTEGER NOT NULL
);
CREATE TABLE auth_automations (
 id TEXT PRIMARY KEY REFERENCES auth_automation_connections(id),
 name TEXT NOT NULL,
 version INTEGER NOT NULL,
 config TEXT NOT NULL,
 updated_by TEXT NOT NULL REFERENCES oa_operators(id),
 updated_at INTEGER NOT NULL
);
CREATE TABLE auth_automation_versions (
 automation_id TEXT NOT NULL REFERENCES auth_automations(id),
 version INTEGER NOT NULL,
 name TEXT NOT NULL,
 config TEXT NOT NULL,
 created_by TEXT NOT NULL REFERENCES oa_operators(id),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(automation_id,version)
);
CREATE TABLE auth_automation_runs (
 id TEXT PRIMARY KEY,
 automation_id TEXT NOT NULL REFERENCES auth_automations(id),
 automation_version INTEGER NOT NULL,
 connection_version INTEGER NOT NULL,
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 person_version INTEGER NOT NULL,
 event_id TEXT,
 state TEXT NOT NULL CHECK(state IN ('dry_run','awaiting_approval','approved','running','completed','failed','uncertain','invalidated')),
 approved_by TEXT REFERENCES oa_operators(id),
 session_id TEXT,
 epoch INTEGER,
 approved_at INTEGER,
 lease_until INTEGER,
 error TEXT,
 created_at INTEGER NOT NULL,
 finished_at INTEGER,
 UNIQUE(automation_id,event_id)
);
CREATE TABLE auth_automation_steps (
 run_id TEXT NOT NULL REFERENCES auth_automation_runs(id),
 ordinal INTEGER NOT NULL CHECK(ordinal IN (1,2)),
 state TEXT NOT NULL CHECK(state IN ('intended','running','completed','failed','uncertain')),
 status INTEGER,
 error TEXT,
 started_at INTEGER,
 finished_at INTEGER,
 PRIMARY KEY(run_id,ordinal)
);
CREATE INDEX auth_automation_pending ON auth_automation_runs(state,lease_until);
