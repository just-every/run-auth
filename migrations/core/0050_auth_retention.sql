-- Retention is separate from owner-confirmed erasure. A queued plan remains
-- exportable for seven days; the cleanup rechecks policy, holds and live work.
CREATE TABLE auth_retention_policy (
 id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL,
 updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL, revision INTEGER NOT NULL
);
CREATE TABLE auth_retention_holds (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('review','request','investigation','legal')),
 period_start INTEGER NOT NULL, period_end INTEGER NOT NULL,
 classes TEXT NOT NULL, reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 released_by TEXT, released_at INTEGER, CHECK(period_start<=period_end)
);
CREATE INDEX auth_retention_holds_period ON auth_retention_holds(released_at,period_start,period_end);
-- The plan contains private, credential-free row snapshots. It is local-only
-- and destroyed at completion, cancellation or after it is superseded.
CREATE TABLE auth_retention_runs (
 id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('queued','completed','cancelled')),
 policy_revision INTEGER NOT NULL, created_at INTEGER NOT NULL, delete_after INTEGER NOT NULL,
 completed_at INTEGER, plan TEXT, summary TEXT NOT NULL, result TEXT NOT NULL DEFAULT '{}', claim_id TEXT
);
CREATE UNIQUE INDEX auth_retention_one_queue ON auth_retention_runs(status) WHERE status='queued';
