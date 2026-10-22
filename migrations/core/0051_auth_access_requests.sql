CREATE TABLE auth_request_policies (
 app_id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 1, decider_id TEXT NOT NULL, max_duration_ms INTEGER NOT NULL,
 updated_by TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE auth_access_requests (
 id TEXT PRIMARY KEY, app_id TEXT NOT NULL, person_id TEXT NOT NULL, role TEXT,
 purpose TEXT NOT NULL, duration_ms INTEGER NOT NULL, decider_id TEXT NOT NULL,
 policy_revision INTEGER NOT NULL, created_at INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', decided_by TEXT, decided_at INTEGER,
 reason TEXT, operation_id TEXT, expires_at INTEGER, expired_at INTEGER
);
CREATE TRIGGER auth_request_policy_insert AFTER INSERT ON auth_request_policies
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_request_policy_update AFTER UPDATE ON auth_request_policies
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_request_update AFTER UPDATE ON auth_access_requests
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
