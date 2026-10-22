CREATE TABLE auth_privileged_resources (
 kind TEXT NOT NULL CHECK(kind IN ('app','group')), target_id TEXT NOT NULL,
 privileged INTEGER NOT NULL DEFAULT 1 CHECK(privileged IN (0,1)), marked_by TEXT NOT NULL, marked_at INTEGER NOT NULL, PRIMARY KEY(kind,target_id)
);
CREATE TABLE auth_decision_operations (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, session_id TEXT NOT NULL,
 kind TEXT NOT NULL, target_id TEXT NOT NULL, operation TEXT NOT NULL,
 person_id TEXT, reason TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_review_schedules (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, reviewer_id TEXT NOT NULL,
 interval_months INTEGER NOT NULL, next_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE auth_reviews (
 id TEXT PRIMARY KEY, schedule_id TEXT REFERENCES auth_review_schedules(id), name TEXT NOT NULL,
 reviewer_id TEXT NOT NULL, period_start INTEGER NOT NULL, period_end INTEGER NOT NULL,
 due_at INTEGER NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')), closed_at INTEGER,
 UNIQUE(schedule_id,period_end)
);
CREATE TABLE auth_review_items (
 id TEXT PRIMARY KEY, review_id TEXT NOT NULL REFERENCES auth_reviews(id),
 subject_id TEXT NOT NULL, app_id TEXT NOT NULL, principal_type TEXT NOT NULL,
 principal_id TEXT NOT NULL, role TEXT, snapshot TEXT NOT NULL,
 reviewer_id TEXT NOT NULL, decision TEXT, reason TEXT, decided_by TEXT, decided_at INTEGER,
 operation_id TEXT REFERENCES auth_decision_operations(id)
);
CREATE TABLE auth_review_events (
 id TEXT PRIMARY KEY, review_id TEXT NOT NULL, item_id TEXT, actor_id TEXT,
 event TEXT NOT NULL, detail TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_app_denials (
 app_id TEXT NOT NULL, person_id TEXT NOT NULL, operation_id TEXT NOT NULL,
 created_at INTEGER NOT NULL, PRIMARY KEY(app_id,person_id)
);
CREATE TRIGGER auth_decision_denial_insert AFTER INSERT ON auth_app_denials
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_decision_denial_delete AFTER DELETE ON auth_app_denials
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_decision_privilege_insert AFTER INSERT ON auth_privileged_resources
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_decision_privilege_delete AFTER DELETE ON auth_privileged_resources
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_decision_review_update AFTER UPDATE ON auth_review_items
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;

CREATE TRIGGER auth_decision_privilege_update AFTER UPDATE ON auth_privileged_resources
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
