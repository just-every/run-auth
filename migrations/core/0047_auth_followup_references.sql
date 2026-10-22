-- Follow-up evidence survives ordinary source deletion without retaining a
-- foreign-key dependency that would block authorized Move-in undo.
CREATE TABLE auth_obligations_rebuilt (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('enrollment','recovery','provisioning','app_setup','app_link_proposal','app_link_token','delegated_assignment')),
 source_id TEXT NOT NULL,
 owner_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 person_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 app_id TEXT REFERENCES auth_apps(id) ON DELETE SET NULL,
 next_action TEXT NOT NULL,
 calendar TEXT NOT NULL,
 deadline_at INTEGER NOT NULL,
 next_due_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('open','completed','cancelled','expired')),
 stop_rule TEXT NOT NULL,
 escalation_rule TEXT NOT NULL,
 last_error TEXT,
 delivery_error TEXT,
 created_at INTEGER NOT NULL,
 stopped_at INTEGER,
 reminders_stopped_at INTEGER,
 claim_id TEXT,
 claimed_until INTEGER,
 UNIQUE(kind,source_id)
);
INSERT INTO auth_obligations_rebuilt SELECT * FROM auth_obligations;
CREATE TABLE auth_obligation_history_rebuilt (
 id TEXT PRIMARY KEY,
 obligation_id TEXT NOT NULL REFERENCES auth_obligations_rebuilt(id) ON DELETE CASCADE,
 event TEXT NOT NULL,
 actor_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 recipient_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 created_at INTEGER NOT NULL,
 error TEXT
);

INSERT INTO auth_obligation_history_rebuilt SELECT * FROM auth_obligation_history;
DROP TABLE auth_obligation_history;
DROP TABLE auth_obligations;
ALTER TABLE auth_obligations_rebuilt RENAME TO auth_obligations;
ALTER TABLE auth_obligation_history_rebuilt RENAME TO auth_obligation_history;
CREATE INDEX auth_obligations_due ON auth_obligations(state,next_due_at);
CREATE INDEX auth_obligation_history_task ON auth_obligation_history(obligation_id,created_at);
