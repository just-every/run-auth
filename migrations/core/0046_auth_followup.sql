-- Follow-up records confer no authority. Sources remain the deciding records.
CREATE TABLE auth_followup_settings (
 id INTEGER PRIMARY KEY CHECK(id=1),
 policy TEXT NOT NULL,
 updated_by TEXT NOT NULL REFERENCES oa_operators(id),
 updated_at INTEGER NOT NULL
);
CREATE TABLE auth_obligations (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('enrollment','recovery','provisioning','app_setup','app_link_proposal','app_link_token','delegated_assignment')),
 source_id TEXT NOT NULL,
 owner_id TEXT REFERENCES oa_operators(id),
 person_id TEXT REFERENCES oa_operators(id),
 app_id TEXT REFERENCES auth_apps(id),
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
CREATE INDEX auth_obligations_due ON auth_obligations(state,next_due_at);
CREATE TABLE auth_obligation_history (
 id TEXT PRIMARY KEY,
 obligation_id TEXT NOT NULL REFERENCES auth_obligations(id) ON DELETE CASCADE,
 event TEXT NOT NULL,
 actor_id TEXT REFERENCES oa_operators(id),
 recipient_id TEXT REFERENCES oa_operators(id),
 created_at INTEGER NOT NULL,
 error TEXT
);
CREATE INDEX auth_obligation_history_task ON auth_obligation_history(obligation_id,created_at);

-- Opaque follow-up references are separate from one-use credential digests.
-- This custody mapping is secret, local, and deleted with the original token.
CREATE TABLE auth_followup_link_tokens (
 id TEXT PRIMARY KEY,
 token_hash TEXT NOT NULL UNIQUE REFERENCES auth_link_tokens(token_hash) ON DELETE CASCADE,
 client_id TEXT REFERENCES auth_clients(id)
);
