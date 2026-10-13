-- Preparer keys: an agent reads the inventory and files proposals; a person
-- approves. Only the key's SHA-256 digest is stored; the key itself is shown
-- once at minting. Its owner is the administrator who minted it and is
-- accountable for it. A key confers no session and no administrator right.
CREATE TABLE auth_agent_keys (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE,
 owner_id TEXT NOT NULL REFERENCES oa_operators(id),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_used_at INTEGER,
 renewed_at INTEGER, revoked_at INTEGER, revoked_by TEXT REFERENCES oa_operators(id)
);
CREATE INDEX auth_agent_keys_owner ON auth_agent_keys(owner_id);
-- A proposed change. Filing stores its effect, the target's state and that
-- state's digest; nothing else changes until a person approves, and
-- execution_id marks the one approval that ran it.
CREATE TABLE auth_agent_proposals (
 id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES auth_agent_keys(id),
 kind TEXT NOT NULL CHECK(kind IN ('suspend_person','restore_person','invite_person','remove_invitation','add_domain_rule','remove_domain_rule')),
 target TEXT NOT NULL, params TEXT NOT NULL, reason TEXT NOT NULL,
 effect TEXT NOT NULL, target_state TEXT NOT NULL, state_digest TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','rejected','failed')),
 decided_by TEXT REFERENCES oa_operators(id), decided_at INTEGER, outcome TEXT, execution_id TEXT UNIQUE
);
CREATE INDEX auth_agent_proposals_key ON auth_agent_proposals(key_id);
CREATE INDEX auth_agent_proposals_pending ON auth_agent_proposals(status,created_at);
