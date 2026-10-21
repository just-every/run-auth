-- An explicit request to connect another upstream identity to the signed-in
-- account. It is bound to the session that asked, used once, and expires in ten
-- minutes; only its digest is stored.
CREATE TABLE auth_link_intents (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES oa_operators(id), session_id TEXT NOT NULL,
 provider_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);
