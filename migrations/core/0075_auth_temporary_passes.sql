-- Temporary enrollment capabilities are local secrets, never portable identity.
CREATE TABLE auth_temporary_pass_requests (
 id TEXT PRIMARY KEY,
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 person_version INTEGER NOT NULL,
 manager_id TEXT NOT NULL,
 manager_session_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 issued_at INTEGER
);
CREATE TABLE auth_temporary_passes (
 id TEXT PRIMARY KEY,
 request_id TEXT NOT NULL UNIQUE REFERENCES auth_temporary_pass_requests(id),
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 person_version INTEGER NOT NULL,
 issuer_id TEXT NOT NULL,
 issuer_session_id TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 enrollment_session_id TEXT,
 completed_at INTEGER,
 revoked_at INTEGER
);
CREATE INDEX auth_temporary_passes_person ON auth_temporary_passes(person_id,created_at);
