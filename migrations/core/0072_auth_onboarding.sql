CREATE TABLE auth_onboarding (
 person_id TEXT PRIMARY KEY REFERENCES oa_operators(id),
 personal_email TEXT NOT NULL,
 personal_verified_at INTEGER,
 start_at INTEGER NOT NULL,
 start_local TEXT NOT NULL,
 time_zone TEXT NOT NULL,
 lead_days INTEGER NOT NULL CHECK(lead_days BETWEEN 0 AND 30),
 generation INTEGER NOT NULL DEFAULT 1,
 token_hash TEXT,
 expires_at INTEGER,
 dispatched_at INTEGER,
 consumed_at INTEGER,
 rescinded_at INTEGER,
 created_at INTEGER NOT NULL
);
ALTER TABLE auth_emails ADD COLUMN proof_kind TEXT NOT NULL DEFAULT 'work';
