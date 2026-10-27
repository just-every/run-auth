-- Enrollment capabilities stay local and never travel in an export.
CREATE TABLE auth_recovery_enrollments (
 case_id TEXT PRIMARY KEY REFERENCES auth_role_cases(id),
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 person_version INTEGER NOT NULL,
 issuer_id TEXT NOT NULL, issuer_session_id TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 consumed_at INTEGER, enrollment_session_id TEXT, completed_at INTEGER, cancelled_at INTEGER
);
CREATE INDEX auth_recovery_enrollments_person ON auth_recovery_enrollments(person_id,created_at);
