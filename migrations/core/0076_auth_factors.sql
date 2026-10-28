-- Factor secrets remain installation-local and are excluded from archives.
CREATE TABLE auth_totp_factors (
 id TEXT PRIMARY KEY,
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 sealed_secret TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 confirmed_at INTEGER,
 last_step INTEGER NOT NULL DEFAULT -1
);
CREATE UNIQUE INDEX auth_totp_confirmed ON auth_totp_factors(person_id) WHERE confirmed_at IS NOT NULL;
CREATE TABLE auth_factor_proofs (
 session_id TEXT PRIMARY KEY REFERENCES auth_sessions(id),
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 factor_id TEXT NOT NULL,
 verified_at INTEGER NOT NULL
);
CREATE TABLE auth_factor_operations (
 id TEXT PRIMARY KEY,
 person_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 kind TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE auth_person_recovery_codes (
 code_hash TEXT PRIMARY KEY,
 person_id TEXT NOT NULL REFERENCES oa_operators(id),
 created_at INTEGER NOT NULL,
 consumed_at INTEGER
);
CREATE TABLE auth_factor_policies (
 app_id TEXT PRIMARY KEY,
 method TEXT NOT NULL CHECK(method IN ('passkey','passkey_or_totp')),
 max_age_seconds INTEGER NOT NULL,
 revision TEXT NOT NULL
);

CREATE TRIGGER auth_factors_version AFTER UPDATE OF version ON oa_operators
WHEN NEW.version<>OLD.version
BEGIN
 DELETE FROM auth_totp_factors WHERE person_id=NEW.id;
 DELETE FROM auth_person_recovery_codes WHERE person_id=NEW.id;
 DELETE FROM auth_factor_proofs WHERE person_id=NEW.id;
END;
