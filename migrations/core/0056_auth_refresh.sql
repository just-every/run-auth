-- Offline authority is explicit and never portable or a browser session.
CREATE TABLE auth_refresh_profiles (
 client_id TEXT PRIMARY KEY REFERENCES auth_oidc_clients(client_id) ON DELETE CASCADE,
 api_id TEXT NOT NULL REFERENCES auth_resource_apis(id) ON DELETE CASCADE,
 scopes TEXT NOT NULL, idle_ms INTEGER NOT NULL, absolute_ms INTEGER NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_refresh_consents (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL, person_id TEXT NOT NULL,
 session_id TEXT NOT NULL, person_version INTEGER NOT NULL, profile_revision INTEGER NOT NULL,
 api_revision INTEGER NOT NULL, app_version INTEGER NOT NULL,
 redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, nonce TEXT, state TEXT,
 scopes TEXT NOT NULL, api_scopes TEXT NOT NULL, jkt TEXT NOT NULL, device_name TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, approved_at INTEGER, decided_at INTEGER
);
ALTER TABLE auth_oidc_codes ADD COLUMN refresh_consent_id TEXT;
CREATE TABLE auth_refresh_families (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES auth_oidc_clients(client_id) ON DELETE CASCADE,
 api_id TEXT NOT NULL REFERENCES auth_resource_apis(id) ON DELETE CASCADE,
 person_id TEXT NOT NULL REFERENCES oa_operators(id) ON DELETE CASCADE,
 person_version INTEGER NOT NULL, session_id TEXT NOT NULL,
 profile_revision INTEGER NOT NULL, api_revision INTEGER NOT NULL, app_version INTEGER NOT NULL,
 scopes TEXT NOT NULL, jkt TEXT NOT NULL, device_name TEXT NOT NULL,
 current_hash TEXT, generation INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
 idle_expires_at INTEGER NOT NULL, absolute_expires_at INTEGER NOT NULL,
 revoked_at INTEGER, reason TEXT, logout_queued_at INTEGER
);
CREATE INDEX auth_refresh_person ON auth_refresh_families(person_id,created_at);
CREATE TABLE auth_refresh_credentials (
 token_hash TEXT PRIMARY KEY, family_id TEXT NOT NULL REFERENCES auth_refresh_families(id) ON DELETE CASCADE,
 generation INTEGER NOT NULL, created_at INTEGER NOT NULL, consumed_at INTEGER,
 UNIQUE(family_id,generation)
);
CREATE TABLE auth_refresh_proofs (
 jkt TEXT NOT NULL, jti TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(jkt,jti)
);
