-- Company apps that sign in with OpenID Connect (the general SaaS profile,
-- kept apart from RER clients). For these apps the SAML columns of auth_apps
-- hold inert defaults and entity_id holds 'oidc:' and the client ID.
ALTER TABLE auth_apps ADD COLUMN protocol TEXT NOT NULL DEFAULT 'saml' CHECK(protocol IN ('saml','oidc'));
CREATE TABLE auth_oidc_clients (
 app_id TEXT PRIMARY KEY REFERENCES auth_apps(id), client_id TEXT NOT NULL UNIQUE,
 auth_method TEXT NOT NULL CHECK(auth_method IN ('client_secret_basic','client_secret_post','private_key_jwt','none')),
 jwks TEXT, redirect_uris TEXT NOT NULL, post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
 require_pkce INTEGER NOT NULL, subject_type TEXT NOT NULL CHECK(subject_type IN ('public','pairwise')),
 legacy_flows INTEGER NOT NULL DEFAULT 0, frontchannel_logout_uri TEXT, backchannel_logout_uri TEXT,
 id_token_alg TEXT NOT NULL CHECK(id_token_alg IN ('ES256','RS256'))
);
-- Client secrets: only a digest. A rotated-out secret keeps working until expires_at.
CREATE TABLE auth_oidc_secrets (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE,
 created_at INTEGER NOT NULL, expires_at INTEGER
);
CREATE INDEX auth_oidc_secrets_client ON auth_oidc_secrets(client_id);
CREATE TABLE auth_oidc_codes (
 code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, person_id TEXT NOT NULL, session_id TEXT NOT NULL,
 redirect_uri TEXT NOT NULL, challenge TEXT, nonce TEXT, scopes TEXT NOT NULL, expires_at INTEGER NOT NULL
);
-- Which OIDC apps an Auth session signed in to, for front- and back-channel logout.
CREATE TABLE auth_oidc_sessions (session_id TEXT NOT NULL, client_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(session_id, client_id));
CREATE TABLE auth_oidc_logouts (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL, person_id TEXT NOT NULL, sid TEXT NOT NULL, jti TEXT NOT NULL UNIQUE,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, created_at INTEGER NOT NULL, finished_at INTEGER, outcome TEXT
);
