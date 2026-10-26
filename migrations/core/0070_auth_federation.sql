CREATE TABLE auth_federation_setups (
 id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, domain TEXT NOT NULL,
 config_hash TEXT NOT NULL, sealed_config TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('draft','testing','tested','active','disabled')),
 created_by TEXT NOT NULL REFERENCES oa_operators(id), owner_version INTEGER NOT NULL,
 test_session_id TEXT, test_binding_hash TEXT, test_until INTEGER, test_subject TEXT,
 tested_subject TEXT, tested_at INTEGER, activated_at INTEGER,
 revision INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX auth_federation_active_provider ON auth_federation_setups(provider_id) WHERE state='active';
CREATE INDEX auth_federation_pending_provider ON auth_federation_setups(provider_id,state,test_until);
CREATE TABLE auth_federation_transactions (
 id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, setup_id TEXT REFERENCES auth_federation_setups(id), configuration_hash TEXT NOT NULL,
 binding_hash TEXT NOT NULL, request_id TEXT NOT NULL, return_to TEXT NOT NULL,
 expires_at INTEGER NOT NULL, consumed_at INTEGER, verified_principal TEXT,
 verified_at INTEGER, completed_at INTEGER
);
CREATE INDEX auth_federation_transactions_expiry ON auth_federation_transactions(expires_at);
CREATE TABLE auth_federation_replays (
 provider_id TEXT NOT NULL, assertion_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY(provider_id,assertion_id)
);
CREATE INDEX auth_federation_replays_expiry ON auth_federation_replays(expires_at);
-- Representative-user OIDC discovery cannot create or replace active trust.
CREATE TABLE auth_federation_test_providers (
 setup_id TEXT NOT NULL REFERENCES auth_federation_setups(id) ON DELETE CASCADE,
 provider_id TEXT NOT NULL, preset TEXT NOT NULL, status TEXT NOT NULL,
 issuer TEXT NOT NULL, client_id TEXT NOT NULL, jwks_uri TEXT NOT NULL,
 authorization_endpoint TEXT NOT NULL, token_endpoint TEXT NOT NULL,
 algorithms TEXT NOT NULL, token_auth_method TEXT NOT NULL, response_iss INTEGER NOT NULL,
 interface_version TEXT, linked_at INTEGER NOT NULL,
 pending_issuer TEXT, pending_client_id TEXT, pending_preset TEXT, pending_at INTEGER,
 jwks TEXT, jwks_fetched_at INTEGER,
 PRIMARY KEY(setup_id,provider_id)
);
CREATE TABLE auth_federation_test_health (
 setup_id TEXT NOT NULL REFERENCES auth_federation_setups(id) ON DELETE CASCADE,
 provider_id TEXT NOT NULL, failing_since INTEGER, hard_failure_at INTEGER,
 checked_at INTEGER NOT NULL, PRIMARY KEY(setup_id,provider_id)
);
