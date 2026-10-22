-- Endpoint-scoped RFC 9449 server nonces and registered-key proof replay state.
-- Neither raw proofs, access tokens nor the nonce value are persisted.
CREATE TABLE auth_delegation_dpop_nonces (
 nonce_hash TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL REFERENCES auth_delegated_agents(id),
 jkt TEXT NOT NULL, htu TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX auth_delegation_dpop_nonce_expiry ON auth_delegation_dpop_nonces(expires_at);
CREATE TABLE auth_delegation_dpop_proofs (
 jkt TEXT NOT NULL, jti TEXT NOT NULL,
 agent_id TEXT NOT NULL REFERENCES auth_delegated_agents(id),
 expires_at INTEGER NOT NULL, PRIMARY KEY(jkt,jti)
);
CREATE INDEX auth_delegation_dpop_proof_expiry ON auth_delegation_dpop_proofs(expires_at);
