-- Provenance is written only after the upstream adapter verifies an OIDC response.
CREATE TABLE auth_upstream_proofs (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES oa_operators(id),
 provider_id TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL,
 configuration_hash TEXT NOT NULL, verified_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
ALTER TABLE auth_sessions ADD COLUMN upstream_proof_id TEXT;
