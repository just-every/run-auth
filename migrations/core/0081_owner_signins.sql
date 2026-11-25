-- One-time owner sign-in grants minted by rer signin with the deployment's
-- Cloudflare credentials. Only the token digest is stored.
CREATE TABLE IF NOT EXISTS oa_owner_signins (
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 operator_id TEXT NOT NULL REFERENCES oa_operators(id), operator_version INTEGER NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);
