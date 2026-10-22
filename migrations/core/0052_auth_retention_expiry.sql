-- Anonymous authenticated expiry commitments distinguish policy deletion from
-- tampering when an earlier erasure receipt committed to a retained audit row.
CREATE TABLE auth_retention_expiry (
 id TEXT PRIMARY KEY, table_name TEXT NOT NULL, digest TEXT NOT NULL,
 run_id TEXT NOT NULL, expired_at INTEGER NOT NULL, issuer TEXT NOT NULL,
 signature TEXT NOT NULL
);
CREATE INDEX auth_retention_expiry_digest ON auth_retention_expiry(table_name,digest);
