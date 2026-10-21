-- Revocation is mandatory; deleting independently held data requires exact
-- destination consent. Abandonment destroys unfinished sealed work without
-- claiming that remote deletion or revocation completed.
ALTER TABLE auth_erasure_remote ADD COLUMN consented_at INTEGER;
ALTER TABLE auth_erasure_remote ADD COLUMN abandoned_at INTEGER;
ALTER TABLE auth_erasure_remote ADD COLUMN app_label TEXT NOT NULL DEFAULT 'Connected app';
CREATE TABLE auth_erasure_reset_consents (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, actor_version INTEGER NOT NULL,
 remote_digest TEXT NOT NULL, destinations TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
