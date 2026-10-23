-- Feed credentials admit files only; they never confer directory authority.
CREATE TABLE auth_hr_feeds (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, schedule_ms INTEGER NOT NULL,
 mapping TEXT NOT NULL, fingerprint TEXT NOT NULL, token_hash TEXT,
 termination_percent INTEGER NOT NULL DEFAULT 5,
 created_by TEXT NOT NULL, owner_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
 last_received_at INTEGER, last_success_at INTEGER, disabled_at INTEGER
);
CREATE TABLE auth_hr_files (
 id TEXT PRIMARY KEY, feed_id TEXT NOT NULL REFERENCES auth_hr_feeds(id),
 digest TEXT NOT NULL, file_name TEXT NOT NULL, received_at INTEGER NOT NULL,
 transport TEXT NOT NULL, state TEXT NOT NULL, reasons TEXT NOT NULL,
 row_count INTEGER NOT NULL, UNIQUE(feed_id,digest)
);
CREATE TABLE auth_hr_file_rows (
 file_id TEXT NOT NULL REFERENCES auth_hr_files(id) ON DELETE CASCADE,
 idx INTEGER NOT NULL, source_id TEXT NOT NULL, record TEXT NOT NULL, applied_at INTEGER,
 PRIMARY KEY(file_id,idx)
);
-- Add a source kind without rebuilding existing obligation/history FKs.
-- The source binding uses an existing app_setup record; only this explicit
-- binding selects HR feed state and presentation, never arbitrary source text.
CREATE TABLE auth_hr_feed_obligations (
 obligation_id TEXT PRIMARY KEY REFERENCES auth_obligations(id) ON DELETE CASCADE,
 feed_id TEXT NOT NULL REFERENCES auth_hr_feeds(id), episode INTEGER NOT NULL,
 UNIQUE(feed_id,episode)
);
