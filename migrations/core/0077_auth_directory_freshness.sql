-- Source liveness is independent of a snapshot digest and its human approval.
ALTER TABLE auth_directory_sources ADD COLUMN observation_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE auth_directory_sources ADD COLUMN last_failure_at INTEGER;
CREATE TABLE auth_directory_source_obligations (
 obligation_id TEXT PRIMARY KEY REFERENCES auth_obligations(id) ON DELETE CASCADE,
 source_id TEXT NOT NULL REFERENCES auth_directory_sources(id),
 episode INTEGER NOT NULL,
 UNIQUE(source_id,episode)
);
