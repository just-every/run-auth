-- Native observations are installation-local evidence, never restored authority.
-- App references deliberately survive connector and app removal.
CREATE TABLE auth_timing_episodes (
 id TEXT PRIMARY KEY, employer_id TEXT NOT NULL, person_id TEXT NOT NULL,
 event_at INTEGER NOT NULL, local_denial_at INTEGER NOT NULL, ended_at INTEGER
);
CREATE INDEX auth_timing_period ON auth_timing_episodes(event_at,person_id);
CREATE TABLE auth_timing_apps (
 episode_id TEXT NOT NULL REFERENCES auth_timing_episodes(id) ON DELETE CASCADE,
 app_id TEXT NOT NULL, channel TEXT NOT NULL, app_name TEXT NOT NULL,
 remote_id TEXT, dispatched_at INTEGER, accepted_at INTEGER, verified_at INTEGER,
 PRIMARY KEY(episode_id,app_id,channel)
);
ALTER TABLE auth_provisioning ADD COLUMN timing_episode_id TEXT;
ALTER TABLE auth_logout_deliveries ADD COLUMN timing_episode_id TEXT;
