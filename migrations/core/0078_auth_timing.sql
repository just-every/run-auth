-- Native observations are installation-local evidence, never restored authority.
-- App references deliberately survive connector and app removal.
CREATE TABLE auth_timing_episodes (
 id TEXT PRIMARY KEY, employer_id TEXT NOT NULL, person_id TEXT NOT NULL,
 event_at INTEGER NOT NULL, local_denial_at INTEGER NOT NULL, ended_at INTEGER,
 inventory_complete INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX auth_timing_period ON auth_timing_episodes(event_at,person_id);
CREATE TABLE auth_timing_apps (
 episode_id TEXT NOT NULL REFERENCES auth_timing_episodes(id) ON DELETE CASCADE,
 app_id TEXT NOT NULL, channel TEXT NOT NULL, app_name TEXT NOT NULL,
 remote_id TEXT, dispatched_at INTEGER, accepted_at INTEGER, verified_at INTEGER,
 connector_retired INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(episode_id,app_id,channel)
);
CREATE TABLE auth_timing_work (
 work_id TEXT NOT NULL, channel TEXT NOT NULL,
 episode_id TEXT NOT NULL REFERENCES auth_timing_episodes(id) ON DELETE CASCADE,
 PRIMARY KEY(work_id,channel)
);
CREATE TRIGGER auth_timing_inventory_erased AFTER DELETE ON auth_timing_apps
 BEGIN UPDATE auth_timing_episodes SET inventory_complete=0 WHERE id=OLD.episode_id; END;
CREATE TRIGGER auth_timing_connector_removed AFTER DELETE ON auth_scim_connectors
 BEGIN UPDATE auth_timing_apps SET connector_retired=1 WHERE app_id=OLD.app_id
  AND (channel='scim' OR channel LIKE 'scim-group:%') AND verified_at IS NULL; END;
CREATE TRIGGER auth_timing_connector_replaced AFTER UPDATE OF base_url ON auth_scim_connectors
 WHEN OLD.base_url!=NEW.base_url
 BEGIN UPDATE auth_timing_apps SET connector_retired=1 WHERE app_id=OLD.app_id
  AND (channel='scim' OR channel LIKE 'scim-group:%') AND verified_at IS NULL; END;
