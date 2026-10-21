ALTER TABLE auth_apps ADD COLUMN mapping_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE auth_mapping_versions (
 app_id TEXT NOT NULL REFERENCES auth_apps(id),
 version INTEGER NOT NULL,
 program TEXT NOT NULL,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 rolled_back_from INTEGER,
 PRIMARY KEY(app_id,version)
);
