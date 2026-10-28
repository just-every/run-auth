-- Nonsecret SAML settings only. Provider credentials and assignments retain
-- their own custody and cannot be restored from a configuration revision.
CREATE TABLE auth_app_revisions (
 app_id TEXT NOT NULL REFERENCES auth_apps(id) ON DELETE CASCADE,
 version INTEGER NOT NULL,
 configuration TEXT NOT NULL,
 created_by TEXT,
 created_at INTEGER NOT NULL,
 rolled_back_from INTEGER,
 preview_id TEXT UNIQUE,
 PRIMARY KEY(app_id,version)
);
