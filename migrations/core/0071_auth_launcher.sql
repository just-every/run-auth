-- Bookmarks are links only; they never become protocol clients.
CREATE TABLE auth_launcher_bookmarks (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, icon TEXT NOT NULL,
 group_id TEXT NOT NULL REFERENCES auth_groups(id) ON DELETE CASCADE,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_launcher_preferences (
 person_id TEXT NOT NULL REFERENCES oa_operators(id) ON DELETE CASCADE,
 tile_id TEXT NOT NULL, favorite INTEGER NOT NULL DEFAULT 0, last_used_at INTEGER,
 PRIMARY KEY(person_id,tile_id)
);
