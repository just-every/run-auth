-- Explicit owner-authorized erasure. Journals contain one-way identifiers, not
-- recoverable profiles. Pending remote identifiers are sealed; reset destroys
-- connector credentials and signing private keys.
CREATE TABLE auth_erasure_policy (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), configured INTEGER NOT NULL DEFAULT 0,
 policy TEXT NOT NULL, updated_by TEXT, updated_at INTEGER NOT NULL
);
INSERT INTO auth_erasure_policy VALUES(1,0,'{"mode":"explicit-owner-confirmation","automaticDeletion":false,"heldData":"refuse-erasure","audit":"anonymized","remote":"separate-until-verified"}',NULL,0);
CREATE TABLE auth_erasure_holds (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL,
 reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 released_by TEXT, released_at INTEGER
);
CREATE TABLE auth_erasure_previews (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL,
 digest TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE auth_erasure_receipts (
 id TEXT PRIMARY KEY, reference TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
 actor_ref TEXT NOT NULL, created_at INTEGER NOT NULL, stores TEXT NOT NULL,
 limitations TEXT NOT NULL, decisions TEXT NOT NULL, status TEXT NOT NULL, journal TEXT NOT NULL
);
CREATE TABLE auth_erasure_journal (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
 source TEXT NOT NULL, organization TEXT NOT NULL, kind TEXT NOT NULL,
 reference TEXT NOT NULL, hashes TEXT NOT NULL, records TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_erasure_remote (
 id TEXT PRIMARY KEY, receipt_id TEXT NOT NULL REFERENCES auth_erasure_receipts(id),
 kind TEXT NOT NULL, partner TEXT NOT NULL, sealed_work TEXT,
 state TEXT NOT NULL CHECK(state IN ('pending','verified','blocked','failed')),
 attempts INTEGER NOT NULL DEFAULT 0, last_status INTEGER, last_error TEXT,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
-- The latch exists only within the same atomic D1 batch as the authorized
-- mutation. It cannot grant authority through any application public door.
CREATE TABLE auth_erasure_commits (id TEXT PRIMARY KEY, kind TEXT NOT NULL);
DROP TRIGGER oa_preserve_last_owner_delete;
CREATE TRIGGER oa_preserve_last_owner_delete BEFORE DELETE ON oa_operators
 WHEN OLD.role='owner' AND OLD.status='active'
 AND (SELECT COUNT(*) FROM oa_operators WHERE role='owner' AND status='active') <= 1
 AND NOT EXISTS(SELECT 1 FROM auth_erasure_commits WHERE kind IN ('organization','installation'))
 BEGIN SELECT RAISE(ABORT, 'last_owner'); END;
