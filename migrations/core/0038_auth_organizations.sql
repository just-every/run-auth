-- The original installation keeps its existing tables. Organizations receive
-- separate physical tables; this registry is global and is never cloned.
CREATE TABLE auth_organizations (
 id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=32 AND id NOT GLOB '*[^0-9a-f]*'),
 name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 200),
 namespace TEXT NOT NULL UNIQUE CHECK(namespace='org_' || id || '_'),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','active','erased'))
);

CREATE TABLE auth_org_invitations (
 person_id TEXT PRIMARY KEY REFERENCES oa_operators(id),
 expires_at INTEGER NOT NULL,
 cancelled_at INTEGER,
 created_by TEXT NOT NULL
);

CREATE TRIGGER auth_org_invitation_created AFTER INSERT ON oa_operators
WHEN NEW.status='invited'
BEGIN
 INSERT OR IGNORE INTO auth_org_invitations(person_id,expires_at,cancelled_at,created_by)
 VALUES(NEW.id,NEW.created_at+604800000,NULL,NEW.id);
END;

CREATE TRIGGER auth_org_invitation_cancelled AFTER UPDATE OF status ON oa_operators
WHEN OLD.status='invited' AND NEW.status='inactive'
BEGIN
 UPDATE auth_org_invitations SET cancelled_at=unixepoch()*1000 WHERE person_id=NEW.id AND cancelled_at IS NULL;
END;
