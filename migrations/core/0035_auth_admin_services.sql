-- Machine administration is a separate OAuth namespace, never a person/session.
CREATE TABLE auth_admin_service_apps (
 id TEXT PRIMARY KEY,
 client_id TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 purpose TEXT NOT NULL,
 owner_id TEXT NOT NULL,
 jwks TEXT NOT NULL,
 scopes TEXT NOT NULL,
 resources TEXT NOT NULL,
 allowed_ips TEXT NOT NULL DEFAULT '[]',
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 revoked_at INTEGER,
 revoked_by TEXT,
 suspended_at INTEGER,
 suspension_reason TEXT,
 last_used_at INTEGER
);
CREATE INDEX auth_admin_service_owner ON auth_admin_service_apps(owner_id);
CREATE TABLE auth_admin_service_assertions (
 service_app_id TEXT NOT NULL REFERENCES auth_admin_service_apps(id),
 jti TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 PRIMARY KEY(service_app_id,jti)
);
-- Losing accountable human authority persists even when a role/status is restored.
-- A human reassignment is the only operation that clears the suspension.
CREATE TRIGGER auth_admin_service_owner_changed AFTER UPDATE OF status,role ON oa_operators
 WHEN NEW.status!='active' OR NEW.role NOT IN ('owner','admin')
 BEGIN
  UPDATE auth_admin_service_apps SET suspended_at=COALESCE(suspended_at,CAST(strftime('%s','now') AS INTEGER)*1000),
   suspension_reason=COALESCE(suspension_reason,CASE WHEN NEW.status!='active' THEN 'owner_suspended' ELSE 'owner_demoted' END),
   revision=revision+1
  WHERE owner_id=NEW.id AND suspended_at IS NULL AND revoked_at IS NULL;
 END;
CREATE TRIGGER auth_admin_service_owner_deleted BEFORE DELETE ON oa_operators
 BEGIN
  UPDATE auth_admin_service_apps SET suspended_at=COALESCE(suspended_at,CAST(strftime('%s','now') AS INTEGER)*1000),
   suspension_reason=COALESCE(suspension_reason,'owner_departed'),revision=revision+1
  WHERE owner_id=OLD.id AND suspended_at IS NULL AND revoked_at IS NULL;
 END;
