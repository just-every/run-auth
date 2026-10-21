-- Registered external APIs share workforce app roles and tenant-local identity.
CREATE TABLE auth_resource_apis (
 id TEXT PRIMARY KEY,
 app_id TEXT NOT NULL REFERENCES auth_apps(id),
 name TEXT NOT NULL,
 audience TEXT NOT NULL UNIQUE,
 policy TEXT NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE INDEX auth_resource_apis_app ON auth_resource_apis(app_id);
CREATE TABLE auth_resource_services (
 id TEXT PRIMARY KEY,
 client_id TEXT NOT NULL UNIQUE,
 api_id TEXT NOT NULL REFERENCES auth_resource_apis(id),
 name TEXT NOT NULL,
 purpose TEXT NOT NULL,
 owner_id TEXT NOT NULL REFERENCES oa_operators(id),
 owner_version INTEGER NOT NULL,
 jwks TEXT NOT NULL,
 scopes TEXT NOT NULL,
 resources TEXT NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 revoked_at INTEGER,
 revoked_by TEXT,
 last_used_at INTEGER
);
CREATE INDEX auth_resource_services_owner ON auth_resource_services(owner_id);
CREATE TABLE auth_resource_assertions (
 service_id TEXT NOT NULL REFERENCES auth_resource_services(id),
 jti TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 PRIMARY KEY(service_id,jti)
);
-- Suspension/departure ends credentials permanently, even after restoration.
CREATE TRIGGER auth_resource_owner_changed AFTER UPDATE OF status,version ON oa_operators
 WHEN NEW.status!='active' OR NEW.version!=OLD.version
 BEGIN
  UPDATE auth_resource_services SET revoked_at=COALESCE(revoked_at,CAST(strftime('%s','now') AS INTEGER)*1000),
   revision=revision+1 WHERE owner_id=NEW.id AND revoked_at IS NULL;
 END;
