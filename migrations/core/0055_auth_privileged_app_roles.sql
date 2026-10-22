CREATE TABLE auth_privileged_app_roles (
 app_id TEXT NOT NULL, role TEXT NOT NULL, privileged INTEGER NOT NULL CHECK(privileged IN (0,1)),
 marked_by TEXT NOT NULL, marked_at INTEGER NOT NULL, PRIMARY KEY(app_id,role)
);
CREATE TRIGGER auth_privileged_role_insert AFTER INSERT ON auth_privileged_app_roles
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_privileged_role_update AFTER UPDATE ON auth_privileged_app_roles
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_privileged_role_delete AFTER DELETE ON auth_privileged_app_roles
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_request_insert AFTER INSERT ON auth_access_requests
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
