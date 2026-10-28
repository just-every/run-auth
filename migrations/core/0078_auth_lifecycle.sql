-- Native leaver plans and their exact existing work; installation custody only.
CREATE TABLE auth_lifecycle_epoch (id INTEGER PRIMARY KEY CHECK(id=1), epoch INTEGER NOT NULL);
INSERT INTO auth_lifecycle_epoch VALUES(1,1);
CREATE TABLE auth_lifecycle_person_epoch (person_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE auth_lifecycle_plans (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES oa_operators(id),
 actor_id TEXT NOT NULL, custodian_id TEXT NOT NULL, preview_digest TEXT NOT NULL,
 plan TEXT NOT NULL, created_at INTEGER NOT NULL, denial_at INTEGER NOT NULL
);
CREATE INDEX auth_lifecycle_person ON auth_lifecycle_plans(person_id,created_at);
CREATE TABLE auth_lifecycle_steps (
 id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES auth_lifecycle_plans(id) ON DELETE CASCADE,
 person_id TEXT NOT NULL, app_id TEXT, app_label TEXT NOT NULL, kind TEXT NOT NULL,
 work_id TEXT, binding TEXT, operation TEXT, deadline_at INTEGER, escalate_at INTEGER,
 state TEXT NOT NULL DEFAULT 'unstarted', outcome TEXT, dispatched_at INTEGER, verified_at INTEGER
);
CREATE INDEX auth_lifecycle_work ON auth_lifecycle_steps(kind,work_id);
ALTER TABLE auth_logout_deliveries ADD COLUMN claimed_until INTEGER;
ALTER TABLE auth_oidc_logouts ADD COLUMN claimed_until INTEGER;
CREATE TRIGGER lifecycle_auth_apps_insert AFTER INSERT ON auth_apps BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_apps_update AFTER UPDATE ON auth_apps BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_apps_delete AFTER DELETE ON auth_apps BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_app_assignments_insert AFTER INSERT ON auth_app_assignments BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_app_assignments_update AFTER UPDATE ON auth_app_assignments BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_app_assignments_delete AFTER DELETE ON auth_app_assignments BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_scim_connectors_insert AFTER INSERT ON auth_scim_connectors BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_scim_connectors_update AFTER UPDATE OF base_url,sealed_token,deprovision,push_groups ON auth_scim_connectors BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_scim_connectors_delete AFTER DELETE ON auth_scim_connectors BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_clients_insert AFTER INSERT ON auth_clients BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_clients_update AFTER UPDATE ON auth_clients BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_clients_delete AFTER DELETE ON auth_clients BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_oidc_clients_insert AFTER INSERT ON auth_oidc_clients BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_oidc_clients_update AFTER UPDATE ON auth_oidc_clients BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_oidc_clients_delete AFTER DELETE ON auth_oidc_clients BEGIN
 INSERT INTO auth_lifecycle_epoch(id,epoch) VALUES(1,1) ON CONFLICT(id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_oa_operators_insert AFTER INSERT ON oa_operators BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_oa_operators_update AFTER UPDATE ON oa_operators BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_oa_operators_delete AFTER DELETE ON oa_operators BEGIN
 DELETE FROM auth_lifecycle_person_epoch WHERE person_id=OLD.id;
END;
CREATE TRIGGER lifecycle_auth_people_insert AFTER INSERT ON auth_people BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_people_update AFTER UPDATE ON auth_people BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_people_delete AFTER DELETE ON auth_people BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_group_members_insert AFTER INSERT ON auth_group_members BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_group_members_update AFTER UPDATE ON auth_group_members BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_group_members_delete AFTER DELETE ON auth_group_members BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_person_fields_insert AFTER INSERT ON auth_person_fields BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_person_fields_update AFTER UPDATE ON auth_person_fields BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_person_fields_delete AFTER DELETE ON auth_person_fields BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_scim_accounts_insert AFTER INSERT ON auth_scim_accounts BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.subject_id,1 WHERE NEW.subject_type='person' ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_scim_accounts_update AFTER UPDATE ON auth_scim_accounts BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.subject_id,1 WHERE OLD.subject_type='person' ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.subject_id,1 WHERE NEW.subject_type='person' ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_scim_accounts_delete AFTER DELETE ON auth_scim_accounts BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.subject_id,1 WHERE OLD.subject_type='person' ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_grants_insert AFTER INSERT ON auth_grants BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_grants_update AFTER UPDATE ON auth_grants BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_grants_delete AFTER DELETE ON auth_grants BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_refresh_families_insert AFTER INSERT ON auth_refresh_families BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_refresh_families_update AFTER UPDATE ON auth_refresh_families BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT NEW.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_refresh_families_delete AFTER DELETE ON auth_refresh_families BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT OLD.person_id,1 WHERE 1 ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_oidc_sessions_insert AFTER INSERT ON auth_oidc_sessions BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=NEW.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_oidc_sessions_update AFTER UPDATE ON auth_oidc_sessions BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=OLD.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=NEW.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_oidc_sessions_delete AFTER DELETE ON auth_oidc_sessions BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=OLD.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_saml_sessions_insert AFTER INSERT ON auth_saml_sessions BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=NEW.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_saml_sessions_update AFTER UPDATE ON auth_saml_sessions BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=OLD.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=NEW.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
CREATE TRIGGER lifecycle_auth_saml_sessions_delete AFTER DELETE ON auth_saml_sessions BEGIN
 INSERT INTO auth_lifecycle_person_epoch(person_id,epoch) SELECT person_id,1 FROM auth_sessions WHERE id=OLD.session_id ON CONFLICT(person_id) DO UPDATE SET epoch=epoch+1;
END;
