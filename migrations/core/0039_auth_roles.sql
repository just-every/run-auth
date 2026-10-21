-- Scoped human administration is independent of oa_operators.role. No scoped
-- grant upgrades the legacy owner/admin/member column or an old admin door.
CREATE TABLE auth_role_epoch (id INTEGER PRIMARY KEY CHECK(id=1), epoch INTEGER NOT NULL);
INSERT INTO auth_role_epoch(id,epoch) VALUES(1,1);
CREATE TABLE auth_roles (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, rank INTEGER NOT NULL CHECK(rank>0 AND rank<90),
 permissions TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE auth_role_grants (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES oa_operators(id), role_id TEXT NOT NULL,
 role_revision INTEGER NOT NULL, resources TEXT NOT NULL,
 granted_by TEXT NOT NULL REFERENCES oa_operators(id), sponsor_grant_id TEXT REFERENCES auth_role_grants(id),
 created_at INTEGER NOT NULL, revoked_at INTEGER, revoked_by TEXT
);
CREATE INDEX auth_role_grants_person ON auth_role_grants(person_id,revoked_at);
CREATE INDEX auth_role_grants_sponsor ON auth_role_grants(sponsor_grant_id);
CREATE TABLE auth_role_previews (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, session_id TEXT NOT NULL,
 epoch INTEGER NOT NULL, plan TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 consumed_at INTEGER, operation_id TEXT
);
CREATE TABLE auth_role_cases (
 id TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES oa_operators(id),
 reason TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','verified','closed')),
 opened_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 verification TEXT, verified_by TEXT, verified_session_id TEXT
);
CREATE INDEX auth_role_cases_person ON auth_role_cases(person_id,state);
-- The first statement of every scoped write claims an operation under live
-- session, email, role, grant and directory authority. Later statements use
-- this unpredictable marker in the same D1 transaction, so triggers changing
-- the epoch during our own write cannot cause partially applied operations.
CREATE TABLE auth_role_operations (
 id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, session_id TEXT NOT NULL,
 permission TEXT NOT NULL, subject_id TEXT, detail TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_role_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL UNIQUE REFERENCES auth_role_operations(id),
 actor_id TEXT NOT NULL, session_id TEXT NOT NULL, event TEXT NOT NULL,
 subject_id TEXT, detail TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TRIGGER auth_roles_epoch_auth_roles_insert AFTER INSERT ON auth_roles
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_roles_update AFTER UPDATE ON auth_roles
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_roles_delete AFTER DELETE ON auth_roles
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_role_grants_insert AFTER INSERT ON auth_role_grants
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_role_grants_update AFTER UPDATE ON auth_role_grants
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_role_grants_delete AFTER DELETE ON auth_role_grants
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_role_cases_insert AFTER INSERT ON auth_role_cases
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_role_cases_update AFTER UPDATE ON auth_role_cases
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_role_cases_delete AFTER DELETE ON auth_role_cases
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_oa_operators_insert AFTER INSERT ON oa_operators
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_oa_operators_update AFTER UPDATE ON oa_operators
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_oa_operators_delete AFTER DELETE ON oa_operators
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_groups_insert AFTER INSERT ON auth_groups
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_groups_update AFTER UPDATE ON auth_groups
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_groups_delete AFTER DELETE ON auth_groups
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_members_insert AFTER INSERT ON auth_group_members
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_members_update AFTER UPDATE ON auth_group_members
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_members_delete AFTER DELETE ON auth_group_members
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_exclusions_insert AFTER INSERT ON auth_group_exclusions
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_exclusions_update AFTER UPDATE ON auth_group_exclusions
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_exclusions_delete AFTER DELETE ON auth_group_exclusions
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_owners_insert AFTER INSERT ON auth_group_owners
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_owners_update AFTER UPDATE ON auth_group_owners
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_group_owners_delete AFTER DELETE ON auth_group_owners
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_attribute_defs_insert AFTER INSERT ON auth_attribute_defs
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_attribute_defs_update AFTER UPDATE ON auth_attribute_defs
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_attribute_defs_delete AFTER DELETE ON auth_attribute_defs
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_person_fields_insert AFTER INSERT ON auth_person_fields
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_person_fields_update AFTER UPDATE ON auth_person_fields
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_person_fields_delete AFTER DELETE ON auth_person_fields
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_apps_insert AFTER INSERT ON auth_apps
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_apps_update AFTER UPDATE ON auth_apps
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_apps_delete AFTER DELETE ON auth_apps
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_recoveries_insert AFTER INSERT ON auth_recoveries
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_recoveries_update AFTER UPDATE ON auth_recoveries
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_recoveries_delete AFTER DELETE ON auth_recoveries
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_passkeys_insert AFTER INSERT ON auth_passkeys
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_passkeys_update AFTER UPDATE ON auth_passkeys
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_passkeys_delete AFTER DELETE ON auth_passkeys
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_oidc_clients_insert AFTER INSERT ON auth_oidc_clients
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_oidc_clients_update AFTER UPDATE ON auth_oidc_clients
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_oidc_clients_delete AFTER DELETE ON auth_oidc_clients
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_oidc_secrets_insert AFTER INSERT ON auth_oidc_secrets
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_oidc_secrets_update AFTER UPDATE ON auth_oidc_secrets
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_oidc_secrets_delete AFTER DELETE ON auth_oidc_secrets
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_app_assignments_insert AFTER INSERT ON auth_app_assignments
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_app_assignments_update AFTER UPDATE ON auth_app_assignments
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_app_assignments_delete AFTER DELETE ON auth_app_assignments
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_scim_connectors_insert AFTER INSERT ON auth_scim_connectors
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_scim_connectors_update AFTER UPDATE ON auth_scim_connectors
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_scim_connectors_delete AFTER DELETE ON auth_scim_connectors
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_oa_domain_rules_insert AFTER INSERT ON oa_domain_rules
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_oa_domain_rules_update AFTER UPDATE ON oa_domain_rules
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_oa_domain_rules_delete AFTER DELETE ON oa_domain_rules
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_provider_states_insert AFTER INSERT ON auth_provider_states
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_provider_states_update AFTER UPDATE ON auth_provider_states
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_provider_states_delete AFTER DELETE ON auth_provider_states
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_admin_service_apps_insert AFTER INSERT ON auth_admin_service_apps
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_admin_service_apps_update AFTER UPDATE ON auth_admin_service_apps
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_roles_epoch_auth_admin_service_apps_delete AFTER DELETE ON auth_admin_service_apps
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
