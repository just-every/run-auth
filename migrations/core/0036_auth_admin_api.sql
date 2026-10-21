-- One optimistic-concurrency epoch covers native UI and REST resource writes.
CREATE TABLE auth_admin_api_epoch (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
INSERT INTO auth_admin_api_epoch(id,version) VALUES(1,1);
-- A transaction-local latch keeps a mutation's precondition fixed while its own
-- native statements advance the epoch. It is removed in the same D1 batch.
CREATE TABLE auth_admin_api_commits (id TEXT PRIMARY KEY);
CREATE TRIGGER admin_epoch_oa_operators_insert AFTER INSERT ON oa_operators
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_oa_operators_update AFTER UPDATE ON oa_operators
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_oa_operators_delete AFTER DELETE ON oa_operators
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_groups_insert AFTER INSERT ON auth_groups
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_groups_update AFTER UPDATE ON auth_groups
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_groups_delete AFTER DELETE ON auth_groups
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_members_insert AFTER INSERT ON auth_group_members
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_members_update AFTER UPDATE ON auth_group_members
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_members_delete AFTER DELETE ON auth_group_members
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_exclusions_insert AFTER INSERT ON auth_group_exclusions
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_exclusions_update AFTER UPDATE ON auth_group_exclusions
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_exclusions_delete AFTER DELETE ON auth_group_exclusions
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_owners_insert AFTER INSERT ON auth_group_owners
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_owners_update AFTER UPDATE ON auth_group_owners
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_group_owners_delete AFTER DELETE ON auth_group_owners
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_apps_insert AFTER INSERT ON auth_apps
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_apps_update AFTER UPDATE ON auth_apps
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_apps_delete AFTER DELETE ON auth_apps
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_app_assignments_insert AFTER INSERT ON auth_app_assignments
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_app_assignments_update AFTER UPDATE ON auth_app_assignments
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_app_assignments_delete AFTER DELETE ON auth_app_assignments
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_attribute_defs_insert AFTER INSERT ON auth_attribute_defs
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_attribute_defs_update AFTER UPDATE ON auth_attribute_defs
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_attribute_defs_delete AFTER DELETE ON auth_attribute_defs
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_person_fields_insert AFTER INSERT ON auth_person_fields
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_person_fields_update AFTER UPDATE ON auth_person_fields
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_person_fields_delete AFTER DELETE ON auth_person_fields
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_person_sources_insert AFTER INSERT ON auth_person_sources
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_person_sources_update AFTER UPDATE ON auth_person_sources
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_person_sources_delete AFTER DELETE ON auth_person_sources
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_people_insert AFTER INSERT ON auth_people
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_people_update AFTER UPDATE ON auth_people
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_people_delete AFTER DELETE ON auth_people
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_oa_domain_rules_insert AFTER INSERT ON oa_domain_rules
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_oa_domain_rules_update AFTER UPDATE ON oa_domain_rules
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_oa_domain_rules_delete AFTER DELETE ON oa_domain_rules
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_domains_insert AFTER INSERT ON auth_domains
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_domains_update AFTER UPDATE ON auth_domains
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_domains_delete AFTER DELETE ON auth_domains
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_mapping_versions_insert AFTER INSERT ON auth_mapping_versions
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_mapping_versions_update AFTER UPDATE ON auth_mapping_versions
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_mapping_versions_delete AFTER DELETE ON auth_mapping_versions
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_oidc_clients_insert AFTER INSERT ON auth_oidc_clients
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_oidc_clients_update AFTER UPDATE ON auth_oidc_clients
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_oidc_clients_delete AFTER DELETE ON auth_oidc_clients
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
