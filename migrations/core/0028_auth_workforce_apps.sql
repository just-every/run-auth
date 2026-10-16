-- Workforce apps: groups, company (SAML) apps and who is assigned to them.
CREATE TABLE auth_groups (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_group_members (
 group_id TEXT NOT NULL REFERENCES auth_groups(id), person_id TEXT NOT NULL REFERENCES oa_operators(id),
 added_by TEXT NOT NULL, added_at INTEGER NOT NULL, PRIMARY KEY(group_id, person_id)
);
CREATE INDEX auth_group_members_person ON auth_group_members(person_id);

-- One company app; its SAML settings live on the row, its catalog recipe (if
-- any) is named, and version counts every configuration change.
CREATE TABLE auth_apps (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, recipe TEXT, launch_url TEXT,
 entity_id TEXT NOT NULL UNIQUE, acs TEXT NOT NULL, slo TEXT,
 sp_certificates TEXT NOT NULL DEFAULT '[]', encryption_certificate TEXT,
 name_id_format TEXT NOT NULL, name_id_source TEXT CHECK(name_id_source IN ('person_id','email')), sign TEXT NOT NULL CHECK(sign IN ('response','assertion','both')),
 digest TEXT NOT NULL CHECK(digest IN ('sha256','sha512','sha1')), sha1_exception INTEGER NOT NULL DEFAULT 0,
 encryption TEXT CHECK(encryption IN ('aes256-gcm','aes128-cbc')), want_requests_signed INTEGER NOT NULL DEFAULT 0,
 idp_initiated INTEGER NOT NULL DEFAULT 0, relay_state TEXT, attributes TEXT NOT NULL DEFAULT '[]',
 version INTEGER NOT NULL DEFAULT 1, created_by TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 disabled_at INTEGER
);
CREATE TABLE auth_app_assignments (
 app_id TEXT NOT NULL REFERENCES auth_apps(id), principal_type TEXT NOT NULL CHECK(principal_type IN ('person','group')),
 principal_id TEXT NOT NULL, role TEXT, created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 PRIMARY KEY(app_id, principal_type, principal_id)
);

-- SAML signing certificates: next (published, not yet signing), active,
-- previous (still published) and retired.
CREATE TABLE auth_saml_keys (
 kid TEXT PRIMARY KEY, certificate TEXT NOT NULL, encrypted_private TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('next','active','previous','retired')),
 created_at INTEGER NOT NULL, activated_at INTEGER, retired_at INTEGER
);
CREATE UNIQUE INDEX auth_saml_keys_one_active ON auth_saml_keys(state) WHERE state='active';
-- Request IDs already answered, so a captured request cannot be replayed.
CREATE TABLE auth_saml_requests (app_id TEXT NOT NULL, request_id TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(app_id, request_id));
-- Which apps an Auth session signed in through SAML, for single logout.
CREATE TABLE auth_saml_sessions (
 session_id TEXT NOT NULL, app_id TEXT NOT NULL, name_id TEXT NOT NULL, name_id_format TEXT NOT NULL,
 session_index TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, ended_at INTEGER,
 PRIMARY KEY(session_id, app_id)
);
-- A single logout in progress: apps still to visit, the one awaiting a
-- response (matched by its request ID), and the app (if any) that asked.
CREATE TABLE auth_saml_logouts (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL, pending TEXT NOT NULL,
 awaiting_app TEXT, awaiting_request TEXT, origin_app TEXT, origin_request TEXT, origin_relay TEXT,
 expires_at INTEGER NOT NULL
);

-- Outbound provisioning (SCIM 2.0). The bearer credential is sealed under
-- AUTH_ENCRYPTION_KEY and never returned.
CREATE TABLE auth_scim_connectors (
 app_id TEXT PRIMARY KEY REFERENCES auth_apps(id), base_url TEXT NOT NULL, sealed_token TEXT NOT NULL,
 deprovision TEXT NOT NULL CHECK(deprovision IN ('deactivate','delete')), push_groups INTEGER NOT NULL DEFAULT 0,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL, rotated_at INTEGER, last_success_at INTEGER, last_error TEXT,
 last_reconciled_at INTEGER
);
-- The remote account Auth manages for a person (or the remote group for a group).
CREATE TABLE auth_scim_accounts (
 app_id TEXT NOT NULL, subject_type TEXT NOT NULL CHECK(subject_type IN ('person','group')), subject_id TEXT NOT NULL,
 remote_id TEXT NOT NULL, state TEXT NOT NULL, updated_at INTEGER NOT NULL,
 PRIMARY KEY(app_id, subject_type, subject_id)
);
-- One open obligation per app and subject: what Auth still has to make true
-- remotely, with event, dispatch and remote-verified times.
CREATE TABLE auth_provisioning (
 id TEXT PRIMARY KEY, app_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
 reason TEXT NOT NULL, event_at INTEGER NOT NULL, dispatched_at INTEGER, verified_at INTEGER,
 operation TEXT, state TEXT NOT NULL CHECK(state IN ('pending','verified','failed','blocked','superseded')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL, last_status INTEGER, last_error TEXT,
 claimed_until INTEGER
);
CREATE UNIQUE INDEX auth_provisioning_open ON auth_provisioning(app_id, subject_type, subject_id) WHERE state IN ('pending','failed','blocked');
CREATE INDEX auth_provisioning_due ON auth_provisioning(state, next_attempt_at);
