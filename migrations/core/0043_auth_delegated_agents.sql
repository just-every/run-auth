-- Dedicated task clients deliberately live outside auth-admin-service:.
CREATE TABLE auth_delegated_agents (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL UNIQUE,
 service_app_id TEXT NOT NULL UNIQUE REFERENCES auth_admin_service_apps(id),
 name TEXT NOT NULL, registered_by TEXT NOT NULL REFERENCES oa_operators(id),
 registered_owner_version INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','suspended','revoked')) DEFAULT 'active',
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE auth_delegated_tasks (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES auth_delegated_agents(id),
 agent_revision INTEGER NOT NULL, service_revision INTEGER NOT NULL,
 organization_id TEXT NOT NULL, accountable_id TEXT NOT NULL REFERENCES oa_operators(id),
 accountable_version INTEGER NOT NULL, app_id TEXT NOT NULL REFERENCES auth_apps(id),
 app_version INTEGER NOT NULL, native_epoch INTEGER NOT NULL, role_epoch INTEGER NOT NULL,
 effect TEXT NOT NULL, effect_digest TEXT NOT NULL,
 before_role TEXT, before_created_by TEXT NOT NULL, before_created_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'requested' CHECK(state IN ('requested','consented','approved','completed','revoked','rejected')),
 revision INTEGER NOT NULL DEFAULT 1,
 consented_by TEXT, consented_at INTEGER, consent_session_id TEXT,
 approved_by TEXT, approver_version INTEGER, approved_at INTEGER, approval_session_id TEXT,
 revoked_by TEXT, revoked_at INTEGER, ended_reason TEXT,
 execution_id TEXT UNIQUE, completed_at INTEGER, last_issued_at INTEGER
);
CREATE INDEX auth_delegated_tasks_person ON auth_delegated_tasks(accountable_id,state);
CREATE INDEX auth_delegated_tasks_agent ON auth_delegated_tasks(agent_id,state);
CREATE TABLE auth_delegation_assertions (
 agent_id TEXT NOT NULL REFERENCES auth_delegated_agents(id), jti TEXT NOT NULL,
 expires_at INTEGER NOT NULL, PRIMARY KEY(agent_id,jti)
);
CREATE TRIGGER auth_delegated_effect_immutable BEFORE UPDATE OF agent_id,agent_revision,service_revision,organization_id,accountable_id,accountable_version,app_id,app_version,native_epoch,role_epoch,effect,effect_digest,before_role,before_created_by,before_created_at,created_at,expires_at ON auth_delegated_tasks
 BEGIN SELECT RAISE(ABORT,'delegation_effect_immutable'); END;
CREATE TRIGGER auth_delegated_agent_ended AFTER UPDATE OF state,revision ON auth_delegated_agents
 WHEN NEW.state!='active' OR NEW.revision!=OLD.revision
 BEGIN
  UPDATE auth_delegated_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='agent_changed'
   WHERE agent_id=NEW.id AND state IN ('requested','consented','approved');
 END;
CREATE TRIGGER auth_delegated_person_ended AFTER UPDATE OF status,version ON oa_operators
 WHEN NEW.status!='active' OR NEW.version!=OLD.version
 BEGIN
  UPDATE auth_delegated_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='person_changed'
   WHERE (accountable_id=NEW.id OR approved_by=NEW.id) AND state IN ('requested','consented','approved');
 END;
-- This task profile excludes employees with any unrevoked scoped role grant.
-- Once a grant is added, removing it cannot revive earlier task authority.
CREATE TRIGGER auth_delegated_role_added AFTER INSERT ON auth_role_grants
 WHEN NEW.revoked_at IS NULL
 BEGIN
  UPDATE auth_delegated_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='person_role_changed'
   WHERE accountable_id=NEW.person_id AND state IN ('requested','consented','approved');
 END;
CREATE TRIGGER auth_delegated_role_changed AFTER UPDATE OF person_id,revoked_at ON auth_role_grants
 WHEN NEW.revoked_at IS NULL
 BEGIN
  UPDATE auth_delegated_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='person_role_changed'
   WHERE accountable_id=NEW.person_id AND state IN ('requested','consented','approved');
 END;
-- Generic credential custody excludes this namespace. Internal lifecycle writes
-- may end its backing authority but cannot widen or repurpose it. New keys,
-- resources and lifetime require new dedicated registration and task consent.
CREATE TRIGGER auth_delegated_credential_immutable BEFORE UPDATE OF client_id,owner_id,jwks,scopes,resources,allowed_ips,expires_at ON auth_admin_service_apps
 WHEN EXISTS(SELECT 1 FROM auth_delegated_agents a WHERE a.service_app_id=OLD.id)
 BEGIN SELECT RAISE(ABORT,'delegated_credential_immutable'); END;
