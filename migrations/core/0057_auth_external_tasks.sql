-- Resource custody is local and must be explicitly registered at a new install.
CREATE TABLE auth_delegation_resources (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('mcp','api')), audience TEXT NOT NULL UNIQUE,
 scopes TEXT NOT NULL, detail_type TEXT NOT NULL, operations TEXT NOT NULL, jwks TEXT NOT NULL,
 registered_by TEXT NOT NULL REFERENCES oa_operators(id), owner_version INTEGER NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, disabled_at INTEGER
);
CREATE TABLE auth_delegation_agent_resources (
 agent_id TEXT NOT NULL REFERENCES auth_delegated_agents(id), resource_id TEXT NOT NULL REFERENCES auth_delegation_resources(id),
 PRIMARY KEY(agent_id,resource_id)
);
CREATE TABLE auth_delegation_resource_assertions (
 resource_id TEXT NOT NULL REFERENCES auth_delegation_resources(id), jti TEXT NOT NULL,
 expires_at INTEGER NOT NULL, PRIMARY KEY(resource_id,jti)
);
CREATE TABLE auth_external_tasks (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES auth_delegated_agents(id),
 agent_revision INTEGER NOT NULL, service_revision INTEGER NOT NULL,
 organization_id TEXT NOT NULL, accountable_id TEXT NOT NULL REFERENCES oa_operators(id),
 accountable_version INTEGER NOT NULL, app_id TEXT REFERENCES auth_apps(id),
 resource_id TEXT NOT NULL REFERENCES auth_delegation_resources(id), resource_version INTEGER NOT NULL,
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

CREATE INDEX auth_external_tasks_person ON auth_external_tasks(accountable_id,state);
CREATE INDEX auth_external_tasks_resource ON auth_external_tasks(resource_id,state);
CREATE TRIGGER auth_external_effect_immutable BEFORE UPDATE OF resource_id,resource_version,agent_id,agent_revision,service_revision,organization_id,accountable_id,accountable_version,app_id,app_version,native_epoch,role_epoch,effect,effect_digest,before_role,before_created_by,before_created_at,created_at,expires_at ON auth_external_tasks
 BEGIN SELECT RAISE(ABORT,'delegation_effect_immutable'); END;
CREATE TRIGGER auth_external_agent_ended AFTER UPDATE OF state,revision ON auth_delegated_agents
 WHEN NEW.state!='active' OR NEW.revision!=OLD.revision
 BEGIN
  UPDATE auth_external_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='agent_changed'
   WHERE agent_id=NEW.id AND state IN ('requested','consented','approved');
 END;
CREATE TRIGGER auth_external_person_ended AFTER UPDATE OF status,version ON oa_operators
 WHEN NEW.status!='active' OR NEW.version!=OLD.version
 BEGIN
  UPDATE auth_external_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='person_changed'
   WHERE (accountable_id=NEW.id OR approved_by=NEW.id) AND state IN ('requested','consented','approved');
 END;
-- This task profile excludes employees with any unrevoked scoped role grant.
-- Once a grant is added, removing it cannot revive earlier task authority.
CREATE TRIGGER auth_external_role_added AFTER INSERT ON auth_role_grants
 WHEN NEW.revoked_at IS NULL
 BEGIN
  UPDATE auth_external_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='person_role_changed'
   WHERE accountable_id=NEW.person_id AND state IN ('requested','consented','approved');
 END;
CREATE TRIGGER auth_external_role_changed AFTER UPDATE OF person_id,revoked_at ON auth_role_grants
 WHEN NEW.revoked_at IS NULL
 BEGIN
  UPDATE auth_external_tasks SET state='revoked',revision=revision+1,
   revoked_at=CAST(strftime('%s','now') AS INTEGER)*1000,ended_reason='person_role_changed'
   WHERE accountable_id=NEW.person_id AND state IN ('requested','consented','approved');
 END;

CREATE TRIGGER auth_external_resource_ended AFTER UPDATE OF disabled_at,revision ON auth_delegation_resources
 BEGIN UPDATE auth_external_tasks SET state='revoked',revision=revision+1,ended_reason='resource_changed',revoked_at=NEW.disabled_at
 WHERE resource_id=NEW.id AND state IN ('requested','consented','approved'); END;
