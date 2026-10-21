-- Provider identity and credentials remain immutable server configuration.
-- A missing row preserves the configured provider's original enabled state.
CREATE TABLE auth_provider_states (
 provider_id TEXT PRIMARY KEY,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 updated_by TEXT NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE TRIGGER admin_epoch_auth_provider_states_insert AFTER INSERT ON auth_provider_states
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_provider_states_update AFTER UPDATE ON auth_provider_states
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER admin_epoch_auth_provider_states_delete AFTER DELETE ON auth_provider_states
 BEGIN UPDATE auth_admin_api_epoch SET version=version+1 WHERE id=1; END;
