-- Lifecycle events in commit order (seq is the cursor), and their delivery to
-- subscribers. Subscriber signing secrets are sealed; read keys are digests.
CREATE TABLE auth_events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, type TEXT NOT NULL, version INTEGER NOT NULL,
 subject TEXT NOT NULL, data TEXT NOT NULL, occurred_at INTEGER NOT NULL
);
CREATE TABLE auth_event_subscriptions (
 id TEXT PRIMARY KEY, url TEXT NOT NULL, types TEXT NOT NULL, sealed_secrets TEXT NOT NULL, read_key_hash TEXT NOT NULL UNIQUE,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL, disabled_at INTEGER
);
CREATE TABLE auth_event_deliveries (
 subscription_id TEXT NOT NULL, seq INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','delivered','failed','abandoned')), last_status INTEGER, delivered_at INTEGER, claimed_until INTEGER,
 PRIMARY KEY(subscription_id, seq)
);
CREATE INDEX auth_event_deliveries_due ON auth_event_deliveries(state, next_attempt_at);
