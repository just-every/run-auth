-- Consent is employer-local; no transport is enabled by migration.
CREATE TABLE auth_notification_policy (
 id INTEGER PRIMARY KEY CHECK(id=1), policy TEXT NOT NULL,
 updated_by TEXT NOT NULL REFERENCES oa_operators(id), updated_at INTEGER NOT NULL
);
CREATE TABLE auth_notification_devices (
 person_id TEXT NOT NULL REFERENCES oa_operators(id) ON DELETE CASCADE,
 session_id TEXT PRIMARY KEY, device_hash TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE auth_security_notifications (
 id TEXT PRIMARY KEY, person_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 event TEXT NOT NULL, source_id TEXT NOT NULL, context TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
 delivery_state TEXT NOT NULL, reported_at INTEGER,
 UNIQUE(person_id,event,source_id)
);
CREATE TABLE auth_suspicious_reports (
 id TEXT PRIMARY KEY, notification_id TEXT NOT NULL UNIQUE REFERENCES auth_security_notifications(id),
 owner_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL, owner_version INTEGER,
 policy TEXT NOT NULL, created_at INTEGER NOT NULL, resolved_at INTEGER,
 sessions_state TEXT NOT NULL DEFAULT 'not_requested', slack_state TEXT NOT NULL DEFAULT 'not_requested'
);
CREATE INDEX auth_suspicious_reports_open ON auth_suspicious_reports(resolved_at,created_at);

CREATE INDEX auth_notification_devices_recent ON auth_notification_devices(person_id,created_at);
CREATE TRIGGER auth_security_notification_erasure AFTER UPDATE OF person_id ON auth_security_notifications
WHEN NEW.person_id IS NULL BEGIN
 UPDATE auth_security_notifications SET context='{}',source_id='erased',token_hash=lower(hex(randomblob(32))),expires_at=0 WHERE id=NEW.id;
END;
