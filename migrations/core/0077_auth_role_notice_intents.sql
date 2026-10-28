-- Required notices survive interruption between a committed role grant and mail.
-- This installation-local queue is never restored as permission to send again.
CREATE TABLE auth_security_notice_intents (
 id TEXT PRIMARY KEY,
 person_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 grant_id TEXT NOT NULL,
 recipient_email TEXT,
 context TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 state TEXT NOT NULL,
 last_error TEXT,
 notification_id TEXT REFERENCES auth_security_notifications(id) ON DELETE SET NULL
);
CREATE INDEX auth_security_notice_intents_pending ON auth_security_notice_intents(state,created_at);
CREATE TRIGGER auth_security_notice_intent_erasure AFTER UPDATE OF person_id ON auth_security_notice_intents
WHEN NEW.person_id IS NULL BEGIN
 UPDATE auth_security_notice_intents SET recipient_email=NULL,context='{}',state='refused',last_error='person_erased' WHERE id=NEW.id;
END;
