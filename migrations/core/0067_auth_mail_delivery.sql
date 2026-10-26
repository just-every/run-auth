CREATE TABLE auth_mail_deliveries (
 id TEXT PRIMARY KEY,
 person_id TEXT REFERENCES oa_operators(id) ON DELETE CASCADE,
 recipient_hash TEXT NOT NULL,
 provider TEXT NOT NULL,
 state TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 event_at INTEGER,
 error TEXT
);
CREATE INDEX auth_mail_deliveries_created ON auth_mail_deliveries(created_at);
CREATE TABLE auth_mail_events (
 id TEXT PRIMARY KEY,
 delivery_id TEXT NOT NULL REFERENCES auth_mail_deliveries(id),
 state TEXT NOT NULL,
 occurred_at INTEGER NOT NULL
);
CREATE TABLE auth_mail_suppressions (
 recipient_hash TEXT PRIMARY KEY,
 person_id TEXT REFERENCES oa_operators(id) ON DELETE CASCADE,
 reason TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TRIGGER auth_mail_event_identity BEFORE INSERT ON auth_mail_events
 WHEN EXISTS(SELECT 1 FROM auth_mail_events WHERE id=NEW.id AND
  (delivery_id<>NEW.delivery_id OR state<>NEW.state OR occurred_at<>NEW.occurred_at))
 BEGIN SELECT RAISE(ABORT,'delivery_event_conflict'); END;
