-- Retain anonymous key lifecycle facts after its read authority ends.
ALTER TABLE auth_erasure_person_receipts ADD COLUMN revoked_at INTEGER;
ALTER TABLE auth_erasure_person_receipts ADD COLUMN expired_at INTEGER;
