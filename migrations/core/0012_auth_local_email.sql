-- Only a completed Auth browser-bound email challenge supplies this timestamp.
-- Existing sessions keep sign-in access but have no local step-up provenance.
ALTER TABLE auth_sessions ADD COLUMN local_email_verified_at INTEGER;
