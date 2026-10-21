-- Revocation is mandatory; deleting independently held data requires exact
-- destination consent. Abandonment destroys unfinished sealed work without
-- claiming that remote deletion or revocation completed.
ALTER TABLE auth_erasure_remote ADD COLUMN consented_at INTEGER;
ALTER TABLE auth_erasure_remote ADD COLUMN abandoned_at INTEGER;
