-- A preparer key ends for good when its owner stops being an administrator.
-- The key records its owner's oa_operators.version at minting; Base's trigger
-- bumps that version on every status or role change, so a key whose recorded
-- version no longer matches is ended and promoting or restoring the owner
-- again does not revive it. Keys minted before this migration keep working
-- only if their owner is an active administrator now; the rest end here.
ALTER TABLE auth_agent_keys ADD COLUMN owner_version INTEGER NOT NULL DEFAULT 0;
UPDATE auth_agent_keys SET owner_version=COALESCE((SELECT p.version FROM oa_operators p WHERE p.id=auth_agent_keys.owner_id AND p.status='active' AND p.role IN ('owner','admin')),0);
