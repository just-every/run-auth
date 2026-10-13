-- Withdrawn RER keys get their own table, which export carries, so a restored
-- install keeps them withdrawn: withdrawal ends a key for good. auth_rer_trust
-- keeps only the keys an owner added; a provisioned key's row existed only to
-- record its withdrawal.
CREATE TABLE auth_rer_withdrawals (
 kid TEXT PRIMARY KEY, source TEXT NOT NULL CHECK(source IN ('provisioned','owner')),
 withdrawn_by TEXT, withdrawn_at INTEGER NOT NULL
);
INSERT INTO auth_rer_withdrawals(kid,source,withdrawn_by,withdrawn_at) SELECT kid,source,withdrawn_by,withdrawn_at FROM auth_rer_trust WHERE withdrawn_at IS NOT NULL;
DELETE FROM auth_rer_trust WHERE source='provisioned';
ALTER TABLE auth_rer_trust DROP COLUMN withdrawn_by;
ALTER TABLE auth_rer_trust DROP COLUMN withdrawn_at;
