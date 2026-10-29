ALTER TABLE bs_settings ADD COLUMN owner_id TEXT CHECK(owner_id IS NULL OR owner_id <> '');
ALTER TABLE bs_team ADD COLUMN business_id TEXT CHECK(business_id IS NULL OR business_id <> '');
ALTER TABLE bs_team ADD COLUMN business_role TEXT CHECK(business_role IS NULL OR business_role IN('admin','member'));
CREATE UNIQUE INDEX bs_team_business_id ON bs_team(business_id) WHERE business_id IS NOT NULL;

-- Binding and native root erasure share a durable custody fence. No agent can
-- be admitted before its signed binding, so even its first read is protected.
CREATE TRIGGER auth_agent_binding_erasure BEFORE INSERT ON auth_erasure_commits
WHEN EXISTS(SELECT 1 FROM bs_settings WHERE owner_id IS NOT NULL)
  OR EXISTS(SELECT 1 FROM bs_team)
BEGIN SELECT RAISE(ABORT,'agent_custody_review_required'); END;
CREATE TRIGGER auth_agent_binding_after_erasure BEFORE INSERT ON bs_settings
WHEN EXISTS(SELECT 1 FROM auth_erasure_commits)
  OR EXISTS(SELECT 1 FROM auth_erasure_journal)
BEGIN SELECT RAISE(ABORT,'agent_custody_review_required'); END;
CREATE TRIGGER auth_agent_rebinding_after_erasure BEFORE UPDATE ON bs_settings
WHEN EXISTS(SELECT 1 FROM auth_erasure_commits)
  OR EXISTS(SELECT 1 FROM auth_erasure_journal)
BEGIN SELECT RAISE(ABORT,'agent_custody_review_required'); END;
