-- Ownership is installation-wide; challenges belong to one employer.
CREATE TABLE auth_domain_claims (
 domain TEXT PRIMARY KEY,
 organization_id TEXT NOT NULL,
 challenge_id TEXT NOT NULL,
 verified_at INTEGER NOT NULL,
 revoked_at INTEGER
);
CREATE TABLE auth_domain_challenges (
 id TEXT PRIMARY KEY,
 domain TEXT NOT NULL,
 value TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 verified_at INTEGER
);
CREATE TRIGGER auth_domain_enrollment_verified BEFORE INSERT ON auth_domains
WHEN NOT EXISTS(SELECT 1 FROM auth_domain_challenges c JOIN auth_domain_claims o ON o.challenge_id=c.id WHERE c.domain=NEW.domain AND o.domain=NEW.domain AND c.verified_at IS NOT NULL AND o.revoked_at IS NULL)
BEGIN SELECT RAISE(ABORT,'domain_not_verified'); END;
CREATE TRIGGER auth_domain_rule_verified BEFORE INSERT ON oa_domain_rules
WHEN NOT EXISTS(SELECT 1 FROM auth_domain_challenges c JOIN auth_domain_claims o ON o.challenge_id=c.id WHERE c.domain=NEW.domain AND o.domain=NEW.domain AND c.verified_at IS NOT NULL AND o.revoked_at IS NULL)
BEGIN SELECT RAISE(ABORT,'domain_not_verified'); END;
CREATE TRIGGER auth_domain_rule_update_verified BEFORE UPDATE ON oa_domain_rules
WHEN NOT EXISTS(SELECT 1 FROM auth_domain_challenges c JOIN auth_domain_claims o ON o.challenge_id=c.id WHERE c.domain=NEW.domain AND o.domain=NEW.domain AND c.verified_at IS NOT NULL AND o.revoked_at IS NULL)
BEGIN SELECT RAISE(ABORT,'domain_not_verified'); END;
