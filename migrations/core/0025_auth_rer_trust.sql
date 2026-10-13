-- RER Managed: the per-account keys whose signed link approvals this install
-- accepts. A provisioned key comes from the RER_LINK_APPROVAL_KEYS binding RER
-- set when it installed Auth; an owner-added key was registered on Sign-in
-- methods. Withdrawal is recorded here for both and is never undone.
CREATE TABLE auth_rer_trust (
 kid TEXT PRIMARY KEY, public_jwk TEXT NOT NULL, source TEXT NOT NULL CHECK(source IN ('provisioned','owner')),
 added_by TEXT, added_at INTEGER NOT NULL, withdrawn_by TEXT, withdrawn_at INTEGER
);
-- Each approval's jti is accepted once.
CREATE TABLE auth_rer_approvals (jti TEXT PRIMARY KEY, kid TEXT NOT NULL, expires_at INTEGER NOT NULL);
