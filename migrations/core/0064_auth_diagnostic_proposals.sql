-- Preserve filed proposals while adding the owner-consented diagnostic kind.
CREATE TABLE auth_agent_proposals_next (
 id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES auth_agent_keys(id),
 kind TEXT NOT NULL CHECK(kind IN ('suspend_person','restore_person','invite_person','remove_invitation','add_domain_rule','remove_domain_rule','approve_app_link','remove_app_link','repair_signin')),
 target TEXT NOT NULL, params TEXT NOT NULL, reason TEXT NOT NULL,
 effect TEXT NOT NULL, target_state TEXT NOT NULL, state_digest TEXT NOT NULL,
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','rejected','failed')),
 decided_by TEXT REFERENCES oa_operators(id), decided_at INTEGER, outcome TEXT, execution_id TEXT UNIQUE
);
INSERT INTO auth_agent_proposals_next SELECT id,key_id,kind,target,params,reason,effect,target_state,state_digest,created_at,expires_at,status,decided_by,decided_at,outcome,execution_id FROM auth_agent_proposals;
DROP TABLE auth_agent_proposals;
ALTER TABLE auth_agent_proposals_next RENAME TO auth_agent_proposals;
CREATE INDEX auth_agent_proposals_key ON auth_agent_proposals(key_id);
CREATE INDEX auth_agent_proposals_pending ON auth_agent_proposals(status,created_at);
