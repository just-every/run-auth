-- Apps linked through the oidc-provider@1 pull handshake. A client keeps its
-- id and sector for life; a re-link replaces only its key, callbacks and source.
ALTER TABLE auth_clients ADD COLUMN interface TEXT NOT NULL DEFAULT 'oidc-provider@1';
ALTER TABLE auth_clients ADD COLUMN logout_uri TEXT;
ALTER TABLE auth_clients ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
ALTER TABLE auth_clients ADD COLUMN linked_at INTEGER;
ALTER TABLE auth_clients ADD COLUMN approved_by TEXT;

-- Every origin Auth has ever pulled, so approval can flag a first-seen origin.
CREATE TABLE auth_origins_seen (origin TEXT PRIMARY KEY, first_seen_at INTEGER NOT NULL);

-- Interface versions live clients report. A lower version than one already
-- reported waits for an owner's approval (approved_at NULL until then).
CREATE TABLE auth_client_versions (
 client_id TEXT NOT NULL REFERENCES auth_clients(id), version TEXT NOT NULL,
 reported_at INTEGER NOT NULL, approved_by TEXT, approved_at INTEGER,
 PRIMARY KEY(client_id, version)
);

-- An administrator's pending approval of an app origin, with what was pulled.
CREATE TABLE auth_link_requests (
 id TEXT PRIMARY KEY, origin TEXT NOT NULL, interface TEXT NOT NULL, app TEXT NOT NULL,
 client_id TEXT, key_changed INTEGER NOT NULL, first_seen INTEGER NOT NULL, punycode INTEGER NOT NULL,
 requested_by TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 decided_by TEXT, decided_at INTEGER, outcome TEXT
);
CREATE INDEX auth_link_requests_open ON auth_link_requests(decided_at, expires_at);

-- One-use link tokens for `rer setup --non-interactive`: one exact origin and
-- callback set, at most an hour. Only the digest is kept.
CREATE TABLE auth_link_tokens (
 token_hash TEXT PRIMARY KEY, origin TEXT NOT NULL, interface TEXT NOT NULL, callbacks TEXT NOT NULL,
 created_by TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);

-- Short one-use codes posted to an app's fixed link callback and redeemed by
-- a request the app signs with its link key.
CREATE TABLE auth_link_codes (
 code_hash TEXT PRIMARY KEY, origin TEXT NOT NULL, interface TEXT NOT NULL, callback TEXT NOT NULL,
 sector_id TEXT NOT NULL, link TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed_at INTEGER
);

-- Which apps received tokens from which Auth session, for session-scoped logout.
CREATE TABLE auth_session_clients (
 session_id TEXT NOT NULL REFERENCES auth_sessions(id), client_id TEXT NOT NULL REFERENCES auth_clients(id),
 PRIMARY KEY(session_id, client_id)
);

-- Back-channel logout and fence deliveries, retried for up to 24 hours.
CREATE TABLE auth_logout_deliveries (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES auth_clients(id), person_id TEXT NOT NULL,
 event TEXT NOT NULL, sid TEXT, jti TEXT NOT NULL UNIQUE, attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at INTEGER NOT NULL, created_at INTEGER NOT NULL, finished_at INTEGER, outcome TEXT
);
CREATE INDEX auth_logout_due ON auth_logout_deliveries(finished_at, next_attempt_at);

-- Agents may now also propose linking or removing an app. SQLite cannot widen a
-- CHECK in place, so the proposals table is rebuilt with the same columns and rows.
CREATE TABLE auth_agent_proposals_next (
 id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES auth_agent_keys(id),
 kind TEXT NOT NULL CHECK(kind IN ('suspend_person','restore_person','invite_person','remove_invitation','add_domain_rule','remove_domain_rule','approve_app_link','remove_app_link')),
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

-- Signed grant maps written at export: every (sector, person, pairwise subject)
-- and former subject, signed with Auth's key, so a later provider can rebind.
CREATE TABLE auth_grant_maps (id TEXT PRIMARY KEY, issuer TEXT NOT NULL, created_at INTEGER NOT NULL, map TEXT NOT NULL);
