-- Private voluntary release handles. No directory or administrator read door.
CREATE TABLE auth_identity_pairs (
 handle TEXT PRIMARY KEY, person_id TEXT NOT NULL REFERENCES oa_operators(id),
 organization_id TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX auth_identity_pairs_person ON auth_identity_pairs(person_id);
CREATE TABLE auth_identity_release_notices (
 id TEXT PRIMARY KEY, handle TEXT NOT NULL UNIQUE, erasure_reference TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','held','erased')) DEFAULT 'pending',
 hold_id TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
-- A person explicitly obtains this read-only receipt credential before erasure.
-- Root erasure removes person_id. No capability enters an owner receipt or URL.
CREATE TABLE auth_erasure_person_receipts (
 token_hash TEXT PRIMARY KEY, person_id TEXT, created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, erased_at INTEGER, notices TEXT NOT NULL
);
