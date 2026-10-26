CREATE TABLE auth_campaigns (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 provider_id TEXT NOT NULL UNIQUE,
 configuration_hash TEXT NOT NULL,
 batch_id TEXT NOT NULL REFERENCES auth_import_batches(id),
 starts_at INTEGER NOT NULL,
 deadline_at INTEGER NOT NULL,
 cutover_at INTEGER NOT NULL,
 created_by TEXT NOT NULL REFERENCES oa_operators(id),
 owner_version INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 cancelled_at INTEGER,
 employee_consent INTEGER NOT NULL DEFAULT 0,
 manager_consent INTEGER NOT NULL DEFAULT 0,
 administrator_consent INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE auth_campaign_people (
 campaign_id TEXT NOT NULL REFERENCES auth_campaigns(id) ON DELETE CASCADE,
 person_id TEXT NOT NULL REFERENCES oa_operators(id) ON DELETE CASCADE,
 source_subject TEXT NOT NULL,
 email TEXT NOT NULL,
 manager_id TEXT REFERENCES oa_operators(id) ON DELETE SET NULL,
 proven_at INTEGER,
 exempt_at INTEGER,
 exemption_reason TEXT,
 PRIMARY KEY(campaign_id,person_id),
 UNIQUE(campaign_id,source_subject)
);
CREATE TABLE auth_campaign_obligations (
 obligation_id TEXT PRIMARY KEY REFERENCES auth_obligations(id) ON DELETE CASCADE,
 campaign_id TEXT NOT NULL REFERENCES auth_campaigns(id) ON DELETE CASCADE,
 person_id TEXT NOT NULL REFERENCES oa_operators(id) ON DELETE CASCADE,
 duty TEXT NOT NULL CHECK(duty IN ('employee','manager','administrator'))
);
