-- Employer-local registrations never inherit installation credentials or trust.
CREATE TABLE auth_employer_providers (
 provider_id TEXT PRIMARY KEY, sealed_config TEXT NOT NULL,
 created_by TEXT NOT NULL REFERENCES oa_operators(id), created_at INTEGER NOT NULL
);
