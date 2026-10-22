-- Existing employers inherit new tables when opened, without changing the
-- already installed obligation table in every physical employer namespace.
CREATE TABLE auth_followup_cases (
 obligation_id TEXT PRIMARY KEY REFERENCES auth_obligations(id) ON DELETE CASCADE,
 case_id TEXT NOT NULL UNIQUE REFERENCES auth_role_cases(id) ON DELETE CASCADE
);
