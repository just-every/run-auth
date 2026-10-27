ALTER TABLE auth_onboarding ADD COLUMN contact_authority TEXT;
ALTER TABLE auth_onboarding ADD COLUMN sending_person_id TEXT REFERENCES oa_operators(id);
ALTER TABLE auth_onboarding ADD COLUMN sending_person_version INTEGER;
ALTER TABLE auth_onboarding ADD COLUMN send_reason TEXT NOT NULL DEFAULT 'initial';
ALTER TABLE auth_onboarding ADD COLUMN recovery_notices_enabled INTEGER NOT NULL DEFAULT 0;
