-- A recovery review case is a recovery obligation with its own deciding source.
ALTER TABLE auth_obligations ADD COLUMN case_id TEXT REFERENCES auth_role_cases(id) ON DELETE SET NULL;
