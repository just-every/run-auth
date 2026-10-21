-- Inline hooks are separate from durable lifecycle event subscriptions.
-- Only output field names are configurable; no hook receives credentials.
CREATE TABLE auth_hooks (
 id TEXT PRIMARY KEY, point TEXT NOT NULL CHECK(point IN ('token','saml','registration','user_import','password_import')),
 url TEXT NOT NULL, app_id TEXT, client_id TEXT, allowed_fields TEXT NOT NULL DEFAULT '[]',
 timeout_ms INTEGER NOT NULL DEFAULT 3000 CHECK(timeout_ms BETWEEN 100 AND 10000),
 fail_closed INTEGER NOT NULL DEFAULT 1 CHECK(fail_closed IN (0,1)), sealed_secret TEXT NOT NULL,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL, disabled_at INTEGER,
 CHECK((point='token' AND ((app_id IS NOT NULL AND client_id IS NULL) OR (app_id IS NULL AND client_id IS NOT NULL)))
    OR (point='saml' AND app_id IS NOT NULL AND client_id IS NULL)
    OR (point IN ('registration','user_import','password_import') AND app_id IS NULL AND client_id IS NULL))
);
CREATE INDEX auth_hooks_point ON auth_hooks(point,app_id,client_id,disabled_at);
