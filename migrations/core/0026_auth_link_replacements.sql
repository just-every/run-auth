-- What an administrator's link request was shown it replaces: the client holding
-- the app's sector at another origin, and an active client at the app's origin
-- with another sector. Approval links only when those are still the same.
ALTER TABLE auth_link_requests ADD COLUMN replaces TEXT NOT NULL DEFAULT '[]';
