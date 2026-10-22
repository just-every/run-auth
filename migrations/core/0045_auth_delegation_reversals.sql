-- A completed task can be referred back to the employer for human review.
-- This record confers no authority and never applies an assignment change.
CREATE TABLE auth_delegation_reversals (
 id TEXT PRIMARY KEY,
 grant_id TEXT NOT NULL UNIQUE REFERENCES auth_delegated_tasks(id),
 organization_id TEXT NOT NULL,
 requested_by TEXT NOT NULL REFERENCES oa_operators(id),
 app_id TEXT NOT NULL REFERENCES auth_apps(id),
 effect_digest TEXT NOT NULL,
 execution_id TEXT NOT NULL,
 completed_at INTEGER NOT NULL,
 before_role TEXT,
 assignment_present INTEGER NOT NULL CHECK(assignment_present IN (0,1)),
 assignment_role TEXT,
 assignment_created_by TEXT,
 assignment_created_at INTEGER,
 state TEXT NOT NULL DEFAULT 'requested' CHECK(state='requested'),
 created_at INTEGER NOT NULL
);
