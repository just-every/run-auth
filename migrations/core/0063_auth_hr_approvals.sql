-- Exact human-approved rows; feed credentials cannot create these receipts.
CREATE TABLE auth_hr_approved_rows (
 file_id TEXT NOT NULL, idx INTEGER NOT NULL, id TEXT NOT NULL UNIQUE,
 approved_by TEXT NOT NULL, approver_version INTEGER NOT NULL,
 approved_at INTEGER NOT NULL, approved_digest TEXT NOT NULL,
 file_digest TEXT NOT NULL, record TEXT NOT NULL, plan_digest TEXT NOT NULL,
 target_id TEXT, due_at INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
 applied_at INTEGER, error TEXT,
 PRIMARY KEY(file_id,idx),
 FOREIGN KEY(file_id) REFERENCES auth_hr_files(id) ON DELETE CASCADE
);
CREATE INDEX auth_hr_approved_due ON auth_hr_approved_rows(state,due_at);
