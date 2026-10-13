-- Move-in staging is separate from people: a staged row can sign in to nothing,
-- receives no mail and is listed only on the move-in review. Admission creates an
-- ordinary invitation; the row then names the person it created.
CREATE TABLE auth_import_batches (
 id TEXT PRIMARY KEY, source_system TEXT NOT NULL, format TEXT NOT NULL, file_name TEXT NOT NULL,
 file_hash TEXT NOT NULL UNIQUE, export_date TEXT NOT NULL, row_count INTEGER NOT NULL,
 created_by TEXT NOT NULL REFERENCES oa_operators(id), created_at INTEGER NOT NULL,
 undone_at INTEGER, undo_report TEXT
);
CREATE TABLE auth_import_rows (
 batch_id TEXT NOT NULL REFERENCES auth_import_batches(id), idx INTEGER NOT NULL,
 source_id TEXT, email TEXT, display_name TEXT, disabled INTEGER, groups TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('staged','admitted','undone')), reasons TEXT NOT NULL,
 person_id TEXT REFERENCES oa_operators(id), admitted_at INTEGER, invited_at INTEGER,
 PRIMARY KEY(batch_id,idx)
);
CREATE INDEX auth_import_rows_person ON auth_import_rows(person_id);
-- An old provider subject kept against the person it was admitted as. It is data
-- for app owners to rebind deliberately, never a credential or an Auth subject.
CREATE TABLE auth_former_subjects (
 source_system TEXT NOT NULL, subject TEXT NOT NULL, person_id TEXT NOT NULL REFERENCES oa_operators(id),
 batch_id TEXT NOT NULL REFERENCES auth_import_batches(id), created_at INTEGER NOT NULL,
 PRIMARY KEY(source_system,subject)
);
CREATE INDEX auth_former_subjects_person ON auth_former_subjects(person_id);
-- Names behind an audit entry, such as who an undo removed and who it kept.
CREATE TABLE auth_activity_details (activity_id INTEGER PRIMARY KEY REFERENCES auth_activity(id), detail TEXT NOT NULL);
