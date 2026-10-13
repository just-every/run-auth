-- An undone batch no longer holds its file: staging the same export again starts
-- a new batch. 0014 made file_hash unique and D1 keeps foreign keys on, so the
-- table is not rebuilt; a file staged again after an undo stores its hash with
-- the new batch's id appended, and this index keeps one open batch per file by
-- the 43-character content hash. Existing rows are untouched.
CREATE UNIQUE INDEX auth_import_batches_open_file ON auth_import_batches(substr(file_hash,1,43)) WHERE undone_at IS NULL;
