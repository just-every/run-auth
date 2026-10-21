-- The workforce directory: typed attributes, values kept per source so
-- precedence and manual overrides stay visible, source identifiers, and
-- attribute-driven group membership with explicit exclusions and owners.
CREATE TABLE auth_attribute_defs (
 name TEXT PRIMARY KEY, label TEXT NOT NULL,
 type TEXT NOT NULL CHECK(type IN ('text','number','boolean','date','choice')), choices TEXT,
 visibility TEXT NOT NULL CHECK(visibility IN ('employee','admin')), employee_editable INTEGER NOT NULL DEFAULT 0,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
-- One value per person, field and source. The effective value is the highest
-- ranked source's: manual (an administrator's override), hr, directory, self.
CREATE TABLE auth_person_fields (
 person_id TEXT NOT NULL REFERENCES oa_operators(id), field TEXT NOT NULL,
 source TEXT NOT NULL CHECK(source IN ('manual','hr','directory','self')), value TEXT NOT NULL,
 set_by TEXT, set_at INTEGER NOT NULL, PRIMARY KEY(person_id, field, source)
);
CREATE INDEX auth_person_fields_field ON auth_person_fields(field, value);
-- A source's identifier for a person, bound once and never changed or reused.
CREATE TABLE auth_person_sources (
 source TEXT NOT NULL CHECK(source IN ('hr','directory')), source_id TEXT NOT NULL,
 person_id TEXT NOT NULL REFERENCES oa_operators(id), bound_by TEXT NOT NULL, bound_at INTEGER NOT NULL,
 PRIMARY KEY(source, source_id), UNIQUE(source, person_id)
);
-- Directory facts beside Base's person row: when a person was terminated.
CREATE TABLE auth_people (person_id TEXT PRIMARY KEY REFERENCES oa_operators(id), terminated_at INTEGER);
CREATE TRIGGER auth_people_rehired AFTER UPDATE OF status ON oa_operators
 WHEN OLD.status='inactive' AND NEW.status!='inactive'
 BEGIN UPDATE auth_people SET terminated_at=NULL WHERE person_id=NEW.id; END;

ALTER TABLE auth_groups ADD COLUMN rule TEXT;
-- 'manual' rows were added by an administrator; 'rule' rows are computed from the group's rule.
ALTER TABLE auth_group_members ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
CREATE TABLE auth_group_exclusions (
 group_id TEXT NOT NULL, person_id TEXT NOT NULL, reason TEXT, set_by TEXT NOT NULL, set_at INTEGER NOT NULL,
 PRIMARY KEY(group_id, person_id)
);
CREATE TABLE auth_group_owners (
 group_id TEXT NOT NULL, person_id TEXT NOT NULL, added_by TEXT NOT NULL, added_at INTEGER NOT NULL,
 PRIMARY KEY(group_id, person_id)
);
