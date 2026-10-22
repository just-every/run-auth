-- Only an explicitly published, app-specific order authorizes reductions.
CREATE TABLE auth_app_role_order (
 app_id TEXT NOT NULL, role TEXT NOT NULL, level INTEGER NOT NULL CHECK(level BETWEEN -1000000 AND 1000000),
 revision TEXT NOT NULL, published_by TEXT NOT NULL, published_at INTEGER NOT NULL,
 PRIMARY KEY(app_id,role)
);
CREATE TABLE auth_app_reductions (
 app_id TEXT NOT NULL, person_id TEXT NOT NULL, role TEXT NOT NULL,
 order_revision TEXT NOT NULL, operation_id TEXT NOT NULL REFERENCES auth_decision_operations(id),
 created_at INTEGER NOT NULL, PRIMARY KEY(app_id,person_id)
);
CREATE TRIGGER auth_review_role_order_insert AFTER INSERT ON auth_app_role_order
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_review_role_order_update AFTER UPDATE ON auth_app_role_order
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_review_role_order_delete AFTER DELETE ON auth_app_role_order
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_review_reduction_insert AFTER INSERT ON auth_app_reductions
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_review_reduction_update AFTER UPDATE ON auth_app_reductions
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
CREATE TRIGGER auth_review_reduction_delete AFTER DELETE ON auth_app_reductions
 BEGIN UPDATE auth_role_epoch SET epoch=epoch+1 WHERE id=1; END;
