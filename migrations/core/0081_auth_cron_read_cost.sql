-- The scheduled maintenance run asks for work that is due or open. Each index
-- below lets one of those questions read only that work, so a run costs the
-- same on the thousandth day as on the first. Nothing here changes a row.

-- People: the owner and the invited are a handful among the whole company.
CREATE INDEX auth_operators_owner ON oa_operators(created_at,id) WHERE role='owner' AND status='active';
CREATE INDEX auth_operators_invited ON oa_operators(created_at) WHERE status='invited';

-- Back-channel logouts still to deliver; every finished one stays as evidence.
CREATE INDEX auth_oidc_logouts_due ON auth_oidc_logouts(next_attempt_at) WHERE finished_at IS NULL;

-- Offline grants: the live ones are checked, and the revoked ones whose
-- credentials are not yet scrubbed are cleaned, once each.
CREATE INDEX auth_refresh_families_live ON auth_refresh_families(client_id) WHERE revoked_at IS NULL;
CREATE INDEX auth_refresh_families_unscrubbed ON auth_refresh_families(created_at) WHERE revoked_at IS NOT NULL AND current_hash IS NOT NULL;

-- Access requests wait in a state; reviews are open until closed.
CREATE INDEX auth_access_requests_state ON auth_access_requests(state,expires_at);
CREATE INDEX auth_reviews_status ON auth_reviews(status,due_at);
CREATE INDEX auth_review_items_review ON auth_review_items(review_id);
CREATE INDEX auth_review_events_item ON auth_review_events(item_id,event,created_at);
CREATE INDEX auth_review_events_review ON auth_review_events(review_id,event);

-- The follow-up queue is built from open records, never from every record.
CREATE INDEX auth_security_notice_intents_unaccepted ON auth_security_notice_intents(created_at) WHERE state!='accepted';
CREATE INDEX auth_link_requests_expiry ON auth_link_requests(expires_at);
CREATE INDEX auth_delegated_tasks_open ON auth_delegated_tasks(expires_at) WHERE state IN ('requested','consented','approved');
CREATE INDEX auth_role_cases_unclosed ON auth_role_cases(created_at) WHERE state!='closed';

-- Approved directory snapshots waiting to be applied.
CREATE INDEX auth_directory_snapshots_applying ON auth_directory_snapshots(approved_at) WHERE state='applying';

-- Hires whose invitation has not gone out: the few, not every hire on record.
CREATE INDEX auth_onboarding_undispatched ON auth_onboarding(start_at) WHERE dispatched_at IS NULL;
