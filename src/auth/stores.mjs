// Shared by erasure previews/commits and the Base export/restore adapter. Every
// installed logical store in migrations/core/0001..0048 is classified here.
// A new managed store requires an explicit decision before either operation.
const groups = {
 portable: [
  'auth_onboarding',
  'auth_launcher_bookmarks', 'auth_launcher_preferences',
  'auth_import_history',
  'auth_app_role_order', 'auth_app_reductions', 'auth_app_denials', 'auth_privileged_resources', 'auth_privileged_app_roles', 'auth_decision_operations',
  'auth_reviews', 'auth_review_items', 'auth_review_events', 'auth_review_schedules',
  'auth_retention_expiry', 'auth_retention_policy', 'auth_retention_holds', 'auth_request_policies', 'auth_access_requests',
  'auth_obligations', 'auth_obligation_history', 'auth_followup_cases',
  'auth_activity', 'auth_activity_details', 'auth_app_assignments', 'auth_apps',
  'auth_attribute_defs', 'auth_client_versions', 'auth_clients', 'auth_domains',
  'auth_emails', 'auth_erasure_holds', 'auth_erasure_journal', 'auth_erasure_policy',
  'auth_erasure_receipts', 'auth_events', 'auth_former_subjects', 'auth_grant_maps',
  'auth_grants', 'auth_group_exclusions', 'auth_group_members', 'auth_group_owners',
  'auth_groups', 'auth_import_batches', 'auth_mapping_versions', 'auth_oidc_clients',
  'auth_org_invitations', 'auth_organizations', 'auth_origins_seen', 'auth_passkeys',
  'auth_people', 'auth_person_fields', 'auth_person_sources', 'auth_provider_states',
  'auth_rer_withdrawals', 'auth_resource_apis', 'auth_role_cases', 'auth_role_events',
  'auth_role_grants', 'auth_role_operations', 'auth_roles', 'auth_scim_accounts',
  'auth_subjects', 'oa_bootstrap', 'oa_domain_rules', 'oa_external_identities',
  'oa_first_run', 'oa_invitation_cancellations', 'oa_operators',
  'rer_dependency_installation',
 ],
 // Installation custody/configuration is re-established at the destination.
 local: [
  'auth_security_notice_intents',
  'auth_factor_policies',
  'auth_automation_runs', 'auth_automation_steps',
  'auth_mail_suppressions',
  'auth_notification_policy',
  'auth_domain_claims',
  'auth_refresh_profiles',
  'auth_retention_runs',
  'auth_followup_settings', 'auth_admin_api_epoch', 'auth_admin_service_apps', 'auth_resource_services',
  'auth_delegation_resources', 'auth_delegation_agent_resources', 'auth_external_tasks',
  'auth_delegated_agents', 'auth_delegated_tasks',
  'auth_delegation_reversals',
  'auth_rer_trust', 'auth_role_epoch', 'oa_auth_audit', 'oa_auth_settings',
  'oa_identity_providers', 'rer_dependency_link',
 ],
 // Entire stores are excluded, including hashes and sealed remote work. Public
 // passkey verification keys above are the deliberately portable exception.
 secret: [
  'auth_totp_factors','auth_person_recovery_codes',
  'auth_onboarding_links','auth_temporary_pass_requests','auth_temporary_passes',
  'auth_automation_connections', 'auth_automations', 'auth_automation_versions',
  'auth_recovery_enrollments',
  'auth_directory_sources','auth_directory_resources','auth_directory_source_groups','auth_federation_setups',
  'auth_campaigns','auth_campaign_people',
  'auth_hr_feeds',
  'auth_migration_bridges', 'auth_migration_subjects',
  'auth_employer_providers',
  'auth_identity_pairs', 'auth_identity_release_notices', 'auth_erasure_person_receipts',
  'auth_refresh_families', 'auth_refresh_credentials',
  'auth_followup_link_tokens', 'auth_agent_keys', 'auth_erasure_remote', 'auth_event_subscriptions', 'auth_hooks',
  'auth_oidc_secrets', 'auth_recovery_tokens', 'auth_saml_keys', 'auth_scim_connectors',
  'auth_settings', 'auth_signing_keys', 'oa_credentials', 'oa_dev_credentials',
  'rer_dependency_keys',
 ],
 transient: [
  'auth_factor_proofs','auth_factor_operations','auth_passkey_session_proofs',
  'auth_directory_source_obligations',
  'auth_directory_snapshots','auth_directory_source_steps','auth_federation_transactions','auth_federation_replays','auth_federation_test_providers','auth_federation_test_health',
  'auth_campaign_obligations',
  'auth_mail_deliveries','auth_mail_events',
  'auth_notification_devices','auth_security_notifications','auth_suspicious_reports',
  'auth_domain_challenges',
  'auth_hr_approved_rows','auth_hr_files','auth_hr_file_rows','auth_hr_feed_obligations',
  'auth_refresh_consents', 'auth_refresh_proofs',
  'auth_admin_api_commits', 'auth_admin_service_assertions', 'auth_agent_proposals',
  'auth_delegation_resource_assertions', 'auth_delegation_assertions',
  'auth_delegation_dpop_nonces', 'auth_delegation_dpop_proofs',
  'auth_assertions', 'auth_challenges', 'auth_codes', 'auth_erasure_commits',
  'auth_erasure_previews', 'auth_erasure_reset_consents', 'auth_event_deliveries', 'auth_import_rows', 'auth_limits',
  'auth_link_codes', 'auth_link_intents', 'auth_link_requests', 'auth_link_tokens',
  'auth_logout_deliveries', 'auth_notices', 'auth_oidc_codes', 'auth_oidc_logouts',
  'auth_oidc_sessions', 'auth_provisioning', 'auth_recoveries', 'auth_rer_approvals',
  'auth_resource_assertions', 'auth_role_previews', 'auth_saml_logouts',
  'auth_saml_requests', 'auth_saml_sessions', 'auth_session_clients', 'auth_sessions',
  'auth_upstream_proofs', 'oa_identity_provider_health', 'oa_limits', 'oa_logout_events',
  'oa_oidc_limits', 'oa_oidc_transactions', 'oa_provider_session_pins',
  'oa_provider_sessions', 'oa_sessions', 'oa_setup_links', 'oa_step_up_challenges',
  'oa_tokens', 'rer_dependency_codes', 'rer_dependency_pending',
 ],
 base: [
  'oc_owner_claims', 'rer_mail_development_outbox', 'rer_portability_epochs',
  'rer_portability_guard', 'rer_portability_jobs', 'rer_portability_journal',
  'rer_portability_owned', 'rer_portability_parts', 'rer_portability_segments',
  'rer_portability_state',
  // Base 0.2.80 adds private import leases and retained recovery audit.
  // Platform's migration ledger is controller bookkeeping, never product data.
  'rer_portability_import_leases', 'rer_portability_recovery_audit', 'rer_migrations',
 ],
};
const globalOnly = new Set(['auth_organizations', 'auth_domain_claims', 'oc_owner_claims']);
export const STORE_REGISTRY = Object.freeze(Object.fromEntries(Object.entries(groups).flatMap(([classification, names]) =>
 names.map(name => [name, Object.freeze({name, classification, portable: classification === 'portable', scoped: !globalOnly.has(name)})]))));

export class StoreRegistryError extends Error {
 constructor(code, store) { super(code); this.code = code; this.store = store; }
}
export const managedStore = name => typeof name === 'string' && /^(?:auth_|oa_|rer_|oc_|org_)/i.test(name);

export function registeredOrganizations(records = []) {
 if (!Array.isArray(records)) throw new StoreRegistryError('invalid_store_namespace');
 const seen = new Set();
 return records.map(record => {
  if (!record || typeof record.id !== 'string' || !/^[a-f0-9]{32}$/.test(record.id)
   || record.namespace !== `org_${record.id}_` || !['active', 'erased'].includes(record.status)
   || seen.has(record.id)) throw new StoreRegistryError('invalid_store_namespace');
  seen.add(record.id);
  return {id: record.id, namespace: record.namespace, status: record.status};
 });
}

// These are Base's actual snapshot/staging names, from portability/export.mjs,
// import.mjs and copies.mjs. They remain internal, never portable. No general
// rer_portability_* exemption would recognize an unreviewed product store.
function definition(name) {
 return STORE_REGISTRY[name] ?? (/^rer_portability_(?:snap|stage)_[a-f0-9]{32}_[0-9]+(?:_meta(?:_sorted)?)?$/.test(name)
  ? {name, classification: 'base', portable: false, scoped: true} : null);
}

export function resolveStore(name, organizations = []) {
 if (!managedStore(name)) return null;
 let logical = name.toLowerCase(), namespace = null;
 if (logical.startsWith('org_')) {
  const match = /^(org_[a-f0-9]{32}_)(.+)$/.exec(name);
  if (!match) throw new StoreRegistryError('invalid_store_namespace', name);
  namespace = match[1]; logical = match[2].toLowerCase();
  if (!registeredOrganizations(organizations).some(record => record.namespace === namespace)) {
   throw new StoreRegistryError('unregistered_store_namespace', name);
  }
 }
 const store = definition(logical);
 if (!store || namespace && !store.scoped) throw new StoreRegistryError('unknown_managed_store', name);
 return {...store, physical: name, namespace};
}

export function portableTables(organizations = []) {
 const records = registeredOrganizations(organizations);
 const stores = Object.values(STORE_REGISTRY).filter(store => store.portable);
 return [...stores.map(store => store.name), ...records.flatMap(record => stores.filter(store => store.scoped).map(store => record.namespace + store.name))];
}
