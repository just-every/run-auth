# Auth claim register

Generated from CONTRACT.md. Historical acceptance journeys remain in ACCEPTANCE.md.

## AUTH-AUDIT-001

Status: partial

Evidence: `tests/auth/audit.test.mjs` — "interactive audit finds twelve-month sign-ins and reconciles a frozen authorized set beyond the old cap across restart and concurrent appends"; "interactive audit rechecks employer, person scope and revoked auditor authority without conferring directory or export writes"; "interactive audit preserves stable event IDs and opaque projections after real subject erasure". `tests/auth/agents-keys.test.mjs` — "admin service apps use private-key OAuth for scoped group and assignment writes; resource, IP, expiry, owner and ETag fences refuse automation while every scope excludes identity and credential custody" includes related-target machine log refusals. `tests/integration/directory-browser.test.mjs` — "organization and authority journey" includes Activity pagination, authority loss between pages and erased-subject readback at 1440 and 390 in both themes. `docs/activity.md`.

Gap: Native interactive Activity and role audit queries now have stable employer-bound event IDs, bounded time, person and event filters, as-of pagination and current authority checks. Twelve-month sign-in readback, reconciliation beyond the old cap despite concurrent appends, auditor write and scope refusals, and opaque erased-subject projections are implemented. Held: authorized Datadog, Splunk, Microsoft Sentinel and Evidence destinations, sink export and streaming, complete failed-sign-in, policy and provisioning correlation, full employee device and grant history, MFA and other report reconciliation including password, push and policy dependencies, and general durable tamper and gap evidence remain unproved. AUTH-RETENTION-001 and AUTH-ERASURE-002 policy holds are unchanged.
