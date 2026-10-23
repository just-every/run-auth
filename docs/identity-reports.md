# Native identity report API

An authorized hardware-passkey session reads `/api/auth/reports` for the named
reports, then `/api/auth/reports/<name>` for JSON. Names are `mfa-enrollment`,
`terminated-people`, `administrators`, `dormant-accounts`,
`joiner-leaver-timeliness` and `connector-health`. Add `format=csv` or
`export=1` for a downloaded CSV or JSON export. Reading requires `audit.view`;
exporting separately requires `audit.export` and the session's fresh local
email confirmation. Every export is recorded under `reports.export` with its
report, capture time, filters and row count. A view-only role cannot export.
These are human administration APIs, not additional admin service scopes.

Reports remain within the current employer's isolated namespace and the
reader's published people/group/app resources. Filters are `group`,
`workerType` (`employee`, `contractor`, `service`) and `department`.
`dormantDays` is an integer from 1 to 3650 (default 90). Duplicate/unknown
filters are refused. Connector health is app-scoped and refuses person
filters. Resource sets in the administrators report omit identifiers outside
the reader's scope; absence of an omitted identifier grants no authority.

Each JSON response declares `columns`, `asOf`, `rowCount`, `directoryCount`,
`filters`, `rows`, `epoch` and `gaps`. CSV columns stay defined even for an
empty report; arrays/objects use JSON cells and formula-leading strings are
escaped for spreadsheets. The response headers repeat the row count and
capture time. Additional factor/session/provisioning facts are read together
in a D1 transaction; a live authority/directory epoch fence refuses concurrent
role, person, factor, group or field changes. `asOf` identifies this captured
current view, not an arbitrary historical reconstruction. The per-person
roster count uses the same authorized directory filter and report eligibility.
Connector rows have no directory-person count.

The native slice exposes these facts without inferring missing evidence:

- MFA enrollment includes every scoped person, enrolled Auth passkeys with
  dates/last use, and no-factor people marked non-compliant. Password-only
  state is unknown. An enrolled passkey is an observed fact, not a verified
  employer MFA-policy result: positive compliance remains unknown until the
  policy and supported factor qualification exist.
- Terminated people include effective termination, native leaver/provisioning
  event and remote read-back times where present, and names of unresolved
  apps within scope. Local-denial and full-deprovision timing stay unknown;
  queue completion cannot prove every downstream door ended.
- Administrators include live built-in and published custom administrator
  grants and effective privileged app roles. Grant provenance is shown where
  retained and within scope; unmeasured last-use/provenance stays unknown.
- Dormant accounts include active people whose last retained successful Auth
  session is older than the chosen threshold. A person with no retained
  successful sign-in is explicitly marked history unknown, not given an
  invented date. Current held apps are scoped.
- Joiner/leaver timing and native SCIM connector-health views retain observed
  facts, open failures and unknowns. They do not claim complete source,
  all-door timing, connector coverage or service-level qualification.

AUTH-REPORTS-001 stays partial: the exact 15 passkey/push, 3 password-only and
2 no-factor acceptance dataset, employer-policy compliance, full timing audit
reconciliation, every connector, scheduled email, scoped machine exports and
compliance/Evidence delivery remain unproved. No outbound delivery or new
retention schedule is enabled by reading or exporting a report.
