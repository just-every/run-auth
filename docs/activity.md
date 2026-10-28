# Investigate native activity

A hardware-passkey administrator or a delegated role with `audit.view` can query
`GET /api/auth/audit`. Activity uses the same query at `/app/activity`. The scoped
role endpoint `GET /api/auth/roles/audit` also uses this query. The older
`GET /api/auth/activity` remains an administrator-only compatibility feed.

Queries accept an inclusive `from` and `to` in Unix milliseconds or a UTC date
and time such as `2026-10-27T12:00`, an exact `person` reference, an exact `event`
type, and a `limit` of 1 through 100 (default 50). Duplicate parameters and invalid
bounds are refused. Activity returns a recoverable 400 response with the filter
form retained. An expired cursor returns 410; a changed query or authority returns
409. Apply the retained filters again or choose Newest events. No retention setting changes: the existing default remains
13 calendar months, and this reader imposes no shorter look-back window.

The response contains `events`, an authorized `total`, `asOf`, the normalized
`filters`, `limit`, and `nextCursor`. Each event has a stable employer-bound
`eventId` and its existing native row ID. Follow `nextCursor` with exactly the
same filters and limit. It expires after 15 minutes and is bound to the session,
issuer, employer and authority epoch. Start a fresh query after a permission or
membership change. Every request rebuilds the current scope and rechecks the
session and epoch before returning data. Cursors confer no authority.

The maximum native row ID and capture time stay fixed across pages. Concurrent
appends, including backdated appends, cannot enter that traversal or alter its
authorized total. Erasure, retention deletion or an authority change are outside
that append-only snapshot guarantee. Erasure uses the existing opaque evidence
projection; erased personal data is never reconstructed by joining old profiles.
Historical invitation addresses and address changes bound to the person are
redacted in persistent audit evidence as well. A historical address never selects
a different current holder for account or credential deletion.
Scoped readers receive summaries without free-form details or directory names.
Related targets outside the role scope are excluded, even for the reader's own
actions. Unresolvable related references and target-free command receipts remain
administrator-only. Native machine log reads remain a separate business-event projection;
related people and groups must also fall inside the machine credential's scope.
Credential, factor, recovery and role events remain excluded from that door.

Interactive view does not grant export. Use `GET /api/auth/audit/export` to
download native activity as JSON, with the same filters, page limits and as-of
traversal as the interactive query. Follow its `nextCursor` on this export
endpoint to collect the complete authorized period; the older role-event export
cap does not truncate this traversal. An interactive cursor cannot be used for
export. Each page requires `audit.export`, hardware proof and local email
confirmation younger than ten minutes. Delegated exports contain only scoped
summaries, with the same related-resource exclusions as interactive reads.

Each returned page includes `exportOperationId`, identifying a committed
`audit.export` receipt with the as-of time, filters, authorized total and stable
event IDs from that page. The receipt commits only while the current session,
fresh email and role authority still hold. A refused export returns no events
and creates no successful receipt. The receipts themselves are later audit
events and cannot alter the captured traversal. After a restart, continuation
still requires the same live session and export authority. These receipts record
release from Auth; they do not prove delivery to an external destination or
provide general tamper detection.

The existing scoped role-event export remains available at
`GET /api/auth/roles/audit/export` with its existing bounded projection and
separate export gate. No sink or stream is added.

Still unproved: authorized Datadog, Splunk, Microsoft Sentinel and Evidence
exports; full failed-sign-in, policy and provisioning correlation; complete
employee device and grant history; every named report reconciliation including
password, push and policy dependencies; general durable tamper and gap evidence.
The existing retention and erasure policy holds remain unchanged.
