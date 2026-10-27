# Investigate native activity

A hardware-passkey administrator or a delegated role with `audit.view` can query
`GET /api/auth/audit`. Activity uses the same query at `/app/activity`. The scoped
role endpoint `GET /api/auth/roles/audit` also uses this query. The older
`GET /api/auth/activity` remains an administrator-only compatibility feed.

Queries accept an inclusive `from` and `to` in Unix milliseconds or a UTC date
and time such as `2026-10-27T12:00`, an exact `person` reference, an exact `event`
type, and a `limit` of 1 through 100 (default 50). Duplicate parameters and invalid
bounds are refused. No retention setting changes: the existing default remains
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
actions. Native machine log reads remain a separate business-event projection;
related people and groups must also fall inside the machine credential's scope.
Credential, factor, recovery and role events remain excluded from that door.

Interactive view does not grant export. The existing scoped audit export still
requires `audit.export`, hardware proof and fresh local email, and keeps its
existing bounded role-event projection. This slice adds no sink or stream.

Still unproved: authorized Datadog, Splunk, Microsoft Sentinel and Evidence
exports; full failed-sign-in, policy and provisioning correlation; complete
employee device and grant history; every named report reconciliation including
password, push and policy dependencies; general durable tamper and gap evidence.
The existing retention and erasure policy holds remain unchanged.
