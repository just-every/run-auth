# Owner-authorized erasure

A company owner erases people and app connections in that company. The
installation owner uses the root door to reset an organization or the local
installation. Installation roles gain no directory access to an isolated
employer through this reset authority. Erasure requires a hardware passkey and
email confirmation in that session within ten minutes, rechecked at commit.
Suspension and termination remain separate administrative actions.

First configure the policy through `POST /api/auth/erasure/policy`:

```json
{"confirm":true,"automaticDeletion":false,"honorLegalHolds":true}
```

An unconfigured policy refuses erasure confirmation. Applicable active legal
holds refuse the whole erasure. Erasure is never scheduled; this does not
suppress the separate employer-configured expiry under AUTH-RETENTION-001.
No legal retention period is inferred.

`POST /api/auth/erasure/hold` accepts `kind`, `target` and a reason. Supported
kinds are `person`, `app`, `organization`, and `installation`. Release a hold
through the same owner door with `{"id":"hold-id","release":true}`.
Organization and installation holds protect their selected namespace.

1. Call `POST /api/auth/erasure/preview` with
   `{"kind":"person","target":"person-id"}`. An app target is its company-app
   or linked-client ID. Review the per-store counts, remote work and holds.
2. Within ten minutes, call `POST /api/auth/erasure/confirm` with `previewId`
   and `confirmation:"ERASE"`. Changed underlying state requires a new preview.
3. To authorize downstream data deletion, also send the exact selected
   `destinations` array from that preview and `confirmRemoteDeletion:true`.
   Missing destinations authorize no deletion; a broad boolean alone grants
   no deletion authority.
4. Save the receipt reference. It separates local completion from unfinished
   remote work. Ordinary company-owned receipts also have a signed JSON journal.

Access revocation proceeds regardless of deletion consent: local sessions,
tokens and factors end, back-channel revocation is attempted, SCIM users are
deactivated and managed group membership is cleared. Deactivation is verified
by a read showing an inactive account or absence; group clearing is verified
by an empty membership read or absence. Consented SCIM deletion is verified by
absence. These outcomes remain distinct from deletion of independently held
provider data.

The connector credential and signing private key are never copied into pending
work, even in encrypted form. Initial post-commit dispatch uses a transient
in-memory connection. Later ordinary company retries can use a still-current,
matching connector or signing key in that company. Unfinished work retains only
the minimum destination/account identifiers and tenant binding, sealed to the
installation. A missing connection, refusal, outage or unverified result stays
visible as blocked or failed; sending a request never proves completion.

A company owner can retry through `POST /api/auth/erasure/retry` with
`receiptId`, selected `destinations` and `confirmRemoteDeletion:true`. Every new
destination consent is exact and the owner's live authority is rechecked.
Already authorized destination consent remains effective. To abandon company
work, select its exact destinations and type `ABANDON` through
`POST /api/auth/erasure/abandon`.

Linked applications receive authority fences when the recorded subject and
callback are available. Ask each application's owner to delete independent
profiles, credentials, exports and delivered messages, and retain their
confirmation. Mailbox/provider owners control delivered email/SMS; installation
owners control exported archives and backups; external audit receiver owners
control their sink copies. Auth does not report these outside copies as erased.
Local outbox copies are removed.

The last active owner cannot be erased as an ordinary person. Transfer
ownership first, or use the protected organization-reset path. Before a reset,
the company owner can authorize downstream deletion in their own organization:

1. Call `POST /org/<id>/api/auth/erasure/reset-preview` and review the exact
   destinations and remote objects.
2. Call `POST /org/<id>/api/auth/erasure/reset-consent` with that `previewId`,
   `confirmation:"AUTHORIZE DELETION"`, the selected `destinations`, and
   `confirmRemoteDeletion:true`. This consent expires after ten minutes and is
   bound to the current remote objects and the consenting owner's authority.

This authorizes downstream deletion only. The installation owner separately
uses the root `POST /api/auth/erasure/preview` with
`{"kind":"organization","target":"<id>"}`, then confirms with the returned
`organizationId`, `previewId` and exact `RESET <issuer>` phrase. The root reset
request cannot choose deletion destinations or supply new deletion consent.
It can use only the employer owner's still-valid pre-reset consent. Without
that consent, local reset and access revocation proceed while deletion remains
blocked. Retained deletion consent is frozen after reset.

Reset ends every organization owner, administrator, member, session, service
app, preparer key and invitation. The issuer answers not found. No employer
connector credential or signing private key survives. Anonymous receipts and
outcomes, plus separately sealed unfinished identifiers, pass to the root
installation owner alone. Installation administrators have no custody. The
retained work never attaches to a newly created organization, even one with the
same name, domain or people.

The root owner sees an item's opaque ID, application label, operation, state
and outcome. Retained responses expose no organization ID, person identifier
or destination. Root view, retry, connection and abandonment actions are audited
in the installation. Receipts are selected through their opaque `receiptId`,
not an organization ID.

For a retained retry, call the root `POST /api/auth/erasure/retry` with
`retained:true`, `receiptId`, one `workId`, and `confirmRetry:true`. A SCIM retry
can additionally supply a fresh `connection:{token:...}`. Keep that token
private: it is used for this one piece of work, never persisted, returned or
placed in audit text. The server uses its sealed endpoint and account binding;
the caller cannot substitute a URL, tenant or remote account. Before mutation,
a GET must return the recorded remote ID and external ID. A mismatch or 404
fails qualification, and live root authority is rechecked before mutation.
Without a qualified connection the item stays blocked. A fence whose issuer
signing key was destroyed stays blocked when no qualified retry recipe exists.
The root owner cannot add deletion consent or retry unconsented deletion.

To abandon retained work, call the root `POST /api/auth/erasure/abandon` with
`retained:true`, `receiptId`, the exact opaque `workIds` array and
`confirmation:"ABANDON"`. Completion or abandonment destroys the sealed
identifier. Abandonment keeps an anonymous `remote_abandoned` outcome and never
claims remote deletion or revocation completed. A request already sent may
still finish. Partner deletion instructions remain visible without revealing
the destination; contact the application's owner using independently held records.

`GET /api/auth/erasure/receipts` shows ordinary company receipts and, for the
root owner, anonymous retained receipts. The journal and integrity endpoints
accept `receiptId`; retained requests use no organization-ID parameter. The
root retained journal contains only anonymous counts and a commitment
authenticated with the installation key using HMAC. It exposes no original
organization public key, issuer, journal rows or audit content. The original
journal remains sealed internally; integrity checks unseal it server-side and
verify the original signed audit commitments. Normal company owners retain
access to their own ordinary signed journal. Later audit appends do not
invalidate a snapshot; a later erasure may legitimately redact earlier rows,
so use the latest receipt when checking the current projection.

A root local installation can preview `kind:"installation"`; hosted
installation deletion is refused. When other organizations exist, the API
refuses a partial root-namespace reset and directs the owner to the complete
local CLI reset. Save the receipt and a post-erasure archive outside the
installation and resolve or explicitly abandon unfinished remote work before
`rer reset --yes`. The CLI removes every declared local organization, local
state and private settings, including the wrapping key; pending work cannot be
retried afterwards.

After erasure, create a new portability archive with `rer export --output exports/after-erasure.rer`. Keep it outside any installation that you will reset. This later archive carries Base's installation-wide erasure checkpoint, including erasures in an employer namespace. Restore uses the existing public command:

```sh
rer import --input exports/before-erasure.rer --journal exports/after-erasure.rer --yes
```

The later journal makes Base refuse the entire pre-erasure archive with `erasure_epoch`. It cannot resurrect its personal rows or its earlier identified audit copies. Restore the new post-erasure archive to retain anonymous history. The API's signed JSON journal accompanies the receipt for accountability; the `--journal` argument takes the later `.rer` archive, not that JSON document. An old archive cannot discover a later journal that its owner did not supply.

An installation archive cannot bypass employer isolation. The installation CLI refuses export/import while an active isolated employer exists; a separate employer-owner-authorized archive/restore door remains AUTH-TRANSFER-002 work. Erased anonymous namespaces may be archived, with credentials and sealed pending remote work excluded. Download receipts through the authorized owner door; erasure is never a prerequisite imposed to obtain a backup.
