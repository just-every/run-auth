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

## Private voluntary membership release (v1)

An installation identity and an employer membership remain independent even when their emails or upstream subjects are identical. Auth never searches for memberships during installation-person erasure. A person can explicitly link a proved membership for a future erasure release notice. This link transfers no sign-in proof, factors, recovery, consent, approval or administrator authority.

The v1 self-service door is the authenticated HTTP API, documented here for a browser client. Sign in independently to the installation and chosen employer in the same browser and enroll a passkey in each. Their cookies remain separately scoped. Send JSON with the usual same-origin `Origin` header:

1. POST `/api/auth/identity-pairs/options` with `{organizationId}`. A live passkey session must exist in each identity; an installation session alone is refused. The response contains a transaction, `rootOptions` and `memberOptions` for two independent WebAuthn authentication ceremonies.
2. Ask `navigator.credentials.get` for each option set using its own allowed credential. POST `/api/auth/identity-pairs/confirm` with `{transaction,rootResponse,memberResponse,confirm:true}` in that browser. The one-use, five-minute transaction binds both live sessions, both people and both passkey counters. Foreign, borrowed, changed or replayed proof is refused. A guarded transaction commits both counters and a random per-pair handle together.
3. GET `/api/auth/identity-pairs` or `/api/auth/identity-pairs/export` to read only your own links. A different administrator's session reads only that administrator's own links. The employer directory, administrator API, ordinary exports and archives contain no link ledger. POST `/api/auth/identity-pairs/remove` with `{handle}` to remove your link and its counterpart. A later link gets a new handle.

Link metadata is private installation/employer-local custody and is excluded from transfer archives. No general identity-link audit event exposes a person's employer choices to an administrator. The private one-use ceremony, two counter changes and handle records retain the explicit consent evidence while the link exists. Employer erasure destroys both sides' handles. Erasing an installation creator changes only root provenance and leaves the employer's independent owner and records in place; the existing last-owner protection still applies.

### Personal receipt after installation erasure

Before erasure, a person may explicitly request a **read-only receipt key** through POST `/api/auth/identity-pairs/receipt-key` with `{confirm:true}` from their own passkey session. Save the returned key privately. Auth stores its digest, never its raw value. To read the receipt later, POST `/api/auth/identity-pairs/receipt` with `{receiptKey}` in the JSON body. Never put the key in a URL, log or message. It supplies no sign-in, membership-list, identity erasure or retry authority. Each notice shows only its opaque handle, erasure reference and state; it never names an employer or organization or reports a count. Invalid, expired and revoked keys return the same unavailable response. Keys expire after thirteen months; the notices are encrypted at rest and the root person ID is removed on erasure.

The key is shown once and cannot be retrieved. To surrender your key, POST `/api/auth/identity-pairs/receipt-revoke` with `{receiptKey,confirm:true}` in the body. This works after your sign-in ends and revokes only that key. Expiry and revocation clear the receipt payload and person reference while retaining anonymous lifecycle facts. No receipt door accepts URL parameters or logs the key.

CT approved these riders on 23 October and requires AUTH-ERASURE-002 to remain partial. Older encrypted receipts resolve opaque fields from their original notice while it exists; after a prior employer reset, missing handles cannot be reconstructed and access is refused. The adopted post-erasure surrender proof is possession of that key plus explicit confirmation; CT approval of this proof remains pending.

Installation-owner erasure uses only this person's explicit pair rows. It creates an opaque notice containing the per-pair handle and erasure reference in each linked employer, in the same guarded transaction as root erasure. It does not wait for an employer decision, search unlinked employers or report their identities erased. The root preview, signed journal and receipt omit the private stores and all employer names/counts. The person's receipt lists each volunteered notice's current state and says:

> Auth erased your installation identity. Memberships you did not link are held separately by those employers; Auth did not see or erase them. Ask each employer to erase them.

### Employer-owner release obligations

Only the employer owner can GET `/api/auth/identity-release-notices`. Each notice has an opaque handle and erasure reference; it contains no installation person ID, email, employer list or root receipt key. The existing durable follow-up engine projects an `identity_release` obligation assigned to the employer owner. Its internal recovery-source namespace is `identity-release:<notice-id>`; this additive binding supports already installed employer schemas without changing the existing obligation-table constraint. UI/API presentation and source decisions use identity-release semantics, with owner-only visibility, assignment and recipients. Existing explicit reminder consent remains required; an unrelated administrator or employee cannot receive or act on these notices.

The owner resolves a notice through the ordinary erasure preview: POST `/api/auth/erasure/preview` with `{kind:"person",releaseNoticeId}` in that employer. Confirm using the existing AUTH-ERASURE-001 owner, fresh-email, hold and exact-preview gates. To record an actual hold, first create the ordinary legal hold, then POST `/api/auth/identity-release-notices/hold` with `{noticeId,holdId}`. Only a matching active person/employer/installation hold qualifies. A recorded hold is shown as held, never erased. Releasing it reopens follow-up; actual membership erasure updates the notice to erased. Organization destruction removes its handles and notices; the personal receipt then reports employer-erased. No notice grants cross-identity authority or licenses automatic destructive work.

Every sign-in screen explains that the employer's Auth owner handles membership erasure.


## Credential revocation audit

The owner-confirmed erasure transaction removes credential authority and appends an `erasure_credentials_revoked` activity event in the same atomic database batch. Its actor and subject are the opaque erasure reference. Its detail contains only `id` and `counts`: sessions, API keys, passkeys, OAuth client token authorities, refresh credentials and delegations. No account name, email or approver identity enters that event. A failed local removal rolls back the event and all local removals. Remote provider work keeps its separate unresolved outcomes.

Counts enumerate removed durable credential records, including consumed or ended records that are deleted. An OAuth client authority can have signed several stateless access tokens; its count is one authority, not a claim to enumerate those token strings. Resource doors recheck live authority, so removing it ends every derivative token at the next request. This counting limit keeps AUTH-ERASURE-003 partial.

The event travels in a post-erasure product archive and survives its restore with the same opaque reference and counts. An older export or backup supplied with a later journal is currently refused as a whole. Applying that journal inside a staged restore, dropping erased records and replaying their audit needs the Base hook tracked by AUTH-TRANSFER-002. Independently held platform-operator backups are outside the product. Personal receipt contents under AUTH-ERASURE-002 are unchanged.
