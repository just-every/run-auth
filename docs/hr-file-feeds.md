# Reviewed HR file feeds

Auth accepts mapped CSV deliveries from a real Auth-hosted, key-authenticated
SFTP listener or an administrator upload. The current profile is deliberately
reviewed: a delivery can stage data and raise an obligation; it cannot sign in,
create an active worker, change an administrator or terminate someone without
explicit approval of that exact file and its preview. Approved rows execute
only at their effective dates under the current approver authority.

## Register one employer's source

Use that employer's issuer and an owner/administrator hardware-passkey session
with fresh local email proof. POST `/api/auth/hr-feeds/create` with:

```json
{
  "name": "Workforce file source",
  "schedule": "hourly",
  "fingerprint": "<SHA256 fingerprint of the source SSH public key>",
  "mapping": {
    "sourceId": "Employee ID",
    "email": "Work email",
    "name": "Name",
    "department": "Department",
    "state": "Status",
    "effectiveAt": "Effective"
  },
  "confirm": true
}
```

Schedules are `hourly` or `daily`. The termination threshold defaults to 5% and
can be explicitly set from 1 to 50 with `terminationPercent`. The response
shows `ingressToken` once: keep it in the ingress service's private configuration,
never a conversation, URL, shell argument, repository or log. Only its digest
is retained by Auth. A departed/demoted custodian, changed custodian version or
disabled feed cannot ingest. Registration/mapping is immutable in this profile;
create a replacement and disable the old source to change it.

Column mappings cover only source ID, work email, name, kind, department,
location, title, manager, start/end dates, status and the effective instant.
Required mappings are source ID, email, status and effective instant. States
are `active`, `suspended`, `terminated`. Effective instants must include a time
and explicit UTC/offset, such as `2026-10-23T13:00:00Z`; Auth does not guess an
employer timezone. Unknown columns, including payroll data or credentials,
are not retained. Files are bounded to 1 MiB, 200 records and 100 columns;
invalid encoding, malformed/duplicate fields, IDs or emails and invalid typed
profile fields are refused or held. Empty files and files above the explicit
termination threshold are held. Missing rows never mean termination.

Identity binding uses `hr` plus `<feed ID>:<source ID>`, never an email match.
An existing source can be explicitly bound through the ordinary reviewed
`/api/auth/directory/source` command before its first feed. A new ID whose
email already exists remains a collision requiring separate identity review.
A `manager` mapping names an existing Auth person ID. Alternatively map
`managerSourceId` to an external manager ID: it resolves only through an
existing HR source binding in this same employer and feed. Unknown IDs remain
in review; there is no email match or cross-employer fallback. For a new
manager in the same delivery, apply that manager first, then preview and
approve the dependent rows. Do not map both manager columns. The field precedence remains manual
override, HR, directory, self. Import hooks
run with the signed minimal source/email/name payload before review and apply;
they can change only an allowed name, never identity, proof, roles or policy.

## Run the SFTP listener

`connectors/sftp` is a Node 22.20+ service using pinned `ssh2@1.17.0`. Install
its dependencies with `npm install --prefix connectors/sftp`. Generate a
private SSH host key under the operator's custody and record its public host
fingerprint for source clients to verify. Do not disable host-key checking.

The mode-0600, operator-owned `AUTH_SFTP_FEEDS_FILE` is a JSON array with one
entry per authorized source:

```json
[{
  "issuer": "https://identity.example.com",
  "feedId": "<returned feed ID>",
  "publicKey": "<source SSH public key>",
  "fingerprint": "<registered source-key fingerprint>",
  "ingressToken": "<private one-time ingress token>"
}]
```

For an isolated employer, use its full `/org/<id>` issuer. The listener binds
the SSH username (feed ID), exact public key, fingerprint, issuer and private
ingress credential together. A path or file cannot select another employer.
Point `AUTH_SFTP_HOST_KEY_FILE` at the mode-0600, operator-owned private host
key, then run `node connectors/sftp/serve.mjs`. The default listener is
loopback port 2222; the operator can explicitly choose `AUTH_SFTP_BIND` and
`AUTH_SFTP_PORT` behind their own network controls. This guide does not deploy
a public listener or qualify an external hosting service.

Upload a plain basename ending in `.csv`. The listener has no shell, command,
filesystem, directory listing, download, rename, traversal or delete facility.
It accepts sequential bounded writes and posts only the completed CSV to the
bound Auth issuer over HTTPS (loopback HTTP only for local development).
It never follows redirects. SSH close succeeds only when Auth acknowledges
staging/holding the file. A lost acknowledgment can leave a staged file;
redelivery is digest-idempotent and cannot create a second file or person.

## Review and explicitly apply

An administrator uploads using POST `/api/auth/hr-feeds/upload` with
`{feedId,fileName,text}`, or reads the SFTP delivery under
`GET /api/auth/hr-feeds?feedId=<id>`. Add `fileId=<id>` to get typed current-time
native changes, rule/group/app effects, new-hire plans, collisions and future
rows, plus the exact review `digest`. A pending preview ID is not a credential.

POST `/api/auth/hr-feeds/apply` with `{feedId,fileId,digest,rows:[0,1],confirm:true}`
using the same normal administrator gates. A termination-threshold hold also
needs `confirmHeld:true`; malformed files cannot be confirmed into validity.
The current reviewed data/hooks must still match the digest. The selected rows
must be current and eligible; future dates, identity collisions and changed
source or email bindings refuse at this immediate-application door.
Each current effect uses the native directory commands and their source,
rank, rule, authority and optimistic-plan checks. The native change, durable row progress and approver and digest audit receipt
commit in one transaction. After an interruption, scheduled maintenance
resumes only the remaining approved rows and reconciles pending local effects.
A stable HR source cannot silently become a second person. A temporary
fail-closed hook outage leaves work pending; a changed hook result, target,
source binding or authority returns it to review. There is no whole-file
atomicity claim.

A new hire remains invited, with no session, factor, administrator right or
outbound invitation. Their normal browser-bound Auth email proof and factor
enrollment remain necessary. Local completion is explicitly separate from
remote provisioning/read-back: `remote: "unverified"` never means downstream
access is finished. Close a reviewed file with POST
`/api/auth/hr-feeds/close-file` and `{feedId,fileId,confirm:true}`; this closes
review without performing another directory action.

## Approve exact dated work

Use POST `/api/auth/hr-feeds/approve` with the same explicit file, preview
`digest`, selected `rows` and `confirm:true`. A destructive hold also needs
`confirmHeld:true`. This approval requires a hardware-passkey administrator
session and fresh local email proof. It authorizes only those rows of that
file, including their exact future effects. It grants no recurring feed policy.

The scheduled Worker executes an approved row no earlier than its effective
instant or its mapped start date at UTC midnight, whichever is later. Current
rows execute at the next scheduled maintenance pass. No human session is
stored or fabricated. The approver must still be an active owner or
administrator at the approved version; the feed custodian must also retain
current authority. The original file digest, row content, source binding,
target and native plan must still match. Any change returns the row to
`review_required`; read the preview again and explicitly approve the new plan.
Demotion, removal, disabling the feed or closing the file prevents pending work.

GET the file preview to inspect `approvals`: due times, approving person,
approved digest, progress and any refusal. Activity records one native
application receipt per row with its approver and digest. Repeated or concurrent
maintenance does not repeat a committed directory change. Completion remains
local; remote provisioning is separately unverified. No approval authorizes
outbound invitations, reminder messages or a later unapproved delivery.

## Freshness, retention and shutdown

No valid delivery by schedule plus one interval (two hours/days) flags the
source stale. Malformed, empty or invalid-profile data cannot reset a successful-read time.
A valid file held for destructive confirmation is still a successful source
read; its effects remain held until explicit approval.
A durable owner-held follow-up appears in Activity/API, is deduplicated across
restart, and stops when a valid next delivery restores freshness or the source
is disabled. This profile adds no outbound recipient consent: HR-source email
reminders and early-send stay disabled unless an explicit audited follow-up
policy separately selects the source-owner duty. Registering or approving a
file never selects that duty.
A reminder would not prove lifecycle or provisioning completion.

POST `/api/auth/hr-feeds/disable` with `{feedId}` under fresh administrator proof
to destroy the credential digest and end subsequent uploads. Removing its
private SFTP binding also ends key acceptance. Existing file review data does
not restore an old credential. Files/rows follow `sourceSnapshots` retention;
unclosed review remains unfinished evidence, and closed files enter the
existing configured retention/export/hold process. Per-person erasure removes
that person's retained rows without deleting another worker's snapshot.
Feed credential/configuration, staged files and jobs are excluded from transfer
archives; a destination must establish its own custody and consent.

AUTH-HRIS-002 uses CT's 24 October approval: each exact file requires explicit
human approval, and only its approved dated changes may execute. Unapproved
recurring pulls never apply; outbound actions require separate consent.
HRIS-001 and SCIM-002 inherit these identity, hook, hold, current-authority,
exact-approval, interruption-recovery and consent obligations before automation.
