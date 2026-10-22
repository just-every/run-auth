# Employer retention and credential custody

Retention expiry is separate from owner-confirmed erasure. Each employer,
including the root installation's own directory, has its own retention policy,
period holds and cleanup runs. Installation roles cannot use an isolated
employer's retention doors. An owner or administrator with a hardware passkey
can read its policy and previews. Policy and hold writes, and downloads, also
require local email confirmation in that same session within ten minutes;
writes recheck this authority in their committing statement.

`GET /api/auth/retention` publishes the policy, class list, active holds and the
latest 100 accountable cleanup runs. New installations retain every class for
13 calendar months. Default periods and previews do not authorize deletion: an owner/admin must explicitly confirm and save the policy before scheduled expiry begins. Policies accept days (90–2555), calendar months (4–84), or
calendar years (1–7). Ninety days is the floor; seven calendar years is the
maximum. Three calendar months can be shorter than ninety days and are refused.
Calendar subtraction clamps month-end and leap dates without converting months
to fixed thirty-day intervals.

Save all class periods through `POST /api/auth/retention/settings`:

```json
{
  "confirm": true,
  "classes": {
    "profiles": {"unit":"months","value":13},
    "sourceSnapshots": {"unit":"months","value":13},
    "authentication": {"unit":"months","value":13},
    "decisions": {"unit":"months","value":13},
    "provisioning": {"unit":"months","value":13},
    "audit": {"unit":"months","value":13},
    "modelTraces": {"unit":"months","value":13},
    "erasureReceipts": {"unit":"months","value":13}
  }
}
```

The change and exact periods are audited atomically. A new policy cancels any
queued deletion plan and destroys its private snapshot. A subsequent cron or
preview prepares a new plan with a fresh export window.

| Class | Existing data covered | Expiry boundary |
| --- | --- | --- |
| Profiles | Terminated directory field values and identity email/name | Time since termination; identity ID, status and references remain |
| Source snapshots | Admitted/undone import rows, completed import metadata, former subjects and terminated source bindings | Import creation or termination; staged imports and current source bindings remain |
| Authentication | Expired Auth sessions, completed/cancelled recovery history and notices | Session creation or completion; unfinished recovery and referenced parent records remain |
| Decisions | Completed scoped and business decisions, closed reviews/items/events, ended access requests | Recorded creation, decision or close; live decisions and remediation remain |
| Provisioning | Verified/superseded provisioning and terminal follow-up records/history | Verification or terminal time; pending, failed and blocked work remains |
| Audit | Sign-in/admin activity and details, Base operator audit, lifecycle events and successful deliveries | Recorded event time; unfinished deliveries and their events remain |
| Model traces | `model_` activity records and their details | Recorded event time; Auth currently produces no separate model transcript store |
| Erasure receipts | Completed receipts and verified, identifier-free remote outcomes | Receipt/outcome time; unfinished sealed work and its receipt remain |

Current identities do not expire merely because they were created long ago.
Terminated profile expiry replaces the name/email with an anonymous placeholder
and removes expired directory values. It preserves identity references and does
not claim the identity has been erased. Credentials remain in their established
server-only custody and lifecycle until revoked, rotated or explicitly erased.
The erasure journal, authenticated anonymous expiry commitments and portability
fences remain durable. Expiry commitments let earlier erasure integrity checks
distinguish authorized policy expiry from unrecorded audit deletion. Reset-retained
work stays under its existing installation-owner custody; retention never opens
an erased employer namespace. Parent records with
retained children wait for a later cleanup rather than cascading away evidence.

## Holds and unfinished work

Open access reviews automatically hold their inclusive review period. Pending,
approved and revocation-pending access requests retain their period and all
later evidence until the operation ends. Unfinished follow-up, provisioning,
recovery, role cases, proposals, delegated work and remote erasure work also
retain their evidence period. Protection is deliberately wider than matching
one identifier inside an audit JSON document. Completing a transport attempt
alone cannot make an unfinished operation eligible.

Owners/admins can add an independent period hold through
`POST /api/auth/retention/hold`:

```json
{"kind":"investigation","periodStart":1767225600000,"periodEnd":1798761599999,"reason":"Case under investigation","classes":["audit","decisions"]}
```

Kinds are `review`, `request`, `investigation` and `legal`. Omit `classes` to
hold all classes. A hold has no automatic end: release it through the same door
with `{"id":"the-hold-id","release":true}`. Creation and release are audited.
Existing erasure legal holds conservatively stop all expiry in that employer.
A hold added after preview is still enforced when cleanup commits.

## Preview, export and scheduled cleanup

`GET /api/auth/retention/preview` returns currently eligible records, counts and
class periods. `POST /api/auth/retention/preview` with `{}` prepares the same
kind of durable plan the cron prepares. A plan covers at most 200 records; the
next plan drains additional eligible records. It remains downloadable for at
least seven days before any deletion.

Download `GET /api/auth/retention/export?runId=<id>` before its `deleteAfter`
time. The owner/admin must have fresh local email proof; the download is
audited. Its fixed allowlist omits credential-bearing stores and session token
hashes. Plans are private local state, excluded from portable archives, and
contain the exact credential-free candidate rows. Completion or cancellation
destroys that snapshot.

The scheduled handler deletes only unchanged candidates from the queued plan,
rechecking current holds and unfinished work in the same D1 transaction. New
aging never widens an earlier plan. Changed or newly held rows are skipped.
A transaction claim prevents two cron invocations from deleting twice. The
run's per-store actual counts, authenticated anonymous expiry commitments and
completion audit commit with cleanup; a
Worker restart cannot turn an unverified obligation into a completed one.
A later run considers skipped or additional records with a fresh seven-day
window. Short-lived challenges, rate limits and protocol replay state keep
their existing short expiry independently; their expiry does not remove the
durable source or follow-up evidence.

## Storage, processors and secret limits

The employer selects its deployment, storage region and processor arrangement,
including a US arrangement when it requires one. This policy API does not move
data or certify a storage location: it returns `verifiedRegion: null` until
separate deployment evidence exists. The employer must establish its hosting,
mail, connector and external audit receiver arrangements with those providers.
No legal retention period is inferred by Auth.

Signing private keys and connector credentials are sealed with AES-GCM under
the installation's encryption key and decrypted only inside their scoped
server operations. Production transport uses HTTPS. Existing signing-key and
connector rotation doors remain authoritative. The shared store registry
excludes credentials and sealed unfinished remote work from portability.
Retention exports never select these secret stores or raw session credentials.
Authentication links and credentials are not inputs to a model or ordinary
activity logging.

Delivered messages, exported archives, downstream app copies and external audit
receiver copies are owned by their respective mailbox, archive, application
and receiver operators. Auth's expiry counts describe its local stores. Those
operators must apply their own retention and deletion arrangements.
