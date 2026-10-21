# Owner-authorized erasure

Erasure is a separate owner action from suspension. The owner signs in with a
passkey and confirms their email in that session within ten minutes. Every
erasure write rechecks that live authority in its transaction.

First record an explicit policy with `POST /api/auth/erasure/policy`:

```json
{"confirm":true,"automaticDeletion":false,"honorLegalHolds":true}
```

The default is unconfigured: data is not automatically deleted and confirmation
is refused until the owner records this policy. This erasure policy does not
set the separate audit-retention schedule. It always preserves anonymized
event/decision history and refuses an applicable active legal hold.

`POST /api/auth/erasure/hold` takes `kind`, `target` and a reason. Supported kinds
are `person`, `app`, `organization`, and `installation`. Release a hold with
`{"id":"the-hold-id","release":true}` through the same owner door. Organization
and installation holds protect all records in their selected namespace.

1. `POST /api/auth/erasure/preview` with `{"kind":"person","target":"person-id"}`
   lists per-store removal/anonymization counts, remote work, applicable holds
   and named limits. An app target is its company-app or linked-client ID.
2. Review the preview. It expires after ten minutes and changes to underlying
   state require another preview.
3. `POST /api/auth/erasure/confirm` with `previewId`, `confirmation:"ERASE"` and
   `confirmRemoteDeletion:true` authorizes the displayed removal, including
   remote SCIM deletion and authority revocation. A prior preview alone never
   authorizes external destruction.
4. Save the response's receipt reference and signed `journal`. The receipt
   records local completion separately from outstanding remote work.

`GET /api/auth/erasure/receipts` shows policy, holds and receipts with per-store
counts and remote status. `GET /api/auth/erasure/journal` returns the latest
signed journal. Both require an owner session with passkey proof.

SCIM removal is verified by a read returning 404. Provider denials, outages and
unverified removal remain blocked or failed. The minimum account identifier
and connector credential required for unfinished work remain sealed under the
installation key; they are erased after verification and never appear in the
receipt, journal or ordinary export. Explicitly authorize another attempt with
`POST /api/auth/erasure/retry` and
`{"receiptId":"receipt-id","confirmRemoteDeletion":true}`. Existing local
sessions, factors and grants are removed even when the provider is unavailable.

Linked applications receive an identity fence when the saved callback and
subject are available. This revokes Auth-issued authority; it does not prove
that the application deleted its independent database. Every affected linked
app is therefore also named as a partner deletion task. Ask the partner to
remove its independently held profile, credentials, exports and delivered
messages, and retain its confirmation. Already delivered email/SMS and data
independently held by Google, Microsoft, Okta or another provider cannot be
recalled by deleting local Auth records. Local outbox copies are removed.

The last active owner cannot be erased as an ordinary person. Transfer ownership
first, or choose the protected organization reset: preview `kind:"organization"`
with the selected organization's ID, then confirm the exact phrase
`RESET <issuer>`. This removes that namespace's records, including owners,
while retaining anonymized evidence, receipts and the journal. Download the
confirm response: the session used to reset the organization no longer exists.

A root local installation can similarly preview `kind:"installation"`; hosted
installation deletion is refused. If other organizations exist, the API refuses
root-namespace reset and directs the owner to the whole-installation CLI path;
it never reports those other organizations as erased. For removal of every local organization and
private installation settings, save the receipt/journal and resolve outstanding
remote work before using the existing `rer reset --yes` command. Reset removes
the wrapping key too, so unfinished remote work cannot be retried afterwards.

After erasure, create a new portability archive with `rer export --output exports/after-erasure.rer`. Keep it outside any installation that you will reset. This later archive carries Base's installation-wide erasure checkpoint, including erasures in an employer namespace. Restore uses the existing public command:

```sh
rer import --input exports/before-erasure.rer --journal exports/after-erasure.rer --yes
```

The later journal makes Base refuse the entire pre-erasure archive with `erasure_epoch`. It cannot resurrect its personal rows or its earlier identified audit copies. Restore the new post-erasure archive to retain anonymous history. The API's signed JSON journal accompanies the receipt for accountability; the `--journal` argument takes the later `.rer` archive, not that JSON document. An old archive cannot discover a later journal that its owner did not supply.
