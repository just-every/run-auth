# Reviewed first-login migration bridge

The v1 bridge verifies an eligible workforce worker's old password once, then uses Auth's own browser-bound email proof and passkey enrollment. It never imports a password hash or factor, creates an administrator, or makes the old password an Auth credential. Google Workspace/Auth0 staging and their existing formats remain supported.

## Custom directory export and review

Upload this documented synthetic format through the existing Move-in staging door (`POST /api/auth/move-in/stage`, JSON `{fileName,text,exportDate}`). Use an authorized export and retain the same immutable directory identifiers:

```json
{
  "format": "auth-custom-directory",
  "version": 1,
  "people": [{
    "directory_id": "synthetic-auth-1",
    "email": "worker@example.com",
    "name": "Example Worker",
    "disabled": false,
    "history": [{"at": "2025-01-01T00:00:00Z", "values": {"department": "Support", "title": "Analyst"}}]
  }]
}
```

History accepts up to 100 dated snapshots per person, with bounded string fields `name`, `title`, `department`, `location` and `workerType`. Unsupported password hashes/factors are ignored, explicitly require reset/reenrollment and confer no authority. Staging retains only the documented directory/profile data. The Move-in review API includes the immutable profile history; admission preserves the reviewed identifier-to-person map in the existing former-subject export. Collisions retain their existing refusal/explicit-review semantics. Import history follows source-snapshot retention and per-person erasure.

After reviewing and admitting rows through Move-in, an employer owner or administrator with a hardware passkey and fresh local email registers a bridge using POST `/api/auth/migration/bridge/register`:

```json
{
  "url": "https://directory.example.com/auth-migration/verify",
  "credential": "a privately supplied shared HMAC credential of at least 16 characters",
  "expiresAt": 1800003600000,
  "subjects": [{"sourceSystem":"custom", "sourceSubject":"synthetic-auth-1", "personId":"the reviewed Auth person ID", "batchId":"the admitted source batch"}],
  "confirm": true
}
```

The credential is a server-only secret; do not paste a real value into an agent conversation, shell argument, document or log. Supply it directly through an authorized private administrative client. Auth encrypts it under a bridge-specific label and never returns it. At most 200 subjects bind to one registration; each must be an unprivileged reviewed member, with a still-admitted, non-disabled source row and stable person/email/version. Google JSON, Auth0 and custom rows with source identifiers support reviewed maps; a Google CSV without a documented identifier requires ordinary enrollment/reset rather than an invented subject. A person cannot be silently rebound through a second bridge. Registration and all mappings commit atomically. Bridge lifetime is at most thirty days and can be shortened by its explicit cutover expiry.

## Verifier protocol

The verifier must be a canonical public HTTPS destination. Auth performs the existing public DNS/address checks, refuses private addresses and redirects and imposes a five-second timeout and a 2 KiB response bound. No provider error body enters a response, audit or agent context.

A worker's browser POSTs `{bridgeId,sourceSubject,password}` to `/api/auth/migration/bridge/login` with the normal same-origin JSON header. Keep the password in that one request body; never put it in a URL or command line. The operation is rate limited per IP and subject. Before verification, the signed `password_import` hook receives only the reviewed Auth person/source IDs and can refuse under the existing hook policy. It receives neither password nor verifier credential and cannot modify identity or permissions.

Auth sends the authorized verifier only:

```json
{"version":1,"id":"unique-call-id","subject":"reviewed-old-subject","password":"the worker's entered old password"}
```

Headers are `bridge-id`, `bridge-call-id`, `bridge-timestamp` (Unix seconds), and `bridge-signature`. The signature is `v1,` plus base64url HMAC-SHA256 of `callId + "." + timestamp + "." + exactBody`, using the private shared credential. The verifier must enforce that signature, a short freshness window and one-use call IDs, then verify the worker's actual legacy credential. Its only successful response is JSON `{authenticated:true,subject:"the same reviewed subject"}`. Wrong passwords, another subject, extra response fields, malformed/unavailable responses, stale or disabled workers, undone sources and changed authority grant nothing. The bridge does not accept an unverified "email matches" answer.

After network verification, Auth rechecks the live bridge, custodian, source batch, person status/version/email and role policy. A compare-and-set records one completion. Auth then sends its own email link bound to that browser; the worker confirms it and enrolls a new Auth passkey under current employer policy. Legacy verification itself creates no Auth session, app permission, factor or administrator authority. Reviewed former subjects and profile history remain stable, and the resulting worker can use the normal real app protocol.

## Interruption and cutover

A delivery interruption after durable verification leaves exactly one completed migration. A retry reports `already-migrated`, with `/signin` as the next step; it never verifies or trusts the old password again. The person resumes the ordinary email sign-in/enrollment door. No new imported person, recovered factor or invented password state is created.

POST `/api/auth/migration/bridge/disable` with `{bridgeId}` using fresh administrator proof to permanently end the bridge and destroy its sealed credential. No re-enable/update door exists. Expiry or custodian departure/demotion also refuses verification; scheduled maintenance destroys expired custody. Disabling during an in-flight verifier call prevents its commit. Completed migrations never regain old-password authority. Bridge credentials/mappings are excluded from transfer archives and included in erasure; source profile history remains subject to the source-snapshot retention policy.

`tests/auth/move-in-admission.test.mjs` — "reviewed custom-directory workers migrate at first legacy login with protected history, exact subject mapping, inherited hooks and permanent bridge shutdown" exercises this protocol through a network-edge verifier, Auth's real email/passkey doors and a real linked app, including wrong-password, disabled/mismatched subjects, interruption/restart and shutdown. This proves the documented integration protocol with synthetic exports; it does not claim a live incumbent tenant qualification.
