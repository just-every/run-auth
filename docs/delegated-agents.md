# Person-consented assignment task identities

This backend implements the native HTTP task profile for AUTH-AGENT-004, its full CONTRACT/ACCEPTANCE text and the seed plan's task-bound identity row. Its routes, OAuth dispatcher, migration, tenant namespaces and lifecycle stores are integrated. Owners register task agents on Agents. Employees review, consent to and revoke tasks in My account; independent administrators review and approve the same canonical task there. This native target needs no vendor credential or external provider integration. Existing RER, OIDC, preparer and machine administration credentials retain their own profiles.

The deliberately narrow task changes one existing direct company-app assignment for the consenting employee themself. It changes the app role, not an Auth administrator role. It does not create assignments, operate on groups, administer privileged people, accept arbitrary tool calls or call an external target automatically. Task authority lasts at most 24 hours, and each token lasts at most five minutes. One successful assignment change completes the task permanently.

Three separate identities matter:

- The **agent custodian** is the employer owner who registers the agent and its exact machine scopes/resources.
- The **accountable employee** sees the immutable concrete task and explicitly consents. The employee must sign in with a passkey. This does not confer admin proof or supply employer approval.
- The **independent approving employer owner or administrator** signs the exact task with a passkey and fresh local email. They must differ from both the employee and the agent custodian. Only legacy owner/admin authority qualifies; scoped custom roles and employees cannot approve.

No self-approval exception exists. The owner can appoint an independent administrator through the existing public people/role action; that administrator signs in again with their own passkey and fresh local email before approving. An app assignment is an ordinary access decision under the shared rank policy. There is no new owner-appointment, generic credential custody, session, preparer-key or impersonation door.

## Exports and parent dispatch

All exports live in `src/auth/agents/delegation/index.mjs`. Browser POST handlers accept `(ctx,request,data?)`; if `data` is absent they use the existing Origin-checked parser. They enforce their own Origin and identity/authority even when the parent supplies parsed data. Machine handlers use bounded JSON/form parsing without requiring a browser Origin.

| Public route | Export | Authority |
| --- | --- | --- |
| POST `/api/auth/delegations/agents/register` | `registerAgent` | Owner, hardware passkey, fresh local email |
| POST `/api/auth/delegations/agents/suspend` | `suspendAgent` | Owner, hardware passkey, fresh local email |
| POST `/api/auth/delegations/request` | `requestDelegation` | Registered agent private-key assertion |
| GET `/api/auth/delegations` | `delegationInventory(ctx,request)` | Person sees own tasks; hardware legacy owner/admin sees employer tasks/agents |
| GET `/api/auth/delegations/consent?id=…` | `delegationConsentView(ctx,request,grantId)` | Accountable person, or hardware legacy owner/admin for approval review |
| POST `/api/auth/delegations/consent` | `consentDelegation` | Accountable person's passkey session, explicit decision |
| POST `/api/auth/delegations/approval/options` | `delegationApprovalOptions` | Independent legacy owner/admin, hardware passkey, fresh local email |
| POST `/api/auth/delegations/approve` | `approveDelegation` | Same administrator/session plus exact WebAuthn challenge response |
| POST `/api/auth/delegations/revoke` | `revokeDelegation` | Accountable person's live session, or owner with hardware/fresh email |
| POST `/oidc/token` | `delegationToken(ctx,request)` | Registered agent private-key assertion plus approved live grant |
| POST `/api/auth/admin/v1/delegated-assignments/execute` | `executeDelegation` | Delegated access token, exact task payload and agent execution proof |

Paths are relative to the selected employer. For a non-root employer the actual issuer and endpoint URLs include `/org/<id>`. `ctx.db` must be the physically scoped employer database; `ctx.origin` is the actual HTTP origin, `ctx.issuer` is the employer issuer, and `ctx.organizationId` identifies that employer. Non-root final SQL guards additionally require the global `auth_organizations` row to remain active. Current new employers are isolated: a root installation session or hosted organization registry row never supplies employer consent, owner approval, signing keys or directory authority. This module does not introduce an installation-operated mode or project installation roles into an employer. Any future mode must still provide the employer-local proofs and published permission/resource boundaries before using these handlers.

Call `delegationToken` before existing token profiles. It reads a request clone and returns `null` for other client namespaces. Its namespace is `delegated-agent:`. It recognizes named delegated clients even when their assertion is malformed and returns a typed OAuth failure. Existing `adminToken` does not recognize this namespace.

Dispatch the fixed execution path before the generic `/api/auth/admin/v1` handler, or add an explicit branch within that handler. Do not let delegated tokens reach ordinary admin commands. The token’s audience is this exact execution URL, and it deliberately omits `admin_service_app`, `sid`, `amr` and human role claims. Thus ordinary admin, UserInfo and resource bearer verifiers cannot interpret it as their credential.

Handlers return actual `Response` values and use the existing `AuthError`. The parent must catch typed errors as it does for other Auth routes. Only `delegationToken` translates its own OAuth failures into JSON responses.

## Agent registration and suspension

`registerAgent` takes:

```json
{
  "name": "Assignment assistant",
  "purpose": "Owner-authorized employee assignment changes",
  "jwks": {"keys": ["actual public ES256 or RS256 JWK objects with distinct kid values"]},
  "appIds": ["company-app-id"],
  "personIds": ["employee-id"],
  "expiresAt": 1800086400000
}
```

The JWKS above describes the required object contents; use real public JWK objects rather than the explanatory string. Public key validation reuses `grants/public-keys.mjs`; private key material and secrets are refused. Arrays require explicit IDs and cannot contain wildcards. Registration expiry is mandatory, future, and at most 365 days ahead.

The result is `{id,clientId,name,scopes,resources,expiresAt,independentApprovalRequired:true}`. Registration creates an `auth_delegated_agents` row and a dedicated `auth_admin_service_apps` row in one owner-guarded batch. The backing machine scope is exactly `assignments.manage`; app/person resources are exactly the owner’s lists, and group resources are empty. The client ID remains in the separate delegated namespace. No secret or private key is minted or returned.

The credential’s public keys, client ID, custodian, resource sets, scopes and expiry are immutable at the database layer. Generic admin-service custody does not list, reassign or revoke these delegated backing rows. Suspension belongs to this module; it cannot widen or repurpose the credential. A change requires a new agent registration and new task consent.

`suspendAgent` takes `{clientId}`. It suspends the agent, advances its revision and permanently revokes unfinished tasks via a database trigger. This profile has no restoration shortcut or key-rotation shortcut. Register a new agent when reauthorization is needed.

## Exact task and agent request

A canonical task has these fields, all mandatory:

```json
{
  "organizationId": "root",
  "accountablePersonId": "employee-id",
  "personId": "employee-id",
  "purpose": "Change my approved documentation role to editor",
  "apiId": "auth.assignments",
  "audience": "https://auth.example/api/auth/admin/v1/delegated-assignments/execute",
  "resource": "assignment:company-app-id:person:employee-id",
  "operation": "assignment.update",
  "appId": "company-app-id",
  "role": "editor",
  "scopes": ["assignments.manage"],
  "expiresAt": 1800003600000
}
```

Timestamps are integer milliseconds, not fixed defaults. Compute deadlines from the actual clock. `accountablePersonId` must equal `personId`. The target must be an active employee with an existing direct assignment, legacy `member` role and no active scoped role grants. The requested role must differ from the current role. Task expiry cannot exceed 24 hours or either agent/backing credential expiry. API, audience, resource syntax, operation and scope are fixed by the server; unknown fields fail. There is no caller-supplied endpoint, callback, SQL, document instruction or executable policy.

`requestDelegation` takes `{clientId,clientAssertion,task}`. The signed assertion contains standard `iss=sub=clientId`, `aud=<issuer>/api/auth/delegations/request`, integer `iat`/`exp` spanning at most five minutes and unique `jti`. It also contains `delegation_use:"request"` and `request_hash=SHA256-base64url(JSON.stringify(canonicalTask))`.

Canonical property order is exactly the order shown above. The module exports the canonicalizer and hashing functions from `effect.mjs` for a client implementation to mirror. Values are strict: strings are not silently trimmed, IDs are bounded, scope order is exact and expiry is numeric. Signing this normalized digest binds the request payload to the agent’s key.

Auth reads person/app/assignment and native/role epochs together, then guards their unchanged values when inserting the task. It returns `{grantId,effectDigest,consentPath,state:"requested",expiresAt}`. `consentPath` points to the selected employer's `/app/account?delegation=<grantId>`. The final `effectDigest` additionally binds the unpredictable grant ID and server-observed target/agent/service preconditions; use the returned value unchanged in consent, approval, token proofs and execution. The task effect and all preconditions are immutable in the database.

The native administration epoch is deliberately pinned for the task's lifetime. Any intervening native administration invalidates the request, even when an unrelated change caused it. Create a fresh request and consent rather than silently rebasing an approved task. The creation role epoch remains immutable evidence in the digest; it is not a lifetime gate, because the existing role epoch also advances on passkey counters, including the required independent approval. Every committing decision instead takes a fresh shared machine-principal owner snapshot and guards that snapshot's role epoch atomically. The target's person/app versions and exact prior assignment remain fixed. Adding an unrevoked scoped role grant to the employee permanently revokes unfinished tasks, so later removal cannot revive them.

## Consent, approval and visible state

`delegationConsentView` supplies the canonical task, exact `before`/`after` roles, employee/app/agent labels, effect digest, revisions, timestamps, `authorityCurrent`, `canConsent`, `canApprove`, agent custodian ID and explicit approval/revocation-reach explanations. Parent UI must render this server-held view and escape all text. It must show the employer and deadline, concrete effect, separate independent-administrator requirement and the limits of revocation before presenting the consent action. A stale or expired task is not active even if its retained database state still says requested/consented/approved.

`consentDelegation` takes `{grantId,effectDigest,decision:"consent"}`. It binds the decision to the current employee/version and live passkey session, advances the task from requested to consented and records the consenting session and time. A person's consent is insufficient to issue a token.

The independent owner/admin first calls `delegationApprovalOptions` with `{grantId,effectDigest}`. It returns `{transaction,options,grantId,effectDigest}` and a short browser-binding cookie. The WebAuthn challenge binds grant ID, effect digest, current task revision and administrator session. `approveDelegation` takes `{grantId,effectDigest,transaction,response}`. It verifies the exact challenge, user verification, administrator, browser, session and counter; the counter and task approval commit together under the existing transaction-local latch. Fresh email, hardware legacy owner/admin authority, unchanged target and prior employee consent are checked inside that transaction.

`delegationInventory` returns `{organizationId,targetApi,grants,agents,hasMore,nextCursor}`. It returns up to 100 tasks in stable newest-first order; use `?before=<nextCursor>` to continue. The parent’s My account UI must expose subsequent pages rather than hiding older active grants. Each grant includes the canonical effect, before/after role, state, `authorityCurrent`, consent/approval/completion/revocation times, approver, execution receipt and revocation reach. Private keys, assertions, bearer tokens and secret digests are absent. Accountable people can inspect their own tasks in My account without gaining employer-wide inventory.

`revokeDelegation` takes `{grantId}`. The accountable person's current session can end their own unfinished task without requiring another administrator's approval or fresh admin email. Another person needs owner hardware/fresh-email authority. It ends token issuance and the next execution request immediately. It does not undo a completed assignment or claim every downstream session was revoked. Existing provisioning and session lifecycle mechanisms remain separately accountable.

## OAuth token and exact target invocation

The agent posts form fields `grant_type=client_credentials`, `client_id`, `client_assertion_type` containing the standard JWT bearer assertion type, `client_assertion`, `grant_id`, exactly `scope=assignments.manage`, and `resource=<exact execution URL>` to `<issuer>/oidc/token`. The resource indicator restricts the audience under [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html). Only the declared private-key profile is accepted; repeated or undeclared parameters and other grant types fail.

This assertion has `iss=sub=clientId`, `aud=<issuer>/oidc/token`, `iat`, `exp`, unique `jti`, `delegation_use:"token"`, `grant_id` and `effect_digest`. Assertions are signed with the registered public-key counterpart, expire within five minutes and are one use. The token endpoint checks current person consent, independent legacy owner/admin approval/version, agent/custodian/service authority, target snapshots and expiry. Signing is followed by a final guarded committing write, so authority lost while cryptography runs wins that race.

Refusal audit distinguishes authenticated identity from attempted identifiers. Token refusals record `attemptedClientId` and `attemptedGrantId`; those values alone never supply an actor, grant subject, accountable person or approver. Only verified registered-key DPoP plus a client assertion signed for that exact grant and effect supply full agent/person/approver attribution, including scope/resource refusals before token issuance. Replay and invalid nonce refusals retain the authenticated signer while still denying authority. A human cookie or preparer key cannot authenticate this profile at either the token or execution door. Activity never stores the raw assertion, proof, token or preparer key. Token requests charge both per-agent proof budgets (120 requests per minute) before signature verification, including requests with refused scopes or resources. Exhaustion returns 429 with Retry-After: 60 and records only attempted identifiers because no proof is verified. Request assertions and execution DPoP share their respective agent budgets with the token door.

Both endpoints require [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) DPoP with a registered agent public key. A valid signed token-endpoint proof without a current nonce receives HTTP 400 `use_dpop_nonce` and `DPoP-Nonce`; this challenge consumes neither the DPoP proof identifier nor the client assertion. The target issues HTTP 401 nonce challenges. Nonces are separate per endpoint, agent and key and last five minutes. Supply a fresh proof with the returned nonce; there is no automatic application retry.

The response contains `access_token`, `token_type:"DPoP"`, `expires_in`, `scope`, `authorization_details`, `grant_id` and `effect_digest`. The signed [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) `at+jwt` has the accountable person's ID as `sub` and the agent as [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) `act:{iss:<issuer>,sub:"agent:<agent-id>"}`. `cnf.jkt` binds the token to the registered DPoP key's SHA-256 JWK thumbprint. Client/agent/service/grant IDs and revisions, employer, person version, exact resource, API and digest remain bound. Its only audience is the fixed execution URL; it carries no human session or reusable admin proof.

The exact [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) authorization detail is `[{type:"auth_assignment_task",locations:[task.audience],actions:[task.operation],identifier:task.resource,grant_id:grantId,effect_digest:effectDigest,task}]`, where `task` is the complete canonical approved task. Optional token-request `authorization_details` must equal that detail; extra authority is refused. The response and JWT always contain it, and the target compares it with the immutable grant and request body.

Execution uses `Authorization: DPoP <token>`, a `DPoP` header, and JSON `{grantId,effectDigest,task}`. The bespoke body proof is removed. DPoP headers have `typ:"dpop+jwt"`, an asymmetric `alg`, and public `jwk`; claims contain `jti`, `iat`, `htm:"POST"`, endpoint `htu` without query/fragment, and nonce. Target proofs also contain `ath=SHA256-base64url(accessToken)`. Missing/foreign/replayed proofs return 401. Canonical body substitutions return 403. A second execution with fresh valid proof returns 409. DPoP replay identifiers are separate from request/token client-assertion identifiers.

The target awaits the existing asynchronous `principalFor(ctx,service,["assignments.manage"],expiresAt)` and preserves its live `ownerState` and `guard` accessors. This reuses the accountable service owner's current role permissions, effective dynamic groups and exact view/edit envelope. Both the task guard and native `writeAdmin` require `apps.assign` for the same app/person; no union of unrelated resource grants opens a broader operation. `prepareAuthority()` refreshes the snapshot immediately before the committing batch, and the current role epoch fences that decision. Rank grants no permission; the current shared rank policy treats an app assignment as an ordinary access decision, while this profile independently excludes privileged target accounts and exposes no account-administration command.

A single D1 batch claims the existing `auth_admin_api_commits` latch under all live authority and target preconditions, completes the task, runs the guarded native assignment mutation, records the attributed execution receipt and removes the latch. Native epoch triggers cannot split that transaction. Native post-write checks recognize the won claim; they do not reject a committed assignment because its own native/role epoch or task state changed. Every later request reconstructs live authority and sees completion. Concurrent/repeated execution has one winner; completion prevents every later token or execution request.

Native assignment audit and normal event/provisioning follow-up are retained. This module never automatically invokes a task or adds an outbound connector operation during request, consent, approval or token issuance. If post-commit native follow-up fails, the assignment and completion receipt remain committed, an explicit follow-up failure audit is recorded, and the error is surfaced; do not report that as a rolled-back assignment or retry the completed task.

## Lifecycle, persistence and integration obligations

Migration `0043_auth_delegated_agents.sql` adds `auth_delegated_agents`, `auth_delegated_tasks`, and short-lived replay identifiers in `auth_delegation_assertions`. Migration 0044 adds `auth_delegation_dpop_nonces` and `auth_delegation_dpop_proofs`; 0045 adds `auth_delegation_reversals`. The profile uses existing admin-service authorization, encrypted issuer signing keys, machine resource checks, native assignment commands and the transaction-local latch. Raw tokens, proofs and nonce values are not persisted.

Live gates include employer activation, active/version-bound employee, active/version-bound registering owner, independent approving owner/admin version, active agent/revision, backing machine credential/revision/expiry, the shared owner's current permission/resource snapshot, task deadline/state/revision, exact target snapshots, consent and approval. Employee or approving-administrator status/version changes, an employee scoped-role grant, and agent suspension persistently revoke unfinished tasks. Custodian/service authority is rechecked online; restoration never revives a task pinned to an earlier revision/native epoch. Expiry requires no scheduler to deny authority. Inventory retains ended tasks and reports `authorityCurrent:false` when live authority has ended; it never turns a denied authority check into permission.

All profile stores are registered in the shared erasure/export/restore inventory. Agent, task and reversal stores are installation-local and excluded from portable archives, as are their backing admin-service rows; restore cannot recreate this authority. New owner registration, person consent and independent approval are required at the destination. Tasks contain personal/purpose/effect data and approval evidence. Erasure removes immutable task effects and their dependency rows, preserving anonymous kind/status/time decisions in the erasure receipt and anonymized activity. Agent/service rows carry custody and public key configuration. Client-assertion replay state, DPoP nonce hashes and DPoP proof identifiers are transient and expire under scheduled maintenance; cleanup never removes a task receipt. Tenant schema creation automatically namespaces the stores and triggers. HTTP fixture migrations include 0043–0045.

Public HTTP and browser journeys accompany this profile. CONTRACT.md and ACCEPTANCE.md record the current proof and pending policy ruling. No certification, external provider compatibility or blanket remote revocation is claimed.

## Acceptance integration map

Acceptance must exercise the complete published journey without reducing it to row deletion checks: create an exact task for one assignment and fixed deadline; render its concrete before/after effect and independent approval requirement; perform person consent and independent employer owner/admin WebAuthn/fresh-email approval; obtain a real private-key OAuth token; invoke the native target; and inspect separate agent/person/approver attribution. A second unfinished grant must be visible and revocable through My account, with its next token/target request refused. HTTP probes must substitute person, employer, purpose, app/resource, target/API, operation/role, scope, deadline, digest, agent/token/key and proof; exercise expiration, person/employer/agent suspension, task completion, revocation, assertion replay and concurrent execution. App/document instructions remain ordinary bounded text, and cannot introduce a field, target, scope or execution path. Consent and inventory UI proof is needed at the home's desktop/mobile sizes. These routes/UI, lifecycle-store integration and proofs are seed-owned work; an external OAuth/MCP provider is not a prerequisite for this documented native HTTP target.
