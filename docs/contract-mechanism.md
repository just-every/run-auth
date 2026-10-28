# Auth contract mechanism and retained profiles

These profile details explain the Auth-specific controls. CONTRACT.md owns acceptance and status.

## AUTH-TENANCY-001

**Current scoped administration semantics (ct 21 Oct 22:55Z; public-door conformance proven):** The original installation retains its issuer and tables. New employers have separate physical stores, path issuers, factors, sessions and signing keys; installation roles confer no directory read/write/export authority in an isolated organization. Existing HTTP tests cover proven-session switching, expiring/cancelled invitations, one-app/one-case delegation and cross-employer denials. All current organizations are isolated. Scoped credential custody and the 1440/390 authority journey pass; named HTTP assertions now cover installation-owner/admin read/write/export and issuer/connector credential refusals, including renamed cookies. The current authority journey passes at 1440 and 390. Complete organization-schema restoration remains under AUTH-TRANSFER-002; current archives fail closed without provisioned destination schemas.

## AUTH-ROLES-001

**Current scoped administration semantics (ct 21 Oct 22:55Z; public-door conformance proven):** Custom and built-in roles, separate view/edit resource sets, membership-sensitive decisions, previewed grants and audited scoped commands are implemented. Existing HTTP assertions cover equal-rank account-administration refusals, higher-owner administration, viewing without a rank fence and refusal of administrator factor reset. The ratified permission/resource/rank order and immutable built-in ranks are published in `docs/administrator-roles.md`. Named HTTP journeys prove scoped admin API credential custody, rank/no-widening, owner-only isolated custom-role design, exact gain/loss previews and hardware/fresh-email gates; the authority journey proves the current controls at 1440 and 390. Future machine doors inherit AUTH-ADMINAPI-001, and ordinary decisions inherit AUTH-DECISIONS-001 before shipping.

## AUTH-HRIS-002

Current execution follows CT's 24 October ruling: a human approves an exact
file, selected rows and their preview digest with hardware and fresh local
email proof. Only those changes may execute when due, after rechecking the
approver's current authority, approved content and target. Drift returns to
review. Recurring pulls cannot approve themselves; outbound consent remains
separate. AUTH-HRIS-001 and AUTH-SCIM-002 inherit these exact-approval and
interruption-recovery obligations before adding automation.

## AUTH-ADMINAPI-001

**Current v1 semantics:** Exposes native people/profile/lifecycle, groups/rules/membership, SAML/OIDC company apps and assignments, exact-domain provider requirements, configured-provider availability, domains and safe audit reads. Resource sets are explicit people/group/app IDs; creation requires unrestricted access to the new resource kind, and compound effects must remain within the grant. Provider identity and credentials remain owner configuration; `idps.manage` enables or disables that configuration and cannot replace its issuer, client or bindings. Tokens are issuer-local, at most five minutes, with live owner/revision/IP checks; mutations use guarded native commands and atomic shared-revision ETags. AUTH-ROLES-001, AUTH-POLICY-001 and AUTH-FEDERATION-001 inherit the same scoped, excluded-action, audit and concurrency obligations for their future machine doors before shipping.

## AUTH-FOLLOWUP-001

**Reminder policy (ct 22 Oct):** Reminder policy (channels, schedules, escalation, recipient rules) is an organization administrator write under AUTH-DECISIONS-001, by the owner or a role holding the published 'manage follow-up' permission; installation roles have none in an isolated organization. Until that write, obligations stay visible in Activity and no reminder is sent. Recipients are roles, never addresses: the person whose action is due (the employee for their own enrollment or recovery, the decider AUTH-DECISIONS-001 names for a request or review, the help desk holding the case), with escalation to an owner or administrator the policy names. Each recipient is rechecked at dispatch against current membership, state and authority; a failed recheck escalates instead. No recipient outside the organization, no free-text address, and no reminder carries a credential or a link that acts without its door's own proof. A reminder never performs a destructive or authority-changing action, and transport acknowledgment never counts as access success. Anyone currently holding an obligation may send its due reminder early, only to recipients the policy already allows. Source completion, cancellation or expired authority stops reminders at the next dispatch; history is kept under AUTH-RETENTION-001 and erased under AUTH-ERASURE-001.

## AUTH-ERASURE-001

**Current erasure semantics (ct 21 Oct 22:55Z; custody conformance proven):** Owner proof, explicit policy, exact preview/confirmation, whole-hold refusal, per-store erasure, separate remote outcomes, the shared fail-closed registry and signed anonymous audit are implemented. The ratified reset policy separates anonymous receipts/outcomes from sealed pending identifiers, destroys employer connector credentials and limits installation-owner custody to previously authorized work through a fresh tenant-bound connection. HTTP journeys prove those custody requirements, erased-issuer doors, root audit and cleanup. Named HTTP assertions also cover owner hardware/fresh-email gates, installation-admin refusal, unknown-registry refusal, stale person previews, employer-owner erasure, live credential termination, successful revocation retry without deletion consent and external-copy limitations. CT 22 Oct 00:20Z assigns voluntary membership links and opaque release obligations to AUTH-ERASURE-002. Installation-identity erasure does not search, match, enumerate or wait on separate employer identities. The Base journal currently refuses the whole earlier archive; restore that applies the journal and restores inactive remains AUTH-TRANSFER-002. Whole-hold refusal is the conservative interim, and AUTH-RETENTION-001 expiry remains separate.

## AUTH-ERASURE-002

**Receipt access (ct 23 Oct 10:25Z, approved with riders):** A person explicitly requests their own key from their own passkey session. It is shown once, stored only as a digest and body-posted, never placed in a URL or log. It reads only that person's receipt and cannot sign in, erase an identity or list memberships. It expires after thirteen months; the person may explicitly surrender it, including after sign-in ends. Expiry and revocation retain anonymous facts and clear the receipt payload. Each notice in the receipt carries only its random handle, erasure reference and state, with no employer, organization or count. CT requires this clause to remain partial.

## AUTH-AGENT-006

**Current profile:** Owner-registered HTTPS resources publish scopes, operations and an authorization-details type. One POST task binds an exact person, object and JSON arguments. The resource authenticates its own key and redeems the original agent DPoP proof at Auth before an effect; the live guarded transaction consumes the task once. No automatic outbound call or general MCP OAuth discovery is claimed. A release receipt records authorization with remote outcome unknown; My account revocation refuses the next call. Future resource profiles inherit these live-check, sender-binding, exact-task, independent-proof and no-false-completion obligations before shipping.


## AUTH-PROTOCOL-001 provider detail

Both algorithms’ keys are encrypted under AUTH_ENCRYPTION_KEY, published before use and retained through outstanding token expiry.

## AUTH-OPS-001 provider detail

(`seed.json` non-goals)

## AUTH-OPS-001 provider detail

(Cloudflare Workers with D1, as `deploy.json` defines it)

## AUTH-LOGOUT-002 provider detail

Google Workspace (Admin SDK Directory `users.signOut` and deletion of the user's OAuth tokens), Microsoft 365 (Microsoft Graph `revokeSignInSessions`), Slack (`admin.users.session.reset`, Enterprise Grid), Zoom (revoke the user's SSO token), Salesforce (revoke the user's OAuth tokens and end their sessions) and GitHub Enterprise (remove the user's SAML SSO credential authorizations).
