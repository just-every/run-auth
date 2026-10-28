# Auth target product contract

Auth is an owner-run MIT workforce identity and single sign-on provider for US employers replacing Okta Workforce Identity, Microsoft Entra ID and JumpCloud, while keeping one sign-in for the owner’s linked RER apps. It brings employees and contractors into the right apps, changes their access with their work and proves access ended when they leave.

## Product target

| | |
| --- | --- |
| Category | Workforce identity and single sign-on (IdP) |
| Incumbents a buyer switches from | Okta Workforce Identity, Microsoft Entra ID, JumpCloud |
| Up-and-comers it must also beat | Rippling IT (identity), authentik, Zitadel |
| First buyer | US employer’s IT/security owner; USD, US employment norms and employer-local time zones |

The primary journey: Connect the employer’s directory and apps, onboard a worker, sign them in, change and review their access, then offboard and verify every access obligation.

## How to read this contract

- This follows the RER contract standard; Core, Agent surface and Later remain visible and count separately.
- Done means every acceptance outcome is proven through Auth’s own doors on the exact candidate; partial and missing retain the full target. Provider sandboxes and official-schema fakes gate product behavior; real vendor qualification is recorded separately.
- Field proof records real accounts, human reviews, approvals by stores and elapsed observations that local fixtures cannot establish.
- Base duties are cited once; clauses state Auth’s additions and run them on Auth scenarios.
- ACCEPTANCE.md and docs/CLAIMS.md are generated from this file. Historical scope, run receipts and buyer-review notes are in CHANGELOG.md; rulings are in RULINGS.md.

## Door rules

- **D-1.** Auth proof. Interactive administrator writes use AUTH-IDENTITY-001 and AUTH-DECISIONS-001’s role, hardware-passkey and fresh-email distinction; ordinary employee decisions use the employee path. Machine writes use AUTH-ADMINAPI-001’s scoped credentials. Hosting an isolated employer confers no employer authority.
- **D-2.** Agent policy. Auth’s Agent surface computes the call’s risk classes. The company’s policy decides what runs, enters review, waits for approval or is refused. References to approvals in legacy agent journeys describe the held company policy; personal proof is never fabricated.
- **D-3.** Personal-contact activation dispatch and day-one fallback follow AUTH-ONBOARD-002; the current authorized employer-local start governs each dispatch.
- **D-4.** Reminder custody. AUTH-FOLLOWUP-002 governs organization-local role recipients, current dispatch authority and early sends; source consent and completion remain distinct from access success.

## Shared duties (Base)

| Base duty | Duty | Delta clauses | Base journey |
| --- | --- | --- | --- |
| BASE-ACCESS-001 | Sign-in | AUTH-ENROLLMENT-001 | not run |
| BASE-ACCESS-002 | Sessions | AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-BOUNDARY-001, AUTH-MOVEIN-001, AUTH-ADMIN-001, AUTH-LINK-001, AUTH-LOGOUT-001, AUTH-TRANSFER-001, AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-PASSWORD-002, AUTH-TAP-001, AUTH-MFA-001, AUTH-POLICY-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-OIDC-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-SCIM-001, AUTH-LIFECYCLE-001, AUTH-TIMING-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-LEGACY-001, AUTH-GATEWAY-001, AUTH-PRIVILEGED-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-DECISIONS-001, AUTH-MIGRATION-001, AUTH-DEVELOPER-001, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-TRANSFER-002, AUTH-AGENT-004, AUTH-AGENT-007, AUTH-AGENT-005 | not run |
| BASE-ACCESS-003 | Public endpoints | none | not run |
| BASE-ACCESS-004 | Server-side authorisation | none | not run |
| BASE-INPUT-001 | Validation | AUTH-PRIVACY-001, AUTH-RER-TRUST-001, AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-BOUNDARY-001, AUTH-MOVEIN-001, AUTH-ADMIN-001, HTTP-001, AUTH-LINK-001, AUTH-LOGOUT-001, AUTH-TRANSFER-001, AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-DOMAINS-001, AUTH-PROFILE-001, AUTH-ENROLLMENT-001, AUTH-PASSWORD-001, AUTH-PASSWORD-002, AUTH-ONBOARD-001, AUTH-ONBOARD-002, AUTH-TAP-001, AUTH-EXPERIENCE-001, AUTH-LOCALE-001, AUTH-LAUNCHER-001, AUTH-SWA-001, AUTH-MFA-001, AUTH-AUTHENTICATOR-001, AUTH-POLICY-001, AUTH-ABUSE-001, AUTH-RISK-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-SAML-001, AUTH-OIDC-001, AUTH-MAPPING-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-M365-001, AUTH-SCIM-001, AUTH-SCIM-002, AUTH-SCIM-003, AUTH-SCIM-004, AUTH-HRIS-001, AUTH-HRIS-002, AUTH-LIFECYCLE-001, AUTH-TIMING-001, AUTH-WORKFLOWS-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-SOCIAL-001, AUTH-LEGACY-001, AUTH-DEVICE-001, AUTH-DESKTOP-001, AUTH-GATEWAY-001, AUTH-PRIVILEGED-001, AUTH-GRANTS-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-HOOKS-001, AUTH-REQUESTS-001, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-CHAT-001, AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-DEVELOPER-001, AUTH-ADMINAPI-001, AUTH-TERRAFORM-001, AUTH-MOBILE-001, AUTH-EVENTS-001, AUTH-FOLLOWUP-001, AUTH-FOLLOWUP-002, AUTH-FOLLOWUP-003, AUTH-FOLLOWUP-004, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-002, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002, AUTH-AGENT-001, AUTH-AGENT-002, AUTH-AGENT-003, AUTH-AGENT-004, AUTH-AGENT-007, AUTH-AGENT-005, AUTH-AGENT-006 | not run |
| BASE-INPUT-002 | HTML | none | not run |
| BASE-INPUT-003 | Uploads | AUTH-HRIS-002 | not run |
| BASE-SECRET-001 | No leakage | AUTH-TENANCY-001, AUTH-SWA-001, AUTH-OIDC-001, AUTH-MAPPING-001, AUTH-CATALOG-001, AUTH-LEGACY-001, AUTH-AUDIT-001, AUTH-MIGRATION-002, AUTH-ADMINAPI-001, AUTH-EVENTS-001, AUTH-OPS-001, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-AGENT-002 | not run |
| BASE-SECRET-002 | Startup | none | not run |
| BASE-DATA-001 | Export and import | AUTH-MOVEIN-001, AUTH-TRANSFER-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-PASSWORD-001, AUTH-SWA-001, AUTH-SAML-001, AUTH-TIMING-001, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-MIGRATION-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002 | not run |
| BASE-DATA-002 | Retention | AUTH-RETENTION-001, AUTH-RETENTION-002 | not run |
| BASE-DATA-003 | Erasure | AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-AUDIT-001, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002 | not run |
| BASE-DATA-004 | Outbound flows | none | not run |
| BASE-DATA-005 | Independence | none | not run |
| BASE-PUBLIC-001 | Privacy | none | not run |
| BASE-PUBLIC-002 | Origins | none | not run |
| BASE-PUBLIC-003 | Accessibility | none | not run |
| BASE-OPS-001 | Health | none | not run |
| BASE-OPS-002 | Migrations | none | not run |
| BASE-OPS-003 | Idempotency | none | not run |
| BASE-OPS-004 | Failure is visible | none | not run |
| BASE-OPS-005 | Audit | none | not run |
| BASE-ROLE-001 | Roles through every door | AUTH-IDENTITY-001, AUTH-MOVEIN-001, AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-ROLES-001, AUTH-PASSWORD-002, AUTH-ONBOARD-001, AUTH-ONBOARD-002, AUTH-TAP-001, AUTH-LAUNCHER-001, AUTH-MFA-001, AUTH-POLICY-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-SAML-001, AUTH-MAPPING-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-SCIM-001, AUTH-LIFECYCLE-001, AUTH-GRANTS-001, AUTH-HOOKS-001, AUTH-REQUESTS-001, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-CHAT-001, AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-001, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-ADMINAPI-001, AUTH-TERRAFORM-001, AUTH-FOLLOWUP-002, AUTH-RECOVERY-003, AUTH-AGENT-001, AUTH-AGENT-003, AUTH-AGENT-005 | not run |
| BASE-AUDIT-001 | Searchable, durable audit | AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-ROLES-001, AUTH-DOMAINS-001, AUTH-PASSWORD-001, AUTH-TAP-001, AUTH-SWA-001, AUTH-POLICY-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-MAPPING-001, AUTH-SCIM-002, AUTH-SCIM-003, AUTH-SCIM-004, AUTH-HRIS-001, AUTH-HRIS-002, AUTH-TIMING-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-DEVICE-001, AUTH-PRIVILEGED-001, AUTH-GRANTS-001, AUTH-HOOKS-001, AUTH-DECISIONS-001, AUTH-CHAT-001, AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-ADMINAPI-001, AUTH-TERRAFORM-001, AUTH-FOLLOWUP-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002, AUTH-AGENT-004, AUTH-AGENT-007 | not run |
| BASE-BACKUP-001 | Independent backup, restore and rollback | AUTH-RER-TRUST-001, AUTH-ADMIN-001, AUTH-TRANSFER-001, AUTH-ROLES-001, AUTH-MFA-001, AUTH-LIFECYCLE-001, AUTH-DESKTOP-001, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-003, AUTH-TRANSFER-002 | not run |
| BASE-DATA-006 | Erasure respects retention and legal hold | AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-RETENTION-001, AUTH-RETENTION-002 | not run |
| BASE-SIGNIN-001 | Standards-based SSO and lifecycle | none | not run |
| BASE-SIGNIN-002 | Native multi-factor authentication | AUTH-IDENTITY-001, AUTH-ENROLLMENT-001, AUTH-MFA-001, AUTH-RECOVERY-002, AUTH-RECOVERY-003 | not run |
| BASE-INSTALL-001 | Free self-host and removal | AUTH-PRIVACY-001, AUTH-RER-TRUST-001, CMD-001, AUTH-LINK-001, AUTH-TRANSFER-001, AUTH-TENANCY-001, AUTH-ROLES-001, AUTH-SWA-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-LEGACY-001, AUTH-AUDIT-001, AUTH-DEVELOPER-001, AUTH-TERRAFORM-001, AUTH-FOLLOWUP-002, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-002, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002 | not run |
| BASE-MAIL-001 | Truthful mail outcomes | AUTH-PRIVACY-001, AUTH-RER-TRUST-001, AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-BOUNDARY-001, AUTH-MOVEIN-001, AUTH-ADMIN-001, AUTH-TRANSFER-001, AUTH-DIRECTORY-001, AUTH-TENANCY-002, AUTH-PROFILE-001, AUTH-ENROLLMENT-001, AUTH-PASSWORD-001, AUTH-PASSWORD-002, AUTH-ONBOARD-001, AUTH-ONBOARD-002, AUTH-LOCALE-001, AUTH-MFA-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-SAML-001, AUTH-M365-001, AUTH-SCIM-001, AUTH-SCIM-002, AUTH-SCIM-003, AUTH-SCIM-004, AUTH-WORKFLOWS-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-SOCIAL-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-MOBILE-001, AUTH-FOLLOWUP-001, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-002, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-003, AUTH-AGENT-002, AUTH-AGENT-004, AUTH-AGENT-007 | not run |
| BASE-ACCESSIBILITY-001 | One accessibility bar | AUTH-EXPERIENCE-001, AUTH-LOCALE-001, AUTH-MOBILE-001 | not run |
| BASE-DOCS-001 | On-site docs from one contract | none | not run |
| BASE-AGENT-001 | One MCP door per seed | SURFACE-001 | not run |
| BASE-AGENT-002 | The seed's jobs are tools, through the UI's own actions | SURFACE-001 | not run |
| BASE-AGENT-003 | Records are resources | SURFACE-007 | not run |
| BASE-AGENT-004 | Business identity and short-lived, audience-bound tokens | AUTH-AGENT-006, SURFACE-008 | not run |
| BASE-AGENT-005 | An agent acts as a person in a role, never more | AUTH-ADMIN-001, AUTH-TENANCY-002, AUTH-PROFILE-001, AUTH-LOGOUT-002, AUTH-CATALOG-002, AUTH-PRIVILEGED-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-AUDIT-001, AUTH-MIGRATION-002, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-TRANSFER-002, AUTH-AGENT-001, AUTH-AGENT-002, AUTH-AGENT-003, AUTH-AGENT-004, AUTH-AGENT-007, AUTH-AGENT-005, AUTH-AGENT-006, SURFACE-007, SURFACE-008 | not run |
| BASE-AGENT-006 | Every action declares its risk class | SURFACE-001, SURFACE-002, SURFACE-003, SURFACE-004, SURFACE-005, SURFACE-006 | not run |
| BASE-AGENT-007 | The company's policy decides, at one chokepoint | SURFACE-008, SURFACE-013 | not run |
| BASE-AGENT-008 | Truthful attribution | SURFACE-008, SURFACE-009 | not run |
| BASE-AGENT-009 | Every agent action is audited with its class and decision | SURFACE-009, SURFACE-013 | not run |
| BASE-AGENT-010 | Agents can follow changes | SURFACE-010 | not run |
| BASE-AGENT-011 | Limits are policy, and Pause stops everything | SURFACE-011, SURFACE-013 | not run |
| BASE-AGENT-012 | Writes are idempotent and conflict-safe | SURFACE-011 | not run |
| BASE-AGENT-013 | Manifest, docs and the conformance journey | SURFACE-001, SURFACE-002, SURFACE-003, SURFACE-004, SURFACE-005, SURFACE-006, SURFACE-012, SURFACE-013 | not run |

## Published clauses

- `AUTH-HOST-001`: *Tier:* Core · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `AUTH-PRIVACY-001`: *Tier:* Core · *Cites:* BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2
- `AUTH-RER-TRUST-001`: *Tier:* Core · *Cites:* BASE-BACKUP-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2
- `AUTH-IDENTITY-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001, BASE-SIGNIN-002 · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `AUTH-PROTOCOL-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `AUTH-BOUNDARY-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `AUTH-MOVEIN-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `AUTH-ADMIN-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-BACKUP-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `CMD-001`: *Tier:* Core · *Cites:* BASE-INSTALL-001 · *Rules:* D-1 · *Register:* R-1, R-2
- `HTTP-001`: *Tier:* Core · *Cites:* BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2
- `AUTH-LINK-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-INSTALL-001 · *Rules:* D-1 · *Register:* R-1, R-2
- `AUTH-LOGOUT-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4
- `AUTH-TRANSFER-001`: *Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-BACKUP-001, BASE-DATA-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

### Retained identity and RER guarantees

#### AUTH-HOST-001 — Issuer host

**Requirement.** The host owns the issuer and passkeys. Choose it before linking apps. A host change is a provider move requiring the apps' owners to approve re-linking; it does not silently preserve an issuer or passkey origin. Fresh local setup selects localhost; explicit and saved hosts are preserved.

**Acceptance.**
1. Choose localhost on fresh setup; repeat with an explicit/saved issuer; enroll a passkey and link an app.
2. Attempt a host move and require a new app-owner approval rather than preserving issuer authority.

#### AUTH-PRIVACY-001 — Shared claims

**Requirement.** Auth shares each person's email and name with the apps they use. Under RER Managed, RER can sign link approvals for the account's Auth install; it receives people's data only as an ordinary linked app, for people who sign in to RER through it.

**Acceptance.**
1. Sign in to two linked apps with different granted identity scopes; inspect UserInfo and tokens for only the permitted claims.
2. Add a RER approval key and confirm it grants no user-data access without an ordinary app sign-in.

#### AUTH-RER-TRUST-001 — RER trust

**Requirement.** Auth accepts a RER link approval only when an active trusted key signed it (`typ: rer-link-approval+jwt`, `aud` this issuer, lifetime at most five minutes, unique `jti` consumed once), its origin and link key match the app document Auth pulls itself, and its `claim`, if any, names the Auth owner. Keys come from the `RER_LINK_APPROVAL_KEYS` setting of a RER-provisioned install, or from an owner or administrator on Sign-in methods with passkey and fresh local email proof. Withdrawal, by an administrator there or by RER with an assertion signed by that key when the account leaves Managed, ends the key for good. RER-made links are flagged and notified like token-made links. An install with no trusted key makes no request to RER.

**Acceptance.**
1. Link using a correctly signed RER approval, then refuse wrong issuer/origin/key/claim, stale assertion and jti replay.
2. Withdraw trust through both supported doors and prove the key cannot be restored or used again.

#### AUTH-IDENTITY-001 — Owner and sign-in proof

**Requirement.** Base bootstrap claims the owner but conveys no Auth privilege. Email-link proof completes once, only in the requesting browser. First passkey enrollment requires Auth email proof; administration and additional passkey enrollment require hardware passkey proof. Every enrollment, recovery approval or completion and administration write also requires this browser's Auth email confirmation within ten minutes, rechecked with the session's authority in the committing write; an enrollment challenge is valid only in the session that requested it. Recovery of anyone holding an administrator or other privileged role (AUTH-DECISIONS-001) requires another administrator's approval, a cancelable notified 72-hour delay, or the local emergency recovery token, and this rule is never relaxed for them. A non-privileged employee may also take the same-business-day help-desk path of AUTH-RECOVERY-003; the administrator recovery path retains these stronger gates.

**Acceptance.**
1. Through the real email, WebAuthn and administration routes, prove same-browser one-use confirmation, first/additional enrollment, fresh local email step-up rechecked at commit, wrong-session and revoked-session refusal, and approved/delayed/canceled/emergency recovery.

#### AUTH-PROTOCOL-001 — OpenID Connect profile

**Requirement.** Auth implements code/PKCE with state, nonce, RFC 9207 issuer, private_key_jwt clients, pairwise subjects and ID tokens accompanied by signed bearer access tokens. Access tokens are restricted to Auth UserInfo, bound to client, subject, session and granted scopes, and valid for at most five minutes or the remaining session lifetime. UserInfo supports GET and POST, returns only scoped identity claims and rechecks active session, account, client, grant, email proof and domain policy. ID tokens and other bearer credentials cannot authorize UserInfo. No refresh tokens or offline access are offered for the static code-flow profiles. Existing clients retain ES256; clients may select RS256. Both signing algorithms preserve Auth’s encrypted key custody, publish-before-use and outstanding-token retirement boundary. The supported profile makes no certification claim.

**Acceptance.**
1. A registered RER client completes code/PKCE/private_key_jwt, validates nonce/issuer/audience/pairwise subject, and calls scoped GET/POST UserInfo.
2. Refuse code/assertion replay and inactive client/person/session/grant/policy; test encrypted ES256/RS256 publish-before-use and retirement.

#### AUTH-BOUNDARY-001 — Private authorization

**Requirement.** The seed denies inherited Base operator, invitation, provider and domain management paths. Only bootstrap, Base session inspection and local Base sign-out remain exposed; gated dev entry exists exclusively in the development bundle. Removing the gate removes dev-session authority; production refuses dev proof.

**Acceptance.**
1. Request each private page/API signed out, as an email-only member, as a passkey administrator and with revoked authority; deny inherited Base management and production dev tokens.
2. Remove the local dev gate and confirm authority ends.

#### AUTH-MOVEIN-001 — Staged move-in

**Requirement.** Directory exports are staged apart from people: a staged row cannot sign in, receives no mail and appears only on the move-in review. Admission creates the same invited member as a People invitation, with no email proof, administrator right, password, factor, app role, group permission or session, and sends mail only when the owner chooses to send invitations. A matching email never rebinds an existing person, passkey or upstream link. Undo removes only people the batch admitted who have never signed in and hold no passkey, app grant or later activity, and records who it removed and kept. An Auth0 former subject is data for app owners: no protocol endpoint accepts it and it never replaces the pairwise subject. Staging, admission, invitation and undo are administration writes under AUTH-IDENTITY-001.

**Acceptance.**
1. Stage Google, Entra, Auth0, Okta and JumpCloud exports through Move-in, inspect collision/disabled rows, admit selected members without proof/roles/mail, explicitly invite, and undo only untouched admissions.
2. Refuse former Auth0 subjects as credentials and concurrent/stale administrative authority.

#### AUTH-ADMIN-001 — Agent preparation

**Requirement.** The company’s policy decides access and security calls. Agent administration carries access for people, invitations and app authority, security for provider rules and credentials, and external when it contacts a recipient. The company’s policy decides each call; the held policy below asks a person to approve the exact proposal. A preparer key, minted, renewed and revoked by an administrator under AUTH-IDENTITY-001, is shown once, stored as a digest, expires 30 days after minting or renewal, and is accepted only by the preparer API while unrevoked and while its accountable administrator remains the administrator who minted it: it ends for good when that person is demoted, suspended or removed, and promoting or restoring them again does not bring it back (a new key is minted). It reads an allow-listed inventory (no session, passkey, key or token material) and files proposals to suspend or restore a person, invite a person, remove an invitation, or add or remove a domain's required provider; filing stores the affected people and apps and a digest of the target's state, and changes nothing else. Under that held company policy, a proposal runs on one exact approval: an administrator's passkey signature over a challenge naming it, with that session's fresh local email proof, rechecked with the approver's authority, the unchanged target state and an unexpired, undecided proposal in the committing write. It runs once; it never suspends the owner or its own approver; its outcome is recorded in Activity with the key and the approver. A preparer key confers no session, page, approval, key management or protocol access and is not an access token.

**Acceptance.**
1. Under the held company policy, mint/renew/revoke a preparer key, inspect its allow-listed inventory, file each supported proposal and approve its exact state with a person’s passkey and fresh local email.
2. Under the held company policy for access and security, prove expiry, stale-state refusal, one winner under concurrent approvals and permanent loss of key authority after administrator removal.

#### CMD-001 — Commands

**Requirement.** Its edition-owned extensions are documented in AUTH-COMMANDS.md. Setup applies real D1 migrations and claims the first owner. Sign-in begins in the browser, never by presenting an unusable CLI-bound proof. Local recovery writes only a token digest to D1 and stores the raw token in a mode-0600 private file.

**Acceptance.**
1. Run real install/setup/dev, start browser sign-in, repeat setup without replacing owner/settings/data, stop the managed process, and generate/redeem local recovery with only a digest in D1 and a mode-0600 raw token file.

#### HTTP-001 — HTTP surfaces

**Requirement.** Hono serves health/API dispatch and Start serves remaining documents; Auth intercepts identity, protocol and private Auth pages before dispatch. Unknown routes return 404.

**Acceptance.**
1. Call health, Auth APIs and public/private documents through the emitted Worker; confirm identity interception, per-request authorization and an ordinary 404 for unknown routes.

#### AUTH-LINK-001 — App links

**Requirement.** Auth links apps through Base's pull protocol (LINKING.md). It reads only the app's own documents at its exact origin and binds the exact callback set. Codes are one-use, last 60 seconds and are redeemed atomically. It verifies the redeem assertion (audience, at most 60 seconds, unique `jti`). A client keeps its id and sector. A new key needs an administrator who saw the existing link, and a link replaces another app (its sector at another origin, or another sector at its origin) only on an approval that named it. Link tokens cover one origin and callback set, are single use and last at most an hour. Production installs refuse loopback and plain-http origins; dev installs serve only loopback apps. Token- and RER-made links are flagged and announced. Reported interface versions are kept, and a lower one, reported or re-linked, waits for the owner. Removing an app signs out everyone it signed in.

**Acceptance.**
1. Use the pull/link-token flow to link a real Base app Worker, sign in, re-link with continuity, and remove it.
2. Refuse mismatched callbacks/origins, replay/concurrent redemption, unauthorized key swap and unapproved downgrade; observe linked-app sessions end on removal.

#### AUTH-LOGOUT-001 — Sign-out reach

**Requirement.** Sign out everywhere, suspension (identity fence) and RP-initiated logout send signed `logout+jwt` tokens with a unique `jti` and no `nonce` to each linked app's registered logout path. Each is retried for up to 24 hours. Discovery advertises `end_session_endpoint` and back-channel logout with session support.

**Acceptance.**
1. Sign out everywhere, suspend a person and request RP logout through real Auth/app endpoints; the app rejects the old session and replayed logout tokens.
2. Exercise bounded retries and inspect the persisted delivery outcome; discovery advertises the supported endpoints.

#### AUTH-TRANSFER-001 — Export and import

**Requirement.** Export carries people, emails, passkey public keys, clients, grants, subjects, history and a signed grant map. It omits sessions, private keys, the pairwise key and the RER keys an owner trusted; withdrawn RER keys stay withdrawn. Import refuses app origins the destination cannot serve and active dev personas. A restore at the same host keeps every client, sector and pairwise subject. Reconnected notice sending follows AUTH-DELIVERY-001’s current-suppression reconciliation.

**Acceptance.**
1. Export a populated installation, import into an empty installation at the same host, and re-link the app with unchanged client/sector/pairwise subject.
2. Inspect retained records and absent authority; refuse incompatible origins and active dev personas.


## Target clauses

### The workforce directory and employee experience

#### AUTH-DIRECTORY-001 — One workforce directory

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers manage employees, contractors, service identities, managers, departments, locations, employment dates, immutable person/source identifiers, custom attributes and active/invited/suspended/terminated states. Search, filter, bulk preview and admin API edits (made through AUTH-ADMINAPI-001 credentials or an administrator's session) use the same validation and audit. Static and attribute-driven groups have explainable membership, group owners and mapped app roles; source precedence and manual overrides are visible. Rehires and email/name changes preserve reviewed identity continuity rather than merging by email.

**Acceptance.**
1. In People/API, onboard a W-2 employee and a contractor, rename and transfer one, preview a bulk edit, evaluate dynamic groups, suspend and rehire; verify stable identifiers, explicit source conflicts and resulting assignments without duplicate accounts.

#### AUTH-TENANCY-001 — Organizations and delegated administration

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-INSTALL-001, BASE-ROLE-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** An installation can serve multiple employer organizations, subsidiaries and partner workspaces. Installation authority and organization authority are separate: the installation owner and installation administrators run the installation, and each organization has its own owner. Each organization is either installation-operated, where installation roles also administer it, or isolated, where installation roles have no read, write or export authority over its directory, profiles, audit content, issuer secrets or connector credentials and the installation owner can only host it or erase or reset it as a whole under AUTH-ERASURE-004. People may hold distinct memberships and roles in more than one organization, with an explicit active organization. Owner, identity administrator, security/policy administrator, app administrator, group owner, manager, help desk, auditor and employee permissions are scoped and server-enforced, including exports and API credentials; each built-in role's permissions are listed, and employers compose further roles and scopes under AUTH-ROLES-001 (custom roles, resource sets of groups/apps/people, separate view and edit scope, rank fence on administration). Invitations expire, can be canceled, and never grant more than the inviter can delegate. Employers can delegate setup without exposing another employer's directory or issuer secrets. Isolation and installation-operated modes preserve independent issuer, factors and sessions. Archive and future-mode boundaries follow AUTH-TRANSFER-002 and AUTH-ROLES-001.

**Acceptance.**
1. Invite a contractor into two employers, switch organization, delegate one app to an app administrator and one recovery case to help desk; deny cross-organization reads/writes/exports and unauthorized role escalation, including direct API requests.
2. For an isolated employer, installation roles acquire no employer session, membership or directory authority merely by hosting it.
3. Installation archive export/import refuses an active isolated employer, including an active employer inside a source archive; anonymous evidence from an erased employer remains portable, with credentials and sealed pending remote work excluded.

#### AUTH-TENANCY-002 — No cross-organization linking or proof transfer

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** A person's memberships in different organizations are never linked, merged or matched automatically, whether by email, domain, upstream subject, device, imported metadata or an agent suggestion. Proof, factors, recovery state, sessions, consent, approvals and administrator authority completed in one organization never satisfy another; each organization's sign-in, enrollment and step-up stand alone. A person's own organization switcher requires their proof in each organization and gives no organization visibility of another's records. Records retained after an organization is erased or reset (AUTH-ERASURE-004 anonymous receipts and sealed remote work) are never attached to, shown in, matched against or retried from any other organization, including a new organization later created with the same name, domain or people. The only link between a person's identities is one they create under AUTH-ERASURE-002; it carries no proof, visibility or authority.

**Acceptance.**
1. Give one person memberships in two isolated organizations with the same email and upstream subject; confirm no automatic link or match, that a passkey sign-in, step-up, recovery or approval completed in one does not satisfy the other, and that an administrator of one cannot see or act on the other membership through UI, admin API or export.
2. Reset one organization, create a new organization with the same name, domain and people, and confirm none of the retained receipts or sealed work appears in, links to or can be retried from it.

#### AUTH-ROLES-001 — Custom administrator roles and resource sets

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-BACKUP-001, BASE-DATA-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers build custom administrator roles from a published permission list (for example: view people, edit profile fields, suspend/restore, reset factors, approve recovery, manage group membership, manage group rules, configure app, assign app, manage policy, manage identity providers, view audit, export audit, manage admin API credentials). A role is granted over a resource set: named groups, attribute-defined groups (such as "non-privileged users in the US group"), apps and individual people, with view scope and edit scope set separately. The built-in AUTH-TENANCY-001 roles are expressible in the same model. Server enforcement applies to UI, admin API and exports alike, in this order: organization boundary, published permission, view or edit resource set, then rank. Built-in administrator ranks are immutable: installation owner and organization owner 100 (each in its own scope), installation administrator 90, identity administrator and security/policy administrator 80, app administrator 50, help desk 20, auditor 10. Group owner, manager, app owner and employee carry administrator rank 0; their decisions follow AUTH-DECISIONS-001. A custom role's rank (1–89) is chosen by the installation owner, an installation administrator for an installation-operated organization, or that organization's owner, always strictly below the chooser's rank. Rank grants nothing by itself. No role can administer (profile, status, factors, recovery approval, roles, sessions or that person's data export) a person whose administrator rank in that scope is equal to or higher than its own, nor anyone outside its edit scope. Viewing follows view scope, not rank. A role holder can never grant a role, rank, resource set or admin API credential wider than their own current authority. Admin API credential custody is the published "manage admin API credentials" permission; until custom roles ship it is held by installation owner and installation administrator. Role and resource-set changes are administrator writes under AUTH-IDENTITY-001, previewed with who gains and loses which actions, and audited. Future machine administration doors inherit AUTH-ADMINAPI-001 credential, scope/resource, excluded-action, live-authority, audit and concurrency checks before shipping.

**Acceptance.**
1. Create a help-desk role with "reset factors" over group A and view-only over group B.
2. As its holder, reset a factor for a person in A; be refused editing in B (view succeeds), refused on an administrator in A, and refused via direct API and export.
3. Attempt to grant the role over a wider set and be refused; change group A's membership and observe the next decision follow it.

#### AUTH-DOMAINS-001 — Verified employer domains

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Administrators prove control of a corporate domain through expiring DNS or equivalent ownership challenges before domain-based enrollment, discovery or federation routing is activated. A domain cannot be silently claimed by another employer. Preview shows who a rule affects, aliases are explicit, and removal/reverification cannot strand emergency owners. Verified domain control never by itself proves an individual’s identity or licenses account linking.

**Acceptance.**
1. Claim a domain through the admin setup door, fail an incorrect or expired challenge and competing claim, then enroll and route an eligible worker.
2. Revoke domain ownership and confirm policy reevaluation and audited recovery access.

#### AUTH-PROFILE-001 — Profiles and safe identity linking

*Tier:* Core · *Cites:* BASE-AGENT-005, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Employees can read and edit permitted profile fields through account UI/API; administrators manage typed custom metadata with field-level visibility and source ownership. Linking or unlinking Google, Microsoft, Okta, GitHub, Apple or generic upstream identities requires proof of the existing account and the new identity, explicit confirmation and a surviving sign-in/recovery path. An issuer/subject pair has one binding; matching email, imported metadata or an agent suggestion alone cannot take over an account.

**Acceptance.**
1. Edit an employee profile and protected HR field, connect a second proven upstream and then unlink it; refuse an email collision, foreign subject, concurrent binding and last usable sign-in removal.
2. Inspect app claims for only consented fields.

#### AUTH-ENROLLMENT-001 — Managed enrollment and password compatibility

*Tier:* Core · *Cites:* BASE-ACCESS-001, BASE-INPUT-001, BASE-MAIL-001, BASE-SIGNIN-002 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Supersedes `BASE-ACCESS-001` for employer-enabled workforce password compatibility under RL-9. Invitation, approved-domain self-registration and HR-driven prehire flows share verification, duplicate resolution, terms/consent and recovery controls. Passkeys are the default. HR-sourced future hires activate before their start date through AUTH-ONBOARD-001, and anyone without a usable factor gets a first credential through a temporary access pass (AUTH-TAP-001). Employers migrating password-dependent workforces can explicitly enable hashed password sign-in, governed by AUTH-PASSWORD-001's per-group policy and reset or unlocked under AUTH-PASSWORD-002, and email or SMS one-time verification; these methods cannot confer hardware administration proof or bypass conditional access. Public registration stays closed unless employer policy opens it, and a pending invitation or import is never authenticated authority.

**Acceptance.**
1. Enroll an invited employee and an approved-domain self-registrant, reject an outside address, complete a password reset under AUTH-PASSWORD-002 and a one-use SMS/email challenge, and prove weaker methods cannot administer or bypass required MFA.
2. Cancel enrollment and verify its outstanding links stop.

#### AUTH-PASSWORD-001 — Password policy per group

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Wherever an employer enables password compatibility (AUTH-ENROLLMENT-001), the Auth password is load-bearing: it carries RADIUS/VPN and Wi-Fi EAP-TTLS (AUTH-LEGACY-001), LDAPS binds, Mac password sync (AUTH-DESKTOP-001), the WS-Trust endpoint (AUTH-M365-001) and AD write-back. It is therefore governed by versioned password policies assigned to groups in an explicit priority order, with a fallback password policy for everyone else; each person's effective policy and why it applies are shown. Each policy sets: minimum length (8–64, default 12) with at least 64 characters always accepted; required character classes (lower case, upper case, digit, symbol, each optional); refusal of any part of the person's username, email local part, first or last name; refusal of Auth's list of at least 100,000 common and dictionary passwords plus employer-added words; breached-password screening by a k-anonymity range query (Have I Been Pwned Pwned Passwords) when a password is set and, by policy, at sign-in; history of the last 0–30 passwords (default 24); minimum age of 0 to 7 days (default 1 hour); maximum age of never or 1–999 days, with an expiry warning a set number of days before (default 14) shown at web sign-in, in the launcher, at the desktop login window and by email, and a forced change at the next sign-in once expired; and lockout after 1–100 consecutive failed attempts (default 10), with automatic unlock after a set period or never, self-service unlock under AUTH-PASSWORD-002 and an optional lockout notice (AUTH-NOTIFY-001). Failed attempts count across every door that accepts the password (web, RADIUS, LDAPS, WS-Trust, desktop). Lockout blocks only the password: passkey sign-in, push, help-desk recovery (AUTH-RECOVERY-003) and a temporary access pass (AUTH-TAP-001) still work, so a remote attacker cannot lock a person out of their account. Policies preview who they affect before publishing, follow group membership on the person's next password set or sign-in, and are administrator writes under AUTH-IDENTITY-001; every policy version is audited and included in the AUTH-REVIEWS-001 evidence export.

**Acceptance.**
1. Assign a policy of length 12, history 24, minimum age 1 hour and lockout at 10 attempts to group A, and a policy of length 16 with symbols required and a 90-day maximum age with a 14-day warning to group B; preview the affected people.
2. Through the web change door and a RADIUS sign-in, refuse for a person in A each of: 11 characters, a password from their history, a second change within the hour, a password containing their last name, a block-list word and a breached password; refuse a password without a symbol for B.
3. Fail 10 attempts for A's person across web and RADIUS and see the password locked while passkey sign-in still succeeds; self-unlock under AUTH-PASSWORD-002.
4. Age B's person's password into the warning window and past expiry, and see the warning at each surface and the forced change.
5. Move the person from A to B and see B's rules at their next change.

#### AUTH-PASSWORD-002 — Self-service password reset, unlock and propagation

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employees reset a forgotten password and unlock a locked password themselves at the hosted sign-in, in the launcher, in the Auth mobile app and at the macOS and Windows login window (AUTH-DESKTOP-001). Policy sets, per group, which factors reset and unlock require: by default one strong factor (passkey, Auth push or Auth TOTP), and, only for a person with no strong factor enrolled, email or SMS plus a second check (an SMS code together with an email link); security questions are never offered. Email or SMS alone is never accepted for anyone who has a stronger factor enrolled, nor for an administrator or privileged role (AUTH-DECISIONS-001), who reset only through a strong factor or AUTH-IDENTITY-001's recovery. Reset and unlock responses do not reveal whether an account exists and are throttled under AUTH-ABUSE-001. A reset or change is checked against the person's AUTH-PASSWORD-001 policy, ends their other password-based sessions as policy sets, sends the AUTH-NOTIFY-001 password-changed notice and propagates to every place the password is used: Auth verifies RADIUS, LDAPS binds and WS-Trust itself, so those take the new password at once; the AD connector writes it back to Active Directory (AUTH-LEGACY-001); and the Mac Platform SSO password-sync account takes it at the next online login or unlock. All of this happens within AUTH-TIMING-001's 60-second local bound, after which the old password is refused at every door Auth controls. A target that cannot yet confirm (connector offline, Mac not yet online) is shown per target as pending, never as done, and stays an AUTH-FOLLOWUP-001 obligation. Help desk can force a reset under AUTH-RECOVERY-003 with a temporary password that must be changed at first use.

**Acceptance.**
1. For a person in group A with Auth push enrolled, reset a forgotten password through self-service with push, and be refused when offering email alone; unlock a locked password the same way.
2. Within 60 seconds see the new password accepted and the old one refused at GlobalProtect RADIUS, an LDAPS bind, the WS-Trust endpoint and the Mac login in password-sync mode, and read the written-back password's change time from AD.
3. Take the AD connector offline during a reset and see AD pending until it returns.
4. Request a reset for an unknown address and receive the same response as for a known one; refuse a self-service reset by email alone for an administrator.

#### AUTH-ONBOARD-001 — New-hire activation before the start date

*Tier:* Core · *From:* AUTH-ONBOARD-001 · *Cites:* BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1, D-3 · *Register:* R-1, R-2, R-4

**Requirement.** For a future hire from an HR source (AUTH-HRIS-001, AUTH-HRIS-002) or created by an administrator, Auth sends an activation invitation to the personal email address on the HR record (or one an administrator enters, marked as an unverified personal contact) at an employer-set lead time before the start date (default 7 days, 0 to 30), with reminders through AUTH-FOLLOWUP-001 and a notice to the hiring manager if it is still unused 2 days before start. The activation link is single use, bound to the person and expires after a set period (default 7 days); reissuing it voids the old one. Opening it proves the personal address; employer policy may add a second check (an SMS code to the HR-recorded mobile number, or an ID-document and selfie check through Persona or CLEAR, whose result and not the document is stored). The hire then enrolls a passkey and the Auth authenticator (AUTH-AUTHENTICATOR-001), and a password where AUTH-ENROLLMENT-001 enables it. Enrollment grants nothing before the authorized start (AUTH-TIMING-001): launcher tiles read "available from" the start time, and every launch, token, SAML, RADIUS and desktop sign-in is refused until then. A hire who has not enrolled by the start uses a temporary access pass (AUTH-TAP-001). An HR start-date change moves the gate; a rescinded offer revokes the enrollment and its factors. The personal address is used only for activation and for recovery notices the employer enables, never as a work sign-in identifier. Dispatch custody follows AUTH-ONBOARD-002. Related outcomes: AUTH-ONBOARD-002.

**Acceptance.**
1. From an HR test source, add a hire starting in 10 days with a 7-day lead time; see no invitation until 7 days before start, then the invitation at the HR personal address.
2. Enroll a passkey and push before start; be refused app launch and token issuance until the start time, then launch.
3. Let a second hire's link expire, reissue it and refuse the old link.
4. Move a start date earlier and later and see the gate follow; rescind an offer and see the enrollment revoked.
5. Confirm no message reaches the personal address after start except enabled recovery notices.

#### AUTH-ONBOARD-002 — Personal-contact dispatch custody

*Tier:* Core · *From:* AUTH-ONBOARD-001 · *Cites:* BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1, D-3 · *Register:* R-1, R-2, R-4

**Requirement.** Pre-start dispatch and day-one fallback follow RL-1. Record employer contact authority and notice/consent responsibility. Initial sends, reissues, retries and reminders recheck the live authorized start, rescission and sender authority; zero-day lead permits no personal-contact activation. At or after start, only enabled recovery notices use that address. Personal contact never becomes work sign-in or administrator proof; manager-requested, group-scoped temporary-pass enrollment preserves day-one onboarding.

**Acceptance.**
1. Assert one initial activation dispatch within a permitted pre-start lead window.
2. For initial activation, explicit reissue, queued retry and reminder, assert zero activation dispatches exactly at start and after start.
3. With lead time zero, assert zero personal activation dispatches and expose the unenrolled hire’s required temporary-pass next step. Move start earlier and later immediately before dispatch and assert the current schedule governs; rescind the offer and assert no dispatch. Refuse personal-contact dispatch without recorded employer authority. Exercise the permitted recovery-notice case separately. Complete the manager-request and scoped-help-desk temporary-pass journey, including refusal outside scope.

#### AUTH-TAP-001 — Temporary access pass

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Help desk, within its AUTH-ROLES-001 scope, or an administrator issues a temporary access pass after a recorded verification using AUTH-RECOVERY-003's methods (manager attestation, a remaining factor, or a Persona or CLEAR check); a manager can request one for a direct report. Auth generates the pass (at least 12 random characters), shows it once to the issuer for delivery in person, by phone or through the manager, and stores only its digest. Policy per group sets its lifetime (default 1 hour, minimum 10 minutes, maximum 8 hours, optionally starting at a joiner's start time) and whether it is single use (the default) or reusable within its lifetime for a first day with several devices. The pass is accepted at the hosted web sign-in and at the AUTH-DESKTOP-001 Mac and Windows login windows, including the first login on a zero-touch Mac or PC, where it creates or binds the local account. It authorizes only enrolling a durable factor (passkey, Auth authenticator, or password where enabled): it never satisfies app MFA or step-up, never launches an app, is never accepted by RADIUS, LDAPS, WS-Trust or a token endpoint, and the session it opens ends when enrollment completes. Issuing a pass for an administrator or privileged role is refused; they follow AUTH-IDENTITY-001. Issue, use, expiry and revocation are audited, and the person and their manager are notified (AUTH-NOTIFY-001).

**Acceptance.**
1. As help desk scoped to a new hire's group, record manager attestation and issue a pass.
2. At a fresh Mac's login window (Platform SSO) and at a fresh Windows PC, sign in with it, create the local account and enroll a passkey.
3. Refuse the pass on reuse, after expiry, at an app launch, at app MFA step-up and at GlobalProtect RADIUS.
4. Refuse issuance without a recorded verification, outside the issuer's scope and for an administrator.
5. Inspect the audit trail and the notices.

#### AUTH-EXPERIENCE-001 — Hosted and embedded identity journeys

*Tier:* Core · *Cites:* BASE-ACCESSIBILITY-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers configure an accessible branded sign-in, enrollment, account and recovery experience on their chosen verified host. React/Next.js components embed the same server-enforced user, membership and organization controls; a versioned journey editor composes approved verification and step-up steps without arbitrary client-side authorization. Preview, test and rollback preserve anti-enumeration, trusted redirects, emergency access and the strict RER profile.

**Acceptance.**
1. Configure branding and an employee journey, use both hosted and embedded account/membership screens, preview a changed MFA step and roll it back.
2. At 1440 and 390, in light/dark with keyboard and assistive technology, complete sign-in/recovery and expose durable errors without leaking hidden fields.

#### AUTH-LOCALE-001 — End-user display languages

*Tier:* Core · *Cites:* BASE-ACCESSIBILITY-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Every employee-facing surface is available in at least 30 display languages: the hosted sign-in, activation, enrollment, recovery, account and launcher pages, the browser extension (AUTH-SWA-001), the macOS and Windows login extensions (AUTH-DESKTOP-001), the iOS and Android app including push and number-matching text (AUTH-AUTHENTICATOR-001, AUTH-MOBILE-001), and every notification email and SMS (AUTH-NOTIFY-001, AUTH-ONBOARD-001). The set includes English, Spanish (United States and Latin America), Simplified and Traditional Chinese, Vietnamese, Tagalog, Korean, Arabic, Russian, Haitian Creole, French, Portuguese (Brazil), German, Japanese, Hindi, Polish and Italian, with right-to-left layout for Arabic. A person's language is, in order: their own choice in My account; else the preferred language from their HR source (AUTH-HRIS-001); else the employer's default for their organization or group; else the browser or device language. Anyone can switch language on the sign-in page before signing in. Dates, times and numbers follow the language and the person's own time zone. Employer-customized text (branding copy, journey messages, notification templates, bookmark tile names) is entered per language with the employer default as fallback, and preview flags each untranslated string. Security text (number matching, push context, recovery and lockout warnings) is never shown untranslated in a supported language. The administrator console ships in English and Spanish.

**Acceptance.**
1. Set a person's language to Spanish and complete activation, sign-in, push approval with number matching, password reset, the launcher, an extension fill and the Mac login window entirely in Spanish; receive the new-device and password-changed notices in Spanish.
2. On the sign-in page switch to Arabic and complete sign-in at 390 in right-to-left layout.
3. Leave an employer notification template in English only and see the English fallback used and flagged in preview.
4. A build check fails when any end-user string key is missing from a supported language.

#### AUTH-LAUNCHER-001 — Employee app launcher

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Every employee gets a searchable dashboard of assigned SaaS, legacy and RER apps—SAML, OIDC, and password-based apps signed in through the Auth browser extension (AUTH-SWA-001)—with favorites, recently used apps and clear access-request actions. Each tile opens the correct employer/role and explains an unprovisioned, denied, expired or connector-blocked assignment. Administrators also add bookmark tiles, a named link with an icon assigned by group, for intranet pages and apps with no SSO; a bookmark carries no credential or assertion. Unassigned apps do not yield working launch assertions or filled credentials; app owners can publish instructions for apps requiring a separate client or VPN.

**Acceptance.**
1. As an employee with Google Workspace, Slack, AWS, a password-only app and a RER app assigned, launch each into its proper account.
2. Request an unassigned app, remove an assignment and expire a temporary grant; the dashboard, the extension and direct launch all enforce the changed access.
3. Assign a bookmark tile to a group and see it only for members.

#### AUTH-SWA-001 — Password-based app sign-in

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-3, R-4

**Requirement.** Apps whose plan has no SAML or OIDC are first-class launcher apps. An Auth browser extension for Chrome, Edge, Firefox and Safari (macOS and iOS) recognizes the app's sign-in page from its recipe, fills and submits the credential only on the recipe's exact origins, and offers the same on direct visits. Employers can force-install and preconfigure the extension (Auth tenant URL, sign-in required) through Jamf Pro, Kandji, Microsoft Intune and Google Chrome Enterprise policy, so employees cannot remove it on managed devices. App administrators choose per app between admin-set shared credentials (employees never see the password) and user-set individual credentials, and may let Auth generate strong passwords to a recipe's length/character rules and rotate them. Credentials are encrypted per person under keys Auth never sends to model context, logs or exports; shared credentials are released only to currently assigned people, and reveal, copy and change are policy-controlled and audited. Unassigning or offboarding a person removes their access in the extension immediately, and the leaver plan (AUTH-LIFECYCLE-001) rotates every shared credential they could use and records each password-only app as an access obligation until rotated or confirmed removed. AUTH-MIGRATION-001 imports Okta SWA app definitions (URL, field selectors, credential scheme) and leaves credentials to re-entry or a guided admin import. This is app sign-in, not a general personal password manager.

**Acceptance.**
1. Install the extension in each of the four browsers, and force-install it preconfigured through Intune on Windows and Jamf Pro on macOS, assign a shared-credential and an individual-credential app, sign in from the launcher and by direct visit, generate a password and refuse fill on a lookalike origin.
2. Unassign one employee and offboard another; their next fill is refused within 60 seconds, the shared password is rotated, and the audit shows every reveal, fill and rotation without the secret.
3. Import an Okta SWA app definition and launch it.

### Authentication, SSO and policy

#### AUTH-MFA-001 — Passkey-first multifactor policy

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-BACKUP-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001, BASE-SIGNIN-002 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers require phishing-resistant platform/synced passkeys or hardware security keys, offer TOTP and single-use recovery codes under explicit assurance rules, and control enrollment, replacement and factor loss. SMS/email are policy-limited bootstrap/recovery alternatives with lower assurance, never equivalent to a security key. The Auth mobile authenticator (AUTH-AUTHENTICATOR-001) adds push with number matching and its own TOTP; each factor's assurance (phishing-resistant, push, TOTP, SMS/email) is published and policy chooses which satisfy which app, RADIUS flow (AUTH-LEGACY-001) and OS login (AUTH-DESKTOP-001). Factor inventory, lost-factor revocation, step-up and the named employee security notifications of AUTH-NOTIFY-001 cover web, desktop and native mobile; a lost factor without a recovery code is restored the same business day under AUTH-RECOVERY-003. Existing hardware-passkey and fresh local email gates for interactive Auth administration by the roles AUTH-DECISIONS-001 lists remain mandatory.

**Acceptance.**
1. Enroll a platform passkey, hardware key, Auth push and TOTP, require step-up for a sensitive app, revoke a lost factor and consume a recovery code once.
2. Deny downgraded admin access and prove factor removal/rotation reaches current sessions according to policy.

#### AUTH-AUTHENTICATOR-001 — Push authenticator in the Auth mobile app

*Tier:* Core · *Cites:* BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-3, R-4

**Requirement.** The iOS and Android Auth app (AUTH-MOBILE-001) enrolls as an authenticator bound to a device key held in the Secure Enclave/StrongBox and protected by biometrics or device PIN. It delivers push approvals showing the requesting app, employee, approximate location, IP, device and time, with number matching (the employee types the number shown on the sign-in screen) wherever the requesting flow can display one; it also generates TOTP offline. Push carries no approval in the notification payload itself: approval is a signed response from the enrolled device key, single use and bound to the transaction, expiring after 120 seconds. Denying a push refuses the sign-in and optionally reports it as suspicious, which notifies the security owner and can suspend further pushes to that person (push-fatigue control: rate limit and automatic number matching after repeated denials). Phishing-resistant passkeys remain the default for browser sign-in; push and TOTP are the stated factors for RADIUS/VPN, Wi-Fi and other flows where a passkey cannot cross the protocol, and policy can require a passkey instead wherever one can. Lost-device removal invalidates the device key at once.

**Acceptance.**
1. On real iOS and Android builds, enroll the authenticator, approve a web sign-in with number matching, deny another and see it refused and reported, and complete a sign-in with the app's offline TOTP.
2. Replay an approval, answer after expiry and answer from a second unenrolled device; each is refused.
3. Send repeated pushes and observe the fatigue control; remove the device and prove its next approval is refused.

#### AUTH-POLICY-001 — Conditional access and session policy

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Versioned policies combine employee/group/app/role, authentication assurance, managed-device posture, IP/network/location, the named behavior signals of AUTH-RISK-001 (new device, new country/state/city, geo-location radius, velocity, IP reputation) and session age; no condition is an unexplained score. Administrators simulate impact before publishing; an explainable decision records the matched rule, each signal's value and evidence freshness. Deny or require step-up when posture is missing/stale, enforce idle/absolute session lifetime and fresh authentication on critical actions, and reevaluate when membership, location, device or policy changes. Emergency accounts are explicitly bounded, monitored and drilled rather than a blanket bypass. Future machine administration doors inherit AUTH-ADMINAPI-001 credential, scope/resource, excluded-action, live-authority, audit and concurrency checks before shipping. Privilege classification, role-order caps and everyday proof follow AUTH-DECISIONS-001.

**Acceptance.**
1. Preview and publish a payroll-app rule requiring a managed US device and fresh passkey; attempt allowed, foreign-network, stale-posture and expired-session launches through app and direct protocol routes.
2. Add an AUTH-RISK-001 "step up on new country" condition and see a new-country sign-in stepped up with the signal named in the decision.
3. Change group/policy during sign-in and verify the current decision at token issuance.

#### AUTH-ABUSE-001 — Automated attack protection

*Tier:* Core · *Cites:* BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Configurable bot challenges, suspicious-IP/device throttling, credential-stuffing and brute-force detection, breached-password screening, lockout and user/security-team notification protect every enrollment, sign-in, reset and token endpoint. Decisions are tenant-scoped and observable, avoid account enumeration and do not let a remote attacker permanently lock out emergency recovery. Risk-driven step-up uses AUTH-RISK-001's named signals, lockout and self-service unlock follow AUTH-PASSWORD-001 and AUTH-PASSWORD-002, and the user notification is AUTH-NOTIFY-001's; all retain the same account proof and administrator controls.

**Acceptance.**
1. Attack real authentication/reset/token HTTP doors with bot traffic, password spraying, a breached password and distributed source attempts; observe rate limits/lockouts, protected notifications and legitimate recovery.
2. Sign in through a Tor exit and from a location implying impossible travel, and verify step-up or denial with the AUTH-RISK-001 signal named in an explainable log.

#### AUTH-RISK-001 — Named sign-in behavior signals

*Tier:* Core · *Cites:* BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** AUTH-POLICY-001 rules use named, tunable behavior signals, each computed from the person's own sign-in history: new device (a browser or device not seen within the person's last N successful sign-ins, by device cookie or bound device key; N defaults to 20); new country; new US state; new city; new geo-location beyond a set radius (default 20 km) from all of the last N locations; velocity (implied travel speed from the previous successful sign-in above a set threshold, default 805 km/h, about 500 mph); new IP address and new network (ASN); and IP reputation: anonymizing proxy or VPN service, hosting provider and Tor exit node from a named, dated IP-intelligence feed (MaxMind GeoIP2 with Anonymous IP by default), an employer block list and employer-trusted corporate networks. Recent failed attempts and denied pushes are also signals. Each signal is a boolean or a number in the rule language, so "step up on new country, allow new city, deny Tor" is a rule an employer writes directly. Data that is unavailable (for example a failed location lookup) has its own named value, and the rule states what it does then. Signals are evaluated at every sign-in and token issuance through every door: web, OIDC, SAML, WS-Federation, desktop, and RADIUS where the connector reports the client IP. A summary risk level may be displayed, but it is always broken down into the signals that produced it; no rule can depend on an opaque score. Each decision records the signal values and the feed versions it used, and AUTH-POLICY-001 simulation replays the last 30 days of sign-ins against a draft rule.

**Acceptance.**
1. Publish "step up on new country, allow new city, deny Tor" for a group.
2. Sign in from a known location and pass; from a new US city and pass with "new city" logged; from a new country and be stepped up; from a location implying 900 km/h travel since the previous sign-in and be stepped up with velocity logged; through a Tor exit and be denied.
3. Change the radius and look-back and see the next decision follow them.
4. Each decision log names the signal, its value and the feed version.
5. Simulate the draft rule over 30 days of history and see per-signal counts.

#### AUTH-NOTIFY-001 — Employee security notifications and suspicious-activity reports

*Tier:* Core · *From:* AUTH-NOTIFY-001 · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Auth sends each employee named security notifications by email to the work address, and as a push in the Auth app where enrolled, for: sign-in from a new device or browser (AUTH-RISK-001's new-device signal), with app, time, approximate location, IP and device; factor enrolled; factor reset or removed, by them or by help desk; password changed or reset; password locked; recovery started (with its cancel action); temporary access pass issued; and an administrator role granted. Employers can turn off individual types except recovery started, factor reset or removed, and administrator role granted, which always send. Every notification carries a one-click "Report suspicious activity" action that works from the email without signing in (a signed, single-use link valid for 7 days) and from the Auth app. A report records a suspicious-activity event linked to the triggering event, alerts the security owner through AUTH-FOLLOWUP-001 (email, Slack or Teams, and Oncall per policy), and by policy ends all the person's sessions and refresh grants with back-channel logout and in connected SaaS apps (AUTH-LOGOUT-002), requires a password reset and factor review at next sign-in, or suspends the person pending help desk. Reports and their outcomes are audited, appear in AUTH-AUDIT-001 investigations and stream to the configured SIEM. A notification never contains a sign-in link or code that could itself confer authority. Verified notification channels and recipients require explicit authorization. Slack disclosure and destructive report responses have separate audited authorization. Once the configured channel is usable, recovery, factor reset or removal and administrator-grant notices cannot be disabled. Before setup, each required notice remains an actionable undeliverable obligation; existing recovery notices continue. A report link permits only its bound report, with no sign-in, arbitrary suspension or implicit cross-SaaS authority. Delivery diagnostics follow AUTH-DELIVERY-001; actual connected revocation follows AUTH-LOGOUT-002. (RL-104). Related outcomes: AUTH-NOTIFY-002.

**Acceptance.**
1. Sign in from a new browser and receive the new-device email with its stated context.
2. Enroll a factor, have help desk reset a factor and change a password, and receive each notification.
3. From the new-device email, while signed out, click "Report suspicious activity": see the security owner's escalation in Slack and, under the end-sessions policy, the person's sessions ended and a linked app's back-channel logout delivered.
4. Refuse the report link's reuse and use after expiry.
5. Turn off new-device notices and receive none; try to turn off recovery notices and be refused.
6. Verified notification channels and recipients require explicit authorization.
7. Slack disclosure and destructive report responses have separate audited authorization.
8. Once the configured channel is usable, recovery, factor reset or removal and administrator-grant notices cannot be disabled.

#### AUTH-NOTIFY-002 — Mandatory channels and report authority

*Tier:* Core · *From:* AUTH-NOTIFY-001 · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Mandatory notices, channel setup and report-response authority follow AUTH-NOTIFY-001’s RL-104 outcome; this part exercises their custody at the notification door. Delivery diagnostics follow AUTH-DELIVERY-001; actual connected revocation follows AUTH-LOGOUT-002.

**Acceptance.**
1. Before setup, each required notice remains an actionable undeliverable obligation; existing recovery notices continue.
2. A report link permits only its bound report, with no sign-in, arbitrary suspension or implicit cross-SaaS authority.

#### AUTH-LOGOUT-002 — Universal logout from connected SaaS for a compromised account

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** When an account is suspected compromised but the person is not leaving, Auth ends their sessions inside connected SaaS apps as well as in Auth, without deprovisioning them. Triggers are: an administrator's or help desk's "End all sessions" action on a person within their AUTH-ROLES-001 scope; an AUTH-NOTIFY-001 suspicious-activity report under the end-sessions policy; an AUTH-POLICY-001 rule on AUTH-RISK-001 signals (for example a Tor-exit or impossible-travel sign-in after a successful one); and an AUTH-AGENT-002 or AUTH-AGENT-005 action decided by the company’s policy for its access and security classes. Auth ends every Auth session and refresh grant, sends back-channel logout to linked apps (AUTH-LOGOUT-001), and calls each connected app's session-revocation API: Google Workspace sessions and OAuth tokens, Microsoft 365 sessions, Slack Enterprise Grid sessions, Zoom SSO tokens, Salesforce OAuth tokens and sessions, and GitHub Enterprise SAML SSO credential authorizations. Exact provider operations are in docs/contract-mechanism.md. Every AUTH-CATALOG-002 recipe states whether it supports session revocation, token revocation or neither. The person stays active; by policy their next sign-in requires a passkey or factor review and a password reset under AUTH-PASSWORD-002. For each app Auth records dispatch, vendor acknowledgment and, where the vendor allows, verification by read-back or a denied-access probe, within AUTH-TIMING-001's downstream bounds (dispatch within 60 seconds, verification within 5 minutes), shown per app as locally denied, acknowledged, verified, unsupported or failed. An unsupported or failed app stays an AUTH-FOLLOWUP-001 obligation showing its residual risk and manual step. The action is audited with its trigger and per-app outcome, and the person is notified (AUTH-NOTIFY-001). This is the job Okta's Universal Logout in Identity Threat Protection does.

**Acceptance.**
1. In authorized Google Workspace, Microsoft 365, Slack Enterprise Grid, Zoom and Salesforce test tenants, sign a person in to each through Auth on the web and in each vendor's desktop or mobile client.
2. From a new-device notice, report suspicious activity under the end-sessions policy: within 60 seconds the person's Auth sessions and a linked app's session end; within 5 minutes each vendor's API shows the sessions or tokens revoked, and each web and client session is refused at its next request, while the person stays active and signs in again with a passkey.
3. Repeat from help desk's End all sessions action and be refused outside the holder's scope.
4. An app with no revocation API is shown as unsupported with its manual step, and a vendor failure stays an open obligation.

#### AUTH-SAML-001 — SAML 2.0 workforce identity provider

*Tier:* Core · *Cites:* BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Auth supplies SP-initiated and explicitly permitted IdP-initiated SAML SSO for company apps, with per-app metadata import/export, entity IDs, exact ACS allow-lists, NameID/attribute/group/role mappings (AUTH-MAPPING-001) and certificate rollover with overlapping publication. Every release supports at minimum: HTTP-POST and HTTP-Redirect bindings for AuthnRequest and Response; RSA-SHA256 and RSA-SHA512 signatures, chosen per app, on the response, the assertion or both; optional assertion encryption with AES-256-GCM or AES-128-CBC content encryption and RSA-OAEP key transport; SP-initiated and IdP-initiated Single Logout over HTTP-Redirect and HTTP-POST; and the `persistent`, `emailAddress`, `unspecified` and `transient` NameID formats. RSA-SHA1 is accepted only as a named per-app compatibility exception. Auth validates request signatures where configured, destination, audience, request correlation, time windows (at most 5 minutes' clock skew) and replay; setup exposes incompatible profiles rather than claiming universal SAML compatibility.

**Acceptance.**
1. Configure a generic SAML SP through the admin door, launch as an assigned employee over each binding, validate mapped role/NameID in each of the four formats, sign the response, the assertion and both with SHA-256 and SHA-512, decrypt an encrypted assertion with each named algorithm at the SP, and roll certificates with overlap.
2. Complete SP- and IdP-initiated logout over both bindings.
3. Refuse a forged request, altered ACS, wrong audience, SHA-1 without an exception, stale/replayed assertion and unassigned user.

#### AUTH-OIDC-001 — General SaaS OIDC and OAuth profiles

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Alongside the unchanged AUTH-PROTOCOL-001 RER profile, app administrators register ordinary SaaS/web/native OIDC clients with discovery, exact redirects, the authorization code flow, scopes, claim mappings (AUTH-MAPPING-001) and per-app public or pairwise subjects. Supported client authentication methods are listed in discovery and chosen per client: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, and `none` for public clients, which must use PKCE (S256); confidential clients may also be required to use PKCE. Client secrets are generated by Auth with at least 256 bits, shown once, stored hashed, and rotated with an overlap window. The implicit and hybrid flows are available only as a named per-app opt-in for legacy SaaS that requires them. None of this loosens existing RER registrations, which keep `private_key_jwt` and mandatory PKCE. Generic clients receive documented consent, session, UserInfo, logout (RP-initiated, front-channel and back-channel) and key-rotation semantics; denied grants cannot mint tokens.

**Acceptance.**
1. Register confidential SaaS clients with each of `client_secret_basic`, `client_secret_post` and `private_key_jwt`, and a public native client with `none` plus PKCE, through the catalog/API; complete code flows and logout for each and rotate a secret with overlap.
2. Refuse a wrong or rotated-out secret, a public client without PKCE, redirect substitution, token substitution, code replay and unsupported grants.
3. Re-run the strict RER journey unchanged and inspect each connection’s advertised profile.

#### AUTH-MAPPING-001 — Attribute and NameID transform language

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Per-app SAML attributes, NameID and OIDC claims, SCIM/API attribute pushes and generated usernames are computed by a documented, versioned expression language over the person's directory, source and group data. It offers string functions (concatenate, lower/upper case, substring, replace, regular-expression replace, trim, pad), conditionals and null handling, date formatting, group-membership tests and list filters, and lookups of the person's manager and source fields—enough to express, for example, a `first.last` username or an app role chosen from group membership. Expressions are typed, side-effect free, cannot read secrets or make network calls, and are bounded in run time. The editor previews each expression's output for chosen people before saving, flags people for whom it yields empty or duplicate values, and every change is versioned and audited. AUTH-CATALOG-002 API provisioning adapters and AUTH-LIFECYCLE-001 future provisioning doors inherit these same computed values before shipping.

**Acceptance.**
1. Through the app setup door, map NameID to a computed `first.last` value with a collision suffix, map a role from group membership and push a formatted date over SCIM; preview against three people including one with a missing field, then launch and provision and read the values back at the SP and SCIM service.
2. Refuse an expression that reads a secret, calls out or exceeds the time bound; roll back to the previous version.
3. Exact semantics: language version 1 is typed JSON over an explicit directory/source/manager/group projection, with no credential/runtime access, dynamic code or network operations.
4. Character work, depth, nodes, output size and elapsed time are bounded.
5. Preview allocates collision suffixes against the entire directory; a save requires the exact preview and current version, and rollback publishes a new audited version.
6. Output doors include SAML, generic OIDC and SCIM.

### SaaS, directories and workforce lifecycle

#### AUTH-CATALOG-001 — Production SaaS application catalog

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-ROLE-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** A maintained catalog configures Google Workspace, Microsoft 365, Slack, GitHub Enterprise, AWS IAM Identity Center, Salesforce and Zoom for SAML/OIDC SSO and supported lifecycle APIs/SCIM. Each recipe states required vendor edition/permissions, groups/roles, attribute ownership, test-user procedure, secret/certificate rotation and deactivation/session limits. Administrators can clone a recipe into a generic connector, securely enter provider credentials, test, preview changes, approve and roll back. A catalog label alone is not a working integration. These seven are the deep-journey anchors; catalog breadth is AUTH-CATALOG-002 and Microsoft 365 domain federation is AUTH-M365-001.

**Acceptance.**
1. For each of the seven named services, an authorized US test tenant connects from catalog, assigns a test group/role, creates or binds the correct account, launches SSO, changes role and offboards it; read back remote state and document any external-session limit.
2. Inject one provider denial and prove it remains unresolved.

#### AUTH-CATALOG-002 — Catalog breadth and verification cadence

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** The catalog carries at least 100 tested recipes for the SaaS apps US small and mid-size companies use most, each tagged SAML, OIDC, SWA (AUTH-SWA-001), SCIM or vendor API, with SCIM or API provisioning wherever the vendor offers it on any plan, and the plan it needs named. The minimum set includes, beyond AUTH-CATALOG-001's seven: Atlassian (Jira, Confluence via Atlassian Guard), Zendesk, HubSpot, Dropbox, Box, Notion, Asana, 1Password, DocuSign, Miro, Figma, Linear, monday.com, Smartsheet, Airtable, Calendly, Adobe Creative Cloud, Canva, Intercom, Freshdesk, ServiceNow, Jamf Pro, Kandji, CrowdStrike Falcon, Datadog, PagerDuty, Snowflake, Tableau, Expensify, Ramp, Brex, BILL, QuickBooks Online, NetSuite, Greenhouse, Lever, Gong, Loom, Webex, RingCentral, Dialpad, GitLab, Bitbucket, Sentry, Cloudflare, Google Cloud, Lucid, Coupa, Carta, Vanta, Drata, Secureframe, Thoropass, Lattice, Culture Amp, Rippling, Gusto, BambooHR, Workato, Zapier, Retool and Postman. A public catalog page publishes the recipe count, each recipe's supported features and its last-verified date. Every recipe is re-verified against a vendor sandbox or authorized test tenant at least every 90 days and within 14 days of a vendor-announced breaking change; a recipe past its date is marked stale in the catalog and at activation, never silently served as verified. The Vanta, Drata, Secureframe and Thoropass recipes carry, beyond sign-in to the platform, the AUTH-COMPLIANCE-001 identity-provider connector, and every recipe states whether the app supports AUTH-LOGOUT-002 session or token revocation. Employers can request a recipe, and AUTH-AGENT-001 drafts new ones, with security, accounts and external classes decided by company policy. Future API/provisioning doors inherit AUTH-MAPPING-001 computed-value validation and preview/version semantics.

**Acceptance.**
1. The catalog door lists at least 100 recipes, every one named above among them, each with protocol tags and a last-verified date within 90 days.
2. A random sample of 10 recipes, drawn by the test run, each passes AUTH-CATALOG-001's connect/assign/launch/role-change/offboard journey with remote state read back.
3. Age one recipe past its date and see it marked stale at the catalog and at activation.

#### AUTH-M365-001 — Microsoft 365 domain federation and licensing

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Auth federates an employer's Microsoft 365 domain as its identity provider using WS-Federation (passive) for browser and modern-authentication clients, with a WS-Trust 1.3 active endpoint for rich clients that still use it (workers on password compatibility only, whose password follows AUTH-PASSWORD-001 and AUTH-PASSWORD-002; passkey-only workers use modern authentication). Claims map the person's ImmutableID (`onPremisesImmutableId`, or Auth's stable source ID when no on-premises AD exists) as the `persistent` NameID/`ImmutableID` claim and the UPN as `IDPEmail`. The setup door converts a verified domain from managed to federated through Microsoft Graph (`internalDomainFederation`), first with Microsoft's staged-rollout group, and converts back to managed for rollback; it warns that Microsoft can take up to two hours to apply a change, schedules the cutover window and keeps a cloud-only emergency administrator outside federation. A tested client matrix is published and accepted: Outlook on the web, Outlook desktop for Windows and Mac, Teams desktop and mobile, OneDrive sync for Windows and Mac, Outlook mobile for iOS and Android, and Office desktop apps. Group-driven license assignment assigns and removes Microsoft 365 SKUs and service plans through Microsoft Graph, shows unused seats, and reclaims a leaver's licenses after the AUTH-WORKFLOWS-001 mailbox steps complete.

**Acceptance.**
1. In an authorized Microsoft 365 test tenant, federate a verified domain in a staged-rollout group, then fully; sign in with each client in the matrix and inspect the ImmutableID and IDPEmail claims.
2. Roll back to managed and sign in again.
3. Add a person to a licensing group and see the SKU assigned, remove them and offboard another, and see each license reclaimed in Microsoft's admin data; a client that fails is shown as a failed matrix row, never omitted.

#### AUTH-SCIM-001 — Outbound provisioning and deprovisioning

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** App/group assignments create, update, suspend/reactivate and deprovision users and groups using SCIM 2.0 or a declared vendor API. Administrators preview attribute/role/group push, collision decisions and destructive effects. Stable external IDs, pagination, PATCH/filter semantics, idempotency, rate limits, credential rotation, remote drift and partial failure are handled without duplicate people or privilege escalation. Disable locally first on a leaver; retain each remote obligation until actual app access and supported sessions/tokens are verified revoked. Changes are pushed on the event, not in a batch, within the AUTH-TIMING-001 bounds: dispatched within 60 seconds and remote state verified within 5 minutes for a healthy connector.

**Acceptance.**
1. Assign a group through admin UI/API to a real SCIM service, provision users/groups, change a role and email, then revoke while the provider returns 429/503 and later recovers.
2. Inspect one account per person, persisted per-app outcomes with dispatch and verification times inside the bounds while healthy, no duplicate side effect and verified deactivation rather than a green queue submission.

#### AUTH-SCIM-002 — Inbound directory synchronization

*Tier:* Core · *From:* AUTH-SCIM-002 · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers can make an authorized generic SCIM 2.0 provider, Microsoft Entra ID, Okta or Google Workspace directory the source for users, groups and membership. A source connector has a scoped credential, verified organization binding, source-of-truth fields, conflict preview and reconciliation bounded by AUTH-TIMING-001: pushed SCIM requests applied within 60 seconds, polled deltas at least every 15 minutes and a full reconciliation at least every 24 hours. Deleting an upstream record cannot silently delete audit or grant a reused email authority; a full-feed outage never means every employee left. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping. Every original acceptance point remains required. Related outcomes: AUTH-SCIM-003.

**Acceptance.**
1. Connect each named directory and a generic SCIM client through setup, import paginated users/groups, apply a mover and deactivate a leaver.
2. Send a foreign-tenant request, duplicate event and incomplete/full-empty snapshot; verify isolation, stable IDs and a held destructive change pending confirmation.

#### AUTH-SCIM-003 — Inbound delivery approval and execution custody

*Tier:* Core · *From:* AUTH-SCIM-002 · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Each delivery stages exact selected changes and a preview digest until an authorized organization administrator decides it with the required proof. Approval never follows from receipt, a recurrence or a later delivery. Commit rechecks live authority, content and target; drift returns to review and interruption recovery prevents duplicate effects. Receipt, approval, effective and application times remain distinct; approval wait remains in receipt-to-application reporting. Timing, identity planning, hook and follow-up duties retain every original bound. Related outcomes: AUTH-SCIM-004.

**Acceptance.**
1. Incoming observations remain staged until an authorized organization administrator approves one exact delivery, selected changes and preview digest with hardware passkey and fresh local email proof.
2. Receipt and staging grant no sign-in, enrollment, assignment or authority-changing effect.
3. Execution rechecks current approver authority, approved content and target; drift returns to review, and interruption recovery prevents duplicate effects.
4. Recurring pulls and later deliveries never approve themselves.
5. Missing or empty feeds never infer termination, and outbound reminders require separate audited consent.
6. For this interim approved-delivery profile, execution timing starts at exact approval or the approved future effective time.
7. Record receipt, approval, effective and application times separately.
8. Approval delay remains visible and cannot be excluded when assessing the complete receipt-to-application source promise.

#### AUTH-SCIM-004 — Inbound receipt and application timing

*Tier:* Core · *From:* AUTH-SCIM-002 · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Each delivery stages exact selected changes and a preview digest until an authorized organization administrator decides it with the required proof. Approval never follows from receipt, a recurrence or a later delivery. Commit rechecks live authority, content and target; drift returns to review and interruption recovery prevents duplicate effects. Receipt, approval, effective and application times remain distinct; approval wait remains in receipt-to-application reporting. Timing, identity planning, hook and follow-up duties retain every original bound. AUTH-HRIS-002 exact-approval and interruption-recovery protections, AUTH-DIRECTORY-001 identity and planner protections, AUTH-HOOKS-001 import protections and AUTH-FOLLOWUP-003 consent and follow-through obligations remain inherited before their receiving doors ship.

**Acceptance.**
1. The original 60-second pushed application, 15-minute polling and 24-hour full-reconciliation targets remain unchanged; staging alone does not satisfy them or timely deprovisioning.
2. An approved leaver event retains every AUTH-TIMING-001 local-denial and downstream obligation.

#### AUTH-HRIS-001 — HR-driven identity sources

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Willow, Rippling, Gusto, BambooHR, Workday, ADP Workforce Now, UKG Pro, Paylocity, Namely and SAP SuccessFactors supply employment/source IDs, manager, department, location, worker type and effective dates through authorized connectors. Each connector states whether it receives vendor events or polls; events are applied within 60 seconds and polls run at least every 15 minutes (AUTH-TIMING-001), and a source with no successful read for 2 polling intervals is flagged stale. HR systems without a connector use AUTH-HRIS-002's scheduled file feed. Employers select field precedence and approved joiner/mover/leaver policies, including contractors and rehires. Preview shows exact access effects before activation, separates future hires from active workers, detects stale/missing feeds and rejects untrusted payload instructions. Auth owns identity/access; payroll, benefits, time off and employee files stay in the HR/payroll products. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

**Acceptance.**
1. Connect each of the ten named HR sources in an authorized tenant; synchronize a future hire, US employment start, department/manager move, scheduled termination and rehire, and measure each change's arrival against its event or polling bound.
2. Exercise DST/timezone effective times, conflicting sources, duplicate/out-of-order events and a stale feed; verify resulting access and unresolved source errors.

#### AUTH-HRIS-002 — Scheduled HR file feeds

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-INPUT-003 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** For any HR or payroll system without a named connector, employers deliver a scheduled CSV feed by SFTP (Auth-hosted, key-authenticated per employer) or upload, with a saved column mapping and the same preview, field precedence, effective-date, joiner/mover/leaver policy and stale-feed rules as AUTH-HRIS-001. The schedule is hourly or daily as the employer chooses; a feed missing past its schedule plus one interval is stale and raises a follow-up (AUTH-FOLLOWUP-001), and a feed that would terminate more than a set share of workers (default 5%) or arrives empty is held for confirmation rather than applied. Files are retained per AUTH-RETENTION-001 and never treated as instructions. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

**Acceptance.**
1. Configure an SFTP feed with a mapping, deliver a file with a hire, a move and a termination and see the preview and resulting access; deliver a malformed file, an empty file and one terminating 20% of workers and see each held; skip a delivery and see the stale flag and follow-up.
2. Refuse a wrong SFTP key and a file for another employer.

#### AUTH-LIFECYCLE-001 — Complete joiner, mover and leaver execution

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-BACKUP-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** An approved HR or administrative event creates a durable, per-person plan of directory changes, group/app/role assignments, credential/session actions, owners and deadlines. Actions remain inside the employer’s scoped connector authority and carry access, security or destructive as applicable; the company’s policy decides each agent or embedded-automation call. Joiners are ready at their authorized start, movers lose obsolete access, and leavers lose Auth access with every downstream revocation tracked, each within the numeric bounds of AUTH-TIMING-001. Reconciliation survives restart, handles uncertainty without blind duplicate writes, and never marks a person fully offboarded while an app still has unresolved access. Employer-built steps, such as transferring a leaver's files to their manager, run as AUTH-WORKFLOWS-001 automations recorded in the same plan. Future API/provisioning doors inherit AUTH-MAPPING-001 computed-value validation and preview/version semantics.

**Acceptance.**
1. From HR/admin doors, onboard a sales hire across Workspace, Slack and Salesforce, move them to engineering/GitHub, then terminate while one provider is unavailable.
2. Restart the worker, inspect deadlines and approvals, restore the provider and confirm each remote outcome with its timestamps; local access must remain denied throughout.

#### AUTH-TIMING-001 — Measured lifecycle time bounds

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Every lifecycle change carries numeric bounds that a test or auditor can check. Leaver: within 60 seconds of the leaver event committing, Auth refuses every session, refresh grant, UserInfo and introspection call, launcher tile, extension fill and RADIUS/LDAP bind for the person, and has sent back-channel logout to every linked app; self-contained access tokens already issued expire within their at most 5-minute lifetime. Downstream: each healthy SCIM/API connector has the change dispatched within 60 seconds and remote state verified within 5 minutes; past 15 minutes an unverified change is escalated as unresolved (AUTH-FOLLOWUP-001). Joiner: the AUTH-ONBOARD-001 activation invitation goes out at its lead time, accounts are provisioned and verified by 06:00 employer-local time on the start date (or at an HR-set start time), and sign-in is permitted from the authorized start. Mover: obsolete access is removed under the same downstream bounds. Sources: HR events applied within 60 seconds, HR polls at least every 15 minutes, file feeds per their schedule, and a full reconciliation of every source and connector at least every 24 hours. Each obligation records event time, local-denial time, dispatch time and remote-verified time per app; a timeliness report shows the share of leavers fully deprovisioned within 1 hour and within 24 hours for any period, with unverified apps listed by name.

**Acceptance.**
1. With healthy connectors to three SaaS test tenants, terminate a person and measure: local refusal on every door and logout delivery within 60 seconds, dispatch within 60 seconds and remote verification within 5 minutes per app.
2. Hold one connector down past 15 minutes and see the escalation; add a future hire and see verified accounts before 06:00 local on the start date.
3. Export the timeliness report for the period and reconcile each row's four timestamps with the audit trail.

#### AUTH-WORKFLOWS-001 — Employer-built identity automations

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Administrators with the automation permission build versioned automations in a no-code editor: a trigger on an identity event (hire, start date, move, attribute change, leave, group membership change, access request decision, a schedule or a webhook), conditions over directory and source data (AUTH-MAPPING-001 expressions), and steps that call connector actions, make a signed HTTP request to any HTTPS REST endpoint with stored connection authentication (API key, basic, bearer or OAuth 2.0 client credentials) and use its parsed response in later steps, wait for a date or an approval, branch, or notify. HTTP step destinations are validated against SSRF as AUTH-EVENTS-001 validates webhooks, and their credentials stay in connector custody. Steps remain within the automation’s scoped connector authority. Each agent or embedded-automation call carries the classes computed in the Agent surface, including destructive for irreversible effects and access for authority changes; the company’s policy decides its disposition. Every automation has a dry run against a chosen person that shows each step's intended effect without performing it, and every run is recorded against that person's AUTH-LIFECYCLE-001 plan with inputs, step outcomes, remote verification and retries, so a failed step stays an open obligation. Auth ships tested templates: Google Drive file ownership transfer to the manager (Data Transfer API), Google Calendar transfer, Gmail delegation to the manager and a leaver auto-reply, Microsoft 365 mailbox conversion to a shared mailbox with manager access, OneDrive access grant to the manager, and license reclaim for Google Workspace, Microsoft 365, Slack, Zoom and Salesforce. Templates are copied and edited, never run blind.

**Acceptance.**
1. In authorized Google Workspace and Microsoft 365 test tenants, enable the leaver templates and terminate a person through HR: read back Drive files owned by the manager, the transferred calendar, the Gmail auto-reply and delegate, the shared mailbox with manager access and every reclaimed license.
2. Dry-run an edited automation and see no remote change; fail one step and see it held as an unresolved obligation in the person's plan; refuse a step outside the automation's granted scope.
3. Call a generic REST endpoint with stored OAuth client credentials and use its response in a later step; refuse an HTTP step aimed at a private address.

#### AUTH-FEDERATION-001 — Generic upstream federation

*Tier:* Core · *From:* AUTH-FEDERATION-001 · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Employers configure generic OIDC and SAML 2.0 upstream IdPs as well as Google Workspace, Microsoft Entra ID and Okta for coexistence, mergers or partner employees. A delegated setup portal verifies domains, issuer/metadata and keys, tests a representative user, previews mappings and activates only after authorized approval. Validate issuer, signature, audience, correlation, clock/replay and trusted subject/email evidence; prevent federation loops, unsolicited account merging and stale configuration admission. Upstream proof never substitutes for the local email/hardware requirements of existing Auth administration. Future machine administration doors inherit AUTH-ADMINAPI-001 credential, scope/resource, excluded-action, live-authority, audit and concurrency checks before shipping. Every original federation acceptance point remains required. Related outcomes: AUTH-FEDERATION-002.

**Acceptance.**
1. Through delegated setup, connect generic SAML/OIDC plus the three named providers, sign in to an assigned downstream app and rotate upstream keys.
2. Refuse an email-only collision, replay, changed issuer/configuration, malicious metadata URL and foreign organization setup; simulate upstream outage and use approved recovery.

#### AUTH-FEDERATION-002 — Reviewed upstream activation custody

*Tier:* Core · *From:* AUTH-FEDERATION-001 · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** The affected employer owner activates exact reviewed ordinary subjects and immutable mappings, with hardware passkey and fresh email proof, independently of installation hosting authority. The commit rechecks organization, trust and mapping; drift returns to review. A representative validation neither creates a session nor grants authority. Store only necessary trust/binding facts and redacted outcomes. Machine administration only enables or disables approved trust under AUTH-ADMINAPI-001.

**Acceptance.**
1. The interim activation profile is owner-only and limited to exact reviewed ordinary subjects and their immutable mappings.
2. The affected organization’s owner approves with hardware passkey and fresh local email proof; current authority, organization binding, trust configuration and mapping are rechecked at commit, and drift returns to review.
3. Installation authority grants no administration of an isolated organization.
4. A representative test validates upstream proof and previews mappings only: it creates no employee session, authenticated membership, downstream grant or administrator authority.
5. Activation does not itself sign in the employee or bypass assignments, policy or AUTH-PROFILE-001 existing-account and new-identity proof.
6. Record only necessary trust configuration, reviewed bindings, approval facts and redacted validation outcomes; disclosure remains governed by existing claims and scope rules. Upstream proof never replaces local administrator proof. Machine administration remains limited to enabling or disabling approved trust; future machine doors inherit all AUTH-ADMINAPI-001 protections.

#### AUTH-SOCIAL-001 — Controlled external identity sign-in

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Google, GitHub and Sign in with Apple adapters support employees/contractors only when their employer explicitly permits them. Verified stable issuer/subject, consent, minimum scopes and explicit existing-account proof govern binding; hiding an email or changing an upstream address does not merge accounts. Social proof has its actual assurance and must satisfy employer MFA and recovery policy.

**Acceptance.**
1. Configure each adapter with a real provider app, sign in an invited contractor, exercise private/changed email and unlink/relink, then withdraw employer permission.
2. Refuse a same-email unproven identity and observe immediate policy denial on further token issuance.

#### AUTH-LEGACY-001 — LDAP, Active Directory and RADIUS access

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-INSTALL-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Auth provides documented LDAP/LDAPS and RADIUS integration for legacy apps, VPNs and Wi-Fi, plus scoped Active Directory coexistence/synchronization where employers retain AD. A separately deployed authenticated connector handles private-network access, certificate/secret rotation, group restrictions, health and revocation acknowledgments. Each recipe publishes its factor matrix rather than "MFA-compatible": RADIUS PAP recipes for Palo Alto GlobalProtect and Cisco Secure Client support password plus Auth push (AUTH-AUTHENTICATOR-001) and password plus TOTP (entered as a challenge response or appended code), number matching is not available over RADIUS and is replaced by push context, and passkeys are not available over RADIUS; Meraki and other 802.1X Wi-Fi recipes support EAP-TLS with an Auth-issued device certificate (AUTH-DEVICE-001) and EAP-TTLS/PAP with password plus push; LDAPS binds support password plus push for apps that tolerate the wait, and otherwise password only behind network policy. Active Directory coexistence states each direction: AD as a source of people and groups (supported), delegated authentication of Auth sign-in to AD (supported), password write-back to AD for workers on password compatibility (supported), and group push from Auth to AD (supported), each through the connector with its scope and conflict rules shown. Every password accepted here follows AUTH-PASSWORD-001's policy and lockout, and a change made anywhere propagates under AUTH-PASSWORD-002. Protocol limitations and unavailable posture fail closed under policy. The connector is engineering scope, not a reason to omit legacy access.

**Acceptance.**
1. Install the real private connector.
2. Sign in to GlobalProtect through RADIUS with password plus push and with password plus TOTP; deny the push and let one time out, and each sign-in is refused.
3. Join Meraki Wi-Fi with EAP-TLS and with EAP-TTLS plus push, bind an LDAPS app, and exercise each AD direction (source import, delegated authentication, password write-back, group push).
4. Disable the employee, rotate trust and disconnect the connector; prove new access stops within AUTH-TIMING-001's leaver bound and unresolved external sessions remain visible.

#### AUTH-DEVICE-001 — Device identity and trust

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Windows, macOS and Linux directory/device connectors and Intune, Jamf Pro, Kandji and JumpCloud posture integrations bind device identity to a person and report encryption, screen lock, OS/compliance and last contact for conditional access. iOS, iPadOS and Android devices report posture through the Auth mobile app and those MDMs: OS version and patch level, jailbreak or root detection, screen lock and biometrics, disk encryption and managed or personal status, each usable in AUTH-POLICY-001 like desktop posture. Employees enroll and remove devices with ownership proof; administrators can revoke device trust and certificate-based Wi-Fi/VPN access. Native/device software, packaging, updates and OS permissions are deliverables. Auth owns identity and trust decisions; broad endpoint patching, EDR and software deployment remain with those endpoint products.

**Acceptance.**
1. Enroll one device per supported desktop OS and an iPhone and an Android phone, and read posture from each named management service; launch from a jailbroken or rooted phone and from one below the required OS version and be denied.
2. Launch an app, stale the posture, mark a device noncompliant and revoke it; verify policy denial, trust removal and an auditable employee/help-desk recovery path.

#### AUTH-DESKTOP-001 — Sign in to the computer with company identity

*Tier:* Core · *Cites:* BASE-BACKUP-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-3, R-4

**Requirement.** Employees sign in to their Mac and Windows PC with their Auth identity. On macOS, an Auth Platform SSO extension, deployed by Jamf Pro, Kandji, Intune or JumpCloud, supports both Platform SSO modes: password sync (the local account password follows the Auth password) and passwordless sign-in with a Secure Enclave key, and creates or binds the local account at first login, where a person with no factor yet signs in with a temporary access pass (AUTH-TAP-001) and enrolls one. In password-sync mode the password follows AUTH-PASSWORD-001's policy, shows its expiry warning and offers self-service reset and unlock at the login window under AUTH-PASSWORD-002. On Windows 10/11, an Auth credential provider does the same at the sign-in and unlock screens. MFA at the OS login screen uses push or TOTP from the Auth authenticator (AUTH-AUTHENTICATOR-001) or a security key, as policy requires. Offline sign-in uses a cached credential valid for an employer-set period (default 7 days, maximum 30) after which the device must reach Auth again. A locked-out employee gets a time-limited, single-use recovery PIN from help desk under AUTH-RECOVERY-003, valid for at most 1 hour. When a person is suspended or leaves, the device refuses their next online login and unlock, and refuses offline login once its next online check or the offline period ends; a device the employer marks lost refuses their offline login at its next contact. On domain-joined Windows PCs, Kerberos desktop SSO (SPNEGO through the private connector) signs a domain-signed-in employee in to Auth's web sign-in without re-entering credentials, as one factor, with policy deciding whether further MFA is required.

**Acceptance.**
1. On a managed Mac and Windows PC, sign in at the OS login with company identity using push, TOTP and a security key; on the Mac exercise both password-sync and Secure Enclave modes.
2. Sign in offline within and beyond the cached period.
3. Lock an employee out and restore them with a help-desk recovery PIN, then refuse the PIN's reuse and its use after an hour.
4. Offboard the employee and see the next online login and unlock refused.
5. On a domain-joined Windows PC, open the launcher and be signed in by Kerberos, then be stepped up where policy requires.

#### AUTH-GATEWAY-001 — On-premises web apps through an access gateway

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** An Auth access gateway, deployed beside the private connector (AUTH-LEGACY-001) as a container or VM image, fronts on-premises and private web apps that use header-based authentication, Kerberos constrained delegation (IIS and other Windows-integrated apps) or no sign-in of their own. It signs the employee in through Auth, applies AUTH-POLICY-001 per app and per path, and passes identity to the app as mapped headers (AUTH-MAPPING-001) or a Kerberos ticket, always stripping identity headers supplied by the client. Apps are published to the launcher through an outbound-only tunnel with no inbound port opened on the private network; session lifetime, logout and leaver denial within AUTH-TIMING-001 apply. This is the job Okta Access Gateway and the Microsoft Entra application proxy do.

**Acceptance.**
1. Deploy the gateway on a private network with no inbound port and publish a header-based test app and an IIS app using Kerberos constrained delegation.
2. Launch both as an assigned employee and read the identity headers and Kerberos identity at each app.
3. Send a forged identity header and see it stripped; deny an unassigned employee and a path-level rule; offboard the employee and see the next request refused within 60 seconds.

#### AUTH-PRIVILEGED-001 — Server and SSH access without standing keys

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-INPUT-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Engineers reach Linux servers over SSH with short-lived SSH certificates (default 10 minutes, at most 12 hours) that Auth issues after sign-in and AUTH-POLICY-001, for server groups mapped from Auth groups; and reach Windows servers over RDP through the access gateway (AUTH-GATEWAY-001) after Auth sign-in. A server agent creates and removes local accounts and grants sudo or local administrator rights from group membership; servers without the agent trust Auth's SSH certificate authority through OpenSSH's `TrustedUserCAKeys`. Elevation to sudo or administrator is requested and time-bound through AUTH-REQUESTS-001. No static SSH keys are issued. Every session's person, server, time, elevation and, where the agent captures them, commands go to AUTH-AUDIT-001. On a leaver, no new certificate is issued within AUTH-TIMING-001's local bound and the agent removes the account. This is the job Okta Privileged Access does.

**Acceptance.**
1. Enroll two Linux servers (one with the agent, one with only the CA key) and one Windows server.
2. As an engineer in a server group, sign in with a passkey, obtain a certificate and SSH in; RDP to the Windows server through the gateway.
3. Be refused sudo until a time-bound request is approved, then gain it and see it expire.
4. Refuse a server outside the person's groups, an expired certificate and an unassigned engineer.
5. Offboard the engineer and see the next connection refused and the local account removed; the audit shows each session.

### Access governance and application authorization

#### AUTH-GRANTS-001 — App roles, APIs and service identities

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Group and role assignments govern app launch, provisioned app roles and registered API permissions. App owners define scopes, role/attribute/resource relationships and fine-grained permission checks through a documented authorization API, with default deny and current tenant/person context. Service accounts use scoped, expiring OAuth client-credentials tokens with distinct accountable owners, targets and audit; they cannot impersonate a person or obtain interactive administrator proof. Administering Auth itself by machine is only through AUTH-ADMINAPI-001's admin scopes. External app authorization remains enforced in the app using verified claims or Auth decisions.

**Acceptance.**
1. Register an API, map a group to read/write and resource-level permissions, and call it as an employee and a service identity.
2. Deny an unassigned role, cross-employer resource, wrong audience, excessive scope and revoked service credential; role removal must change the next authorization decision.

#### AUTH-TOKENS-001 — Refresh and delegated session lifecycle

*Tier:* Core · *From:* AUTH-TOKENS-001 · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-DATA-003, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Explicitly registered non-RER profiles may grant offline access with least-privilege consent, refresh-token rotation, reuse detection, family revocation, idle/absolute expiry and sender/client binding appropriate to the profile. Web/native SDKs rotate safely across concurrent requests without concealing replay. Employees and administrators see active app/device grants and can revoke them; disabling a person, app or grant prevents refresh and triggers supported app/session revocation. AUTH-PROTOCOL-001 continues to offer no refresh/offline access. Related outcomes: AUTH-TOKENS-002.

**Acceptance.**
1. Use a native SDK to obtain an approved refresh grant, rotate it, replay an old token and revoke the family through My account.
2. Run concurrent refresh, expiry, suspension and app removal, confirming the resource API refuses invalid authority and strict RER clients receive no refresh token.
3. An administrator explicitly binds a general OIDC client to its own app's resource API, published scopes and chosen idle/absolute lifetimes; there are no implicit offline grants.
4. Each person consents to the exact app/device, audience, scopes and lifetimes.
5. S256 PKCE, registered client authentication and ES256 DPoP bind the grant.
6. Refresh digests rotate with one winner; authenticated consumed-token reuse ends the family without a grace interval or cached successor.
7. The SDK coalesces concurrent calls and commits storage before publishing a successor; failures require deliberate new consent.
8. Resource decisions recheck the family, current account/app/assignment, policy and API/profile revisions and preserve the app's subject policy.

#### AUTH-TOKENS-002 — Offline resource endings and portability

*Tier:* Core · *From:* AUTH-TOKENS-001 · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-DATA-003, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Offline app/device grants have Auth-specific endings: browser expiry alone leaves them live, while explicit source-session revocation, account/app/profile endings and grant expiry end resource authority. My account and scoped administrator custody retain the Auth proof and rank distinction. AUTH-PROTOCOL-001’s strict RER profile remains separate. SDK consumers inherit the storage, binding, concurrency and failure semantics of AUTH-TOKENS-001; AUTH-AGENT-006 is a separate task profile.

**Acceptance.**
1. Browser expiry alone does not end an offline grant; explicit source-session revocation, account/app/profile endings and either grant expiry do.
2. My account and scoped administrator doors retain the existing permission, view/edit resource, hardware/fresh-email and account-rank fences.
3. Supported OIDC logout is queued without claiming remote deletion.
4. Credentials and family authority are nonportable, and the shared registry covers erasure/retention.

#### AUTH-HOOKS-001 — Inline hooks for custom sign-in logic

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers register signed HTTPS inline hooks that Auth calls synchronously at named points: before token issuance (add or change claims within an allow-listed set), before a SAML assertion (add attributes), at self-registration (allow, deny or change profile fields), at password import (verify a migrating password under AUTH-MIGRATION-002) and at user import (match or create). Each hook receives a documented minimal payload, is signed by Auth and must answer within its timeout (default 3 seconds, maximum 10). The employer chooses fail-open or fail-closed per hook; security-relevant points default to fail-closed. A hook can never grant an administrator role, remove required MFA, change the subject or override AUTH-POLICY-001. Destinations are validated against SSRF as AUTH-EVENTS-001 validates webhooks, and every call is audited with latency and outcome. This is the job Okta's token, SAML, registration, password-import and user-import inline hooks do. Under current-capability inheritance, AUTH-MIGRATION-002 must supply the password-verification/first-login hook before that bridge ships, and new match/create doors in AUTH-HRIS-001, AUTH-HRIS-002 and AUTH-SCIM-002 inherit all hook protections before shipping.

**Acceptance.**
1. Register a token hook that adds a cost-center claim and see it in the ID token; a registration hook that denies an outside domain; and a hook that tries to add an administrator role and change the subject, and see both changes refused.
2. Let a fail-closed hook time out and see the sign-in refused with a clear error, then a fail-open hook time out and see sign-in continue with the event logged.
3. Refuse a hook URL that resolves to a private address.
4. signed hooks run for strict RER and general OIDC ID tokens, SAML assertions, self-registration, staged move-in admission and source-id-matched directory imports.
5. Token/SAML outputs are restricted to explicit custom fields; registration/import may alter only the currently exposed name field, and neither may change an identity binding or authority.
6. Every remote call is bounded, audited and followed by a fresh issuance/commit authority check.
7. Unavailable password-hook registration refuses; no password verifier is simulated.

#### AUTH-REQUESTS-001 — Access requests and time-bound grants

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employees request apps/roles with purpose and duration; policies route to manager, app owner or security approvers, handle separation of duties and forbid self-approval. Approvers see current employment, existing access, risk and license consequence, and decide with the proof AUTH-DECISIONS-001 sets, on the web or in Slack or Teams (AUTH-CHAT-001). Exact approved scopes provision only after a fresh authorization check, expire automatically and verify removal in connected apps. Denial, cancellation, approver absence, extensions and emergency elevation leave attributable history. The administrator selects an independent decider and caps temporary duration at thirty days. Record exact resource, role, purpose and duration; separation of duties and live proof/classification are rechecked at commit. Temporary grants and pre-existing direct assignments remain distinct: expiry removes only temporary authority. Missing or expired decider authority and unknown remote removal remain open obligations. (RL-105). Privilege classification, role-order caps and everyday proof follow AUTH-DECISIONS-001.

**Acceptance.**
1. Request Salesforce access and temporary AWS elevation from the launcher, have the required independent people approve, provision only those roles, and let the grant expire while a connector fails.
2. Reject self/stale/concurrent approvals and verify revocation/escalation before closing the request.
3. Native requests support an explicitly administrator-selected independent decider, a maximum thirty-day duration, exact approval/denial and restart-safe expiry that stays pending until remote removal is verified.
4. The administrator selects an independent decider and caps temporary duration at thirty days. Record exact resource, role, purpose and duration; separation of duties and live proof/classification are rechecked at commit. Temporary grants and pre-existing direct assignments remain distinct: expiry removes only temporary authority. Missing or expired decider authority and unknown remote removal remain open obligations.

#### AUTH-REVIEWS-001 — Periodic access certification

*Tier:* Core · *Cites:* BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Administrators schedule recurring manager/app-owner reviews with a fixed snapshot of identities, groups, role grants, source, last observed use and data freshness. Reviewers certify, reduce or revoke with reasons; delegation, reminders, absence and overdue escalation are explicit. Completed reviews retain decisions and verified remediation results, including unresolved connector failures, and export a reproducible SOC 2 evidence package without claiming certification. Campaign creation, delegated review authority and export require current published scoped permission and administrator proof. Ordinary certify, reduce and revoke follows AUTH-DECISIONS-001 unless privileged authority is implicated. Delegation never enlarges the delegator’s app/person scope or persistent caps; changed or unknown hierarchy invalidates stale authority and refuses widening. Completion preserves immutable decisions and unresolved remote-removal failures. (RL-107). Future POLICY/PASSWORD clauses inherit immutable policy-version evidence before shipping. Privilege classification, role-order caps and everyday proof follow AUTH-DECISIONS-001.

**Acceptance.**
1. Start a quarterly review of employee, contractor and service-account access, delegate one reviewer, certify one role and revoke another.
2. Change membership mid-review, miss a deadline and fail a provider removal; inspect immutable snapshot, new drift and an export whose completion cannot conceal unfinished remediation.
3. Native reviews retain immutable access snapshots and separate current drift, certify/revoke decisions and read-back remediation, including failures.
4. Recurring snapshots and overdue records are durable.
5. Explicit app-role reduction, consented decider reminders, absence escalation, scoped published review permissions and optional native administrator-grant inventory are supported.
6. Native role revocation uses the existing rank/scope evaluator and refuses owner removal.
7. Under RL-107, scheduling, delegation and export require their published scoped permission, hardware and fresh email.
8. Campaign creation, delegated review authority and export require current published scoped permission and administrator proof. Ordinary certify, reduce and revoke follows AUTH-DECISIONS-001 unless privileged authority is implicated. Delegation never enlarges the delegator’s app/person scope or persistent caps; changed or unknown hierarchy invalidates stale authority and refuses widening. Completion preserves immutable decisions and unresolved remote-removal failures.

#### AUTH-DECISIONS-001 — Proof levels for administration and everyday decisions

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** The contract lists who carries the administrator gate. Bound by AUTH-IDENTITY-001's hardware passkey and fresh local email proof for every write: owner, identity administrator, security/policy administrator, app administrator (app configuration, credentials, connector authority), help desk (factor reset, recovery, suspension), auditor when exporting, and every custom role from AUTH-ROLES-001 holding any administrator permission; also any decision that grants an administrator or other privileged role, changes recovery, signing keys, identity providers or admin API credentials, or approves recovery of an administrator. Not bound: a manager, app owner or group owner approving or denying an access request for a non-privileged role, a group owner editing membership of a group that grants no privileged role, a reviewer certifying or revoking access, and an employee requesting access. Those decisions take an ordinary employee passkey sign-in plus the step-up their policy requires (by default a user-verified passkey assertion within the last 15 minutes, bound to the decision). The server checks the decider's current authority, the request's unchanged state and separation of duties at commit, whichever door the decision came through. Privileged roles are marked as such on each app and group, and that marking is itself an administrator write. Only a currently authorized administrator changes privilege classification, hierarchy or persistent caps. Unknown, stale or ambiguous hierarchy uses the privileged path; exact app-role classifications propagate to groups. Republication never silently widens an approved cap. Everyday nonprivileged decisions retain their employee-passkey and policy step-up path. (RL-101). Review-management permissions are AUTH-REVIEWS-001.

**Acceptance.**
1. As a manager with an employee passkey and no local email confirmation, approve a Salesforce request, edit a non-privileged group as its owner, and certify access in a review; each commits after step-up.
2. Attempt to approve a request for an administrator role, edit a privileged group and approve an administrator's recovery with the same proof; each is refused until the administrator gate is satisfied.
3. Approve a stale request and one the decider lost authority over between view and commit; both are refused.
4. Native doors use one single-use, session/decision-bound UV passkey assertion (15-minute expiry), atomic live authority/state fences and the existing administrator gate.
5. Apps default privileged until an explicit audited owner/admin classification, inherited by their groups; an exact app-role classification overrides that app default and propagates to groups granting the role.
6. Privilege classification remains owner/admin-only.
7. Only a currently authorized administrator changes privilege classification, hierarchy or persistent caps. Unknown, stale or ambiguous hierarchy uses the privileged path; exact app-role classifications propagate to groups. Republication never silently widens an approved cap. Everyday nonprivileged decisions retain their employee-passkey and policy step-up path.

#### AUTH-CHAT-001 — Approve, deny and certify from Slack and Microsoft Teams

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Auth's Slack app and Teams app deliver access requests, review items and reminders to the deciding person with the request context AUTH-REQUESTS-001 shows on the web, and let them approve, deny, ask for more information or certify in the message. A chat account is bound to an Auth person once, by signing in to Auth from the chat app's link (SSO into Slack or Teams through Auth also confirms the binding), and each action re-checks that the chat user, workspace or tenant and Auth person still match. Actions whose policy requires step-up open an Auth step-up page and commit only after it; grants of privileged roles show the request read-only with an "open in Auth" link and are decided only on the web under the administrator gate. Every chat decision is audited with the chat user, workspace, message and Auth person.

**Acceptance.**
1. In authorized Slack and Teams test workspaces, bind a manager, approve one request and deny another from each, certify a review item, and see the outcomes provisioned and audited.
2. Refuse an action from an unbound chat account, one bound to a different person, a stale or already-decided request and a removed binding; a privileged-role request offers only the web link.

#### AUTH-AUDIT-001 — Identity investigation and reporting

*Tier:* Core · *Cites:* BASE-AGENT-005, BASE-AUDIT-001, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-INSTALL-001, BASE-ROLE-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employees see their sign-in/device/grant history; authorized investigators search and correlate sign-ins, policy decisions, enrollment/recovery, app provisioning, approvals, agent actions and downstream confirmations. Reports show active workers, app/role/license assignments and orphaned access, and the named per-person reports of AUTH-REPORTS-001 (MFA enrollment, terminated people, administrators and privileged roles, dormant accounts, joiner/leaver timeliness, connector health), with unknown freshness explicit. Tenant-filtered export and streams to Datadog, Splunk, Microsoft Sentinel and the Evidence sibling carry stable event IDs, actor/delegate, target, time, policy revision and outcome; Compliance platforms that test the identity provider through a live connection (Vanta, Drata, Secureframe, Thoropass) receive per-person state through AUTH-COMPLIANCE-001, not a log export. Identity evidence is tamper-evident. Out of the box, sign-in, administration and decision events are searchable and exportable through the UI and a paginated log API for 13 months (AUTH-RETENTION-001's default).

**Acceptance.**
1. Investigate an employee’s failed sign-in through its policy decision and provisioning history, export a review period to each named sink/Evidence, and reconcile the AUTH-REPORTS-001 MFA-enrollment export for one employer row by row with its directory, with every person who has no factor present and marked non-compliant.
2. Query an event 12 months old through the log API on a default installation.
3. Reconcile event counts across pages, detect tampering/gaps, deny an auditor’s write attempt and prove erased subjects no longer disclose personal identifiers.

#### AUTH-REPORTS-001 — Named per-person identity reports

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Auth ships named reports, each with a defined column set, filters by employer, group, worker type and department, a CSV and admin API export, and a stated as-of time at which its row count reconciles to the directory. (1) **MFA enrollment:** one row per person in scope with Auth person ID, email, name, worker type, status, MFA compliant (yes or no against the employer's MFA policy), each enrolled factor type with its enrollment date and last use, and a password-only flag; a person with no factor appears as non-compliant and is never omitted. (2) **Terminated people:** person ID, email, termination effective time, leaver event time, local-denial time and full-deprovision time from AUTH-TIMING-001, and each app still unresolved, by name. (3) **Administrators and privileged roles:** each holder of a built-in or custom administrator role (AUTH-ROLES-001) or an app or group role marked privileged (AUTH-DECISIONS-001), with its resource set, who granted it and when, and last use. (4) **Dormant accounts:** active people with no successful sign-in in an employer-set number of days (default 90), with last sign-in time and door, and the apps they hold. (5) **Joiner and leaver timeliness** (AUTH-TIMING-001). (6) **Connector health:** each connector's last successful sync and open failures. Reports can be scheduled to email recipients and delivered to AUTH-COMPLIANCE-001 connectors and the Evidence sibling. Unknown or stale data is shown as unknown, never counted as compliant. Roles with the view-audit permission read reports; only roles with export rights export them, and each export is audited.

**Acceptance.**
1. With 20 people (15 with a passkey or push, 3 with only a password, 2 with no factor), export the MFA-enrollment report and reconcile it row by row with the directory: all 20 rows are present and the 5 non-compliant people are marked.
2. Terminate two people, one while a connector is held down, export the terminated-people report and reconcile each row's local-denial and full-deprovision times with the AUTH-TIMING-001 audit; the held app is named.
3. Grant and revoke a custom administrator role and see the administrators report follow; age a person past 90 days without sign-in and see them on the dormant report.
4. Refuse export to a role without export rights.
5. Each export's row count equals the directory count for its filter at its as-of time.

#### AUTH-COMPLIANCE-001 — Identity-provider connectors for compliance platforms

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Auth is the identity-provider connection of the employer's SOC 2 compliance-automation platform, so the platform's continuous tests keep their source through cutover and afterwards. Auth maintains a connector for each of Vanta, Drata, Secureframe and Thoropass, set up from that platform's catalog recipe (AUTH-CATALOG-002). **Vanta:** a private integration through Vanta's Build Integrations API that pushes the full state of `UserAccount` resources with `status`, `mfaEnabled`, `mfaMethods`, `authMethod` and `permissionLevel`, so Vanta reads Auth as the source of employment status and opens its offboarding checklist when Auth deactivates a person. **Drata:** a Drata identity-provider connection of Drata's CSV connection type, beside any others the account holds, kept current by Auth through Drata's public API so that "MFA on Identity Provider" is checked against Auth for every person sourced from it; any Drata partner listing needed for an automated connection is part of this clause's engineering. **Secureframe and Thoropass:** the vendor's documented custom identity integration, with the recipe stating whether the vendor's tests read a live connection or a delivered file. Each connector sends, for every person in scope: Auth person ID, work email and name; status active, suspended or terminated, with the termination time; MFA enrolled, true only when the person holds a factor that satisfies the employer's MFA policy; each enrolled factor type, mapped through a published per-vendor table to the vendor's values (passkey and security key, push, TOTP, SMS, email), with nothing unmapped silently dropped; group memberships, including AUTH-DIRECTORY-001 dynamic groups, so the platform scopes people and access reviews by Auth group; and administrator or privileged role (AUTH-DECISIONS-001). It pushes the full state at least hourly, and each lifecycle, factor or administrator-role change within AUTH-TIMING-001's 60-second dispatch bound. Each sync records the vendor's acknowledgment and, where the vendor's API allows, a read-back of what it stored. A failed or unacknowledged sync, or a last success older than two hours, shows on the connector's health and in AUTH-REPORTS-001 and raises an AUTH-FOLLOWUP-001 obligation; it is never shown green. Which people and groups are sent is an administrator write previewed with who is added and removed. Connector credentials stay in connector custody (AUTH-RETENTION-001), and every sync is audited. The same per-person state feeds the Evidence sibling. Auth supplies identity facts; the platform, Evidence and the auditor judge the controls.

**Acceptance.**
1. In an authorized Vanta test tenant, connect Auth through the private integration: Vanta's accounts page shows every Auth person in scope with the correct status, MFA status and factor types, and a custom MFA test passes.
2. Remove one person's last factor and see the test fail within one sync; offboard another and see them in Vanta's offboarding queue within one sync.
3. Scope by an Auth group and see Vanta's scope follow a membership change.
4. Repeat in a Drata test tenant and see "MFA on Identity Provider" pass and then fail the same way.
5. Configure the Secureframe and Thoropass recipes in authorized test accounts and see each person's MFA status.
6. Revoke the Vanta credential and see the connector unhealthy, with a follow-up raised, within two hours.

### Migration, integration and operations

#### AUTH-MIGRATION-001 — Switch from Okta, Entra ID or JumpCloud

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Guided migration from each named incumbent inventories users, immutable source subjects, groups, app/role assignments, SAML/OIDC settings, password-based (Okta SWA) app definitions, provisioning rules, factors, devices, admin roles with their resource sets, and policies through authorized APIs/exports, and lists each Okta Workflows flow with the AUTH-WORKFLOWS-001 template or step that replaces it (an API Connector card maps to the HTTP request step), and each Okta inline hook to its AUTH-HOOKS-001 equivalent. Preview maps what can transfer and names every unsupported/credential-bound item with an actionable reenrollment or partner step; never import working sessions, private keys or fake MFA proof. Factor and password re-enrollment runs as AUTH-MIGRATION-003's enrollment campaign. Staged cohorts, old-to-new subject maps, app-owner-approved subject binding, dual-provider coexistence, reconciliation and rollback preserve employee access without enabling imported authority. The inventory also lists the incumbent's identity-reading integrations: compliance platforms (Vanta, Drata, Secureframe, Thoropass) and any other service holding an incumbent API token or reading its system log. For each it names the Auth replacement (AUTH-COMPLIANCE-001 for compliance platforms, AUTH-EVENTS-001 or the AUTH-AUDIT-001 streams for log readers) or states that none exists. The cutover plan connects every replacement and holds cutover until each one's first successful sync, so no compliance test loses its source during an audit observation window. Final cutover verifies SSO and leaver revocation in every affected app.

**Acceptance.**
1. For Okta Workforce Identity, Microsoft Entra ID and JumpCloud separately, migrate a populated authorized test tenant with groups, apps, a collision, suspended worker and privileged assignment.
2. Pilot a cohort, re-enroll factors through the AUTH-MIGRATION-003 campaign, compare counts/permissions, roll back and cut over; prove old subjects cannot act as credentials and no app is silently omitted.
3. With Vanta and Drata connected to the incumbent, see both listed with AUTH-COMPLIANCE-001 as their replacement, and cutover held until each replacement's first sync succeeds.

#### AUTH-MIGRATION-002 — Custom-directory and progressive move-in

*Tier:* Core · *Cites:* BASE-AGENT-005, BASE-AUDIT-001, BASE-DATA-001, BASE-INPUT-001, BASE-MAIL-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Existing Google Workspace/Auth0 exports and authorized custom-directory/database migrations preserve reviewed identifiers and profile history. A constrained migration bridge may verify an eligible worker’s old password at their first successful sign-in, then enroll them into Auth under employer policy and retire that bridge after cutover. Secrets never enter agent context or logs, failed old authentication grants nothing, and unsupported password hashes/factors are explicitly reset or reenrolled rather than fabricated. This is workforce migration compatibility, not a separate consumer identity product. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

**Acceptance.**
1. Import Google and Auth0 records, migrate one eligible legacy worker at first login through the real bridge, and compare downstream subject mapping before/after.
2. Refuse a wrong password, email collision and disabled worker; interrupt migration and prove an idempotent outcome and a cleanly disabled bridge.

#### AUTH-MIGRATION-003 — Cutover enrollment campaign

*Tier:* Core · *From:* AUTH-MIGRATION-003 · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Incumbent passwords and factor enrollments cannot be exported, so switching from Okta, Entra ID or JumpCloud includes an enrollment campaign that gets every employee enrolled in Auth before cutover without help desk. The administrator federates the incumbent as an upstream for the campaign (AUTH-FEDERATION-001: Okta, Entra ID or JumpCloud over OIDC or SAML) and sets a cohort, an enrollment deadline and a cutover date. Each employee is notified at their work address and in Slack or Teams (AUTH-FOLLOWUP-001), signs in to Auth with their current incumbent sign-in, including its MFA, as proof of identity, and enrolls a passkey and the Auth authenticator, plus a password where AUTH-ENROLLMENT-001 enables it. Auth binds the incumbent's immutable subject to the person AUTH-MIGRATION-001 staged, never by email match alone. Where the incumbent's API allows verifying a password (Okta's Authentication API), an optional bridge checks the employee's current password at their campaign sign-in and keeps it as their Auth password under AUTH-PASSWORD-001, so VPN users keep working at cutover. A campaign dashboard shows each person as enrolled, pending, overdue or exempt, with factor types, per-cohort counts and the number left before cutover. Reminders escalate to the manager 3 days before the deadline and to the administrator at the deadline, and the straggler list exports. Federated campaign proof is accepted only during the campaign window and only for staged people. After cutover the federation is removed, and anyone not enrolled uses a temporary access pass (AUTH-TAP-001). Campaign proof never confers administrator authority; administrators enroll under AUTH-IDENTITY-001. This policy does not replace any enrollment, channel, escalation, export, cutover or provider acceptance requirement. Related outcomes: AUTH-MIGRATION-004.

**Acceptance.**
1. In an authorized Okta test tenant with 20 staged employees, run a campaign: all 20 enroll through Okta-federated proof with no help-desk action while the dashboard counts down.
2. Leave 3 unenrolled and see them named as overdue with manager reminders and in the export.
3. Refuse a person whose email matches but whose Okta subject differs, an unstaged person, proof after the campaign window and campaign proof for an administrator.
4. Bridge one employee's Okta password and sign in with it at RADIUS after cutover.
5. Repeat the enrollment proof with Entra ID and JumpCloud as upstreams.

#### AUTH-MIGRATION-004 — Campaign manager reminder custody

*Tier:* Core · *From:* AUTH-MIGRATION-003 · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** The employer owner may select a cohort manager. Sending enrollment reminders to that manager needs a separate audited policy write by the employer owner or published manage-follow-up holder, with administrator proof. Campaign creation, directory manager fields and previous consent confer no new outbound consent. Each notice contains only name, work address and enrollment deadline; dispatch rechecks current manager membership, state and duty, and escalates on failure. Notices confer no identity authority; source completion, cancellation and expiry stop dispatch.

**Acceptance.**
1. The owner may explicitly select a cohort manager.
2. Sending that manager enrollment reminders requires separate audited outbound consent in a policy write by the organization owner or a role holding the published manage-follow-up permission, with hardware passkey and fresh local email proof rechecked at commit.
3. Campaign creation, a directory manager field and existing reminder consent do not grant this consent.
4. Each manager notice contains only the affected employee’s name, work address and enrollment deadline.
5. Dispatch rechecks the selected manager’s current organization membership, state and cohort duty; a failed recheck follows the existing approved escalation rule.
6. The notice grants no enrollment, recovery, approval or administrator authority and contains no credential or proof-bypassing link.
7. Consent, dispatch outcomes and stopping history remain subject to AUTH-FOLLOWUP-001, AUTH-FOLLOWUP-002, AUTH-RETENTION-001 and AUTH-ERASURE-001.
8. Completion, cancellation or expired campaign authority stops reminders.

#### AUTH-DEVELOPER-001 — Working integration SDKs and admin API

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-INPUT-001, BASE-INSTALL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Versioned quickstarts and SDKs for Next.js/React, Node.js, Python and Hono cover real web/server sign-in, callback validation, sessions, logout, claims/API permission checks and scoped administration through AUTH-ADMINAPI-001 credentials. Embeddable user/organization components call the same authorized APIs. Examples declare exact supported profiles, errors, key-cache/rotation behavior and deployment steps; sandbox/test organizations use isolated real protocol flows and cannot mint production authority. App owners can extend the catalog without depending on RER.

**Acceptance.**
1. Build and run each framework quickstart against a fresh Auth install; enroll an employee, sign in, verify a protected API, switch an authorized organization, revoke access and observe logout.
2. Follow the docs from an empty app and diagnose a deliberately wrong redirect without hand-editing SDK internals.

#### AUTH-ADMINAPI-001 — Admin API credentials for automation

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-ROLE-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** An administrator under the AUTH-IDENTITY-001 gate creates an admin service app: an OAuth 2.0 client-credentials client authenticating with `private_key_jwt` (a client secret is not offered for admin scopes), granted least-privilege admin scopes (for example `people.read`, `people.manage`, `groups.manage`, `apps.manage`, `assignments.manage`, `policies.manage`, `idps.manage`, `domains.read`, `logs.read`), optionally narrowed to an AUTH-ROLES-001 resource set. Each has a named accountable human owner, an expiry of at most 12 months, an optional source-IP allow-list and a published purpose; access tokens last at most 15 minutes. Exclusions are stated per scope and enforced: no admin scope can assign or change administrator roles or resource sets, change any person's factors or recovery, approve recovery, manage signing keys, create or change admin service apps, change emergency accounts, or widen its own policy. Every call is audited with the service app, owner, scope and result; the owner's demotion, suspension or departure suspends the app until a new owner is assigned. The full admin API is a documented, versioned REST API with OpenAPI description, pagination, ETags for optimistic concurrency and rate-limit headers. Under the held company policy, preparer keys (AUTH-ADMIN-001) file proposals and are distinct from these credentials.

**Acceptance.**
1. Create a service app with `groups.manage` and `assignments.manage` from an allowed IP, call the API to create a group and assign an app; call a policy endpoint and from another IP and be refused; attempt each excluded action with every scope and be refused.
2. Expire the app, suspend its owner, and replay a stale ETag; each is refused or suspended as stated, and the audit shows every call.

#### AUTH-TERRAFORM-001 — Terraform provider

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-ROLE-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-3, R-4

**Requirement.** A Terraform provider published on the public Terraform Registry (and usable with OpenTofu) manages Auth's people, groups, group rules, apps (SAML, OIDC, password-based) and their assignments, attribute mappings, policies, identity providers, domains and automations, authenticating with AUTH-ADMINAPI-001 credentials. It supports `plan`, `apply`, `import` of existing objects and drift detection, with idempotent applies and documented resource schemas; it can never do what its credential's scopes exclude, so administrator roles, resource sets and their holders, factors, recovery and signing keys stay with interactive administrators.

**Acceptance.**
1. Against a fresh install, `terraform plan` and `terraform apply` create a group, an app assignment and a policy; a second plan shows no changes; a change made in the UI appears as drift on the next plan; `terraform import` adopts an existing app.
2. A resource needing a scope outside the credential's grant fails at apply with a refused, audited call and no partial change to that resource.

#### AUTH-MOBILE-001 — Native employee and administrator access

*Tier:* Core · *Cites:* BASE-ACCESSIBILITY-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-3, R-4

**Requirement.** Auth delivers iOS and Android employee app-launcher/account experiences and Expo/native iOS/Android SDKs using system-browser authorization, PKCE, universal/app links and OS-protected credential storage. Employees sign in with passkeys, use the app as their push and TOTP authenticator (AUTH-AUTHENTICATOR-001), launch company apps, view/revoke devices/grants and recover access; managers and app owners decide requests under AUTH-DECISIONS-001; authorized administrators can review urgent access/recovery requests with the same hardware and local email gates. Responsive web covers the same essential flows. Employers deploy the app through Microsoft Intune, Jamf Pro, Kandji or Android Enterprise with managed app configuration (AppConfig: Auth tenant URL, enrollment and policy), so a managed phone opens already pointed at the employer. Lost phones, offline state and push notifications never imply approved access.

**Acceptance.**
1. On real iOS and Android builds plus Expo SDK clients, deploy the app with managed configuration through Intune and Android Enterprise, enroll a passkey, return through a verified link, launch an assigned app, approve an authorized request and revoke the lost device.
2. Refuse a hijacked callback and offline approval; exercise web equivalents at 1440 and 390.

#### AUTH-EVENTS-001 — Reliable lifecycle events and webhooks

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Authorized subscribers receive versioned signed events for people, memberships, assignments, policy, recovery and provisioning outcomes. Delivery uses stable IDs, bounded retries/backoff, secret rotation, replay protection and per-subscriber outcomes; consumers can resume from a cursor and reconcile missed events through the API. Destinations are validated against SSRF/private-network abuse. A delivery acknowledgment proves receipt only, and uncertain writes/events do not falsely close downstream access obligations.

**Acceptance.**
1. Subscribe a real app endpoint through admin/API, perform a joiner/mover/leaver, rotate signing material and recover after 429, timeout and outage.
2. Replay an event and request a historical cursor; verify ordered/versioned reconstruction without duplicate grants or missing unresolved work.

#### AUTH-FOLLOWUP-001 — Follow-through until access is resolved

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1, D-4 · *Register:* R-1, R-2

**Requirement.** Enrollment, recovery, app setup, provisioning and revocation each keep an owner, next due action, employer timezone and business calendar, deadline, and stop/escalation rule. Email reminders go to approved recipients. Connector denial, missing approval and uncertain remote effect stay visible across restart, with actionable redacted errors. Satisfied, cancelled or expired authority stops reminders. A sent alert or a successful tool call alone never means the employee can sign in or has lost access. Every saved policy, including one saved before the escalation-recipient write check, escalates a failed recipient recheck to an approved owner or administrator. AUTH-TIMING-001's 15-minute unverified-downstream escalation is raised here. Reminder policy follows D-4.

**Acceptance.**
1. Leave an invitation, a recovery awaiting a distinct administrator's approval, and a failed deprovision unresolved across a weekend/DST change and a process restart.
2. Observe due actions, reminders and escalation, including for a legacy policy with no escalation recipient.
3. Complete or cancel each through its normal door, and verify reminders cease while the complete history remains.

#### AUTH-FOLLOWUP-002 — Role-derived recipients, manage-follow-up authority and early send

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-INSTALL-001, BASE-ROLE-001 · *Rules:* D-1, D-4 · *Register:* R-1, R-2, R-4

**Requirement.** The policy write is open to the owner or a role holding the published 'manage follow-up' permission. Installation roles have none in an isolated organization. Recipients are roles, never addresses: the employee for their own enrollment or recovery, and the help desk holding the case, with escalation to a named owner or administrator. Each recipient is rechecked at dispatch. Anyone currently holding an obligation may send its due reminder early, only to recipients the policy allows.

**Acceptance.**
1. A custom role with 'manage follow-up' saves the policy.
2. An installation role is refused.
3. The employee receives their own enrollment and recovery reminders, and the holding help desk receives its case reminders.
4. A help-desk holder who loses the role escalates.
5. A holder's early send reaches only allowed recipients, and a non-holder is refused.
6. All of this runs at 1440 and 390.

#### AUTH-FOLLOWUP-003 — Access-request, review and stale-source obligations

*Tier:* Core · *Cites:* BASE-AUDIT-001, BASE-INPUT-001 · *Rules:* D-1, D-4 · *Register:* R-1, R-2

**Requirement.** Access requests (AUTH-REQUESTS-001), review items (AUTH-REVIEWS-001) and stale directory or HR sources (AUTH-SCIM-002, AUTH-HRIS-001/002) become obligations under the AUTH-FOLLOWUP-001 engine. Reminders go to the decider AUTH-DECISIONS-001 names. Missing approval and stale source stay visible across restart. source doors are native pending access requests, open native review items and registered HR file feeds. Requests and review items resolve the current decider at dispatch; follow-up ownership never grants decision authority. Stale HR delivery reminders require the separately selected source-owner duty in an explicit audited policy write; registering a feed and existing reviewer consent grant no additional outbound consent. The source owner must retain current administrator authority and the registered version. Source completion, cancellation or expired request authority stops reminders without deciding access. Future source doors in AUTH-SCIM-002 and AUTH-HRIS-001, and additional request or review doors in AUTH-REQUESTS-001 and AUTH-REVIEWS-001, inherit the same adapter, current-authority, consent, stop and retained-history obligations before shipping.

**Acceptance.**
1. Leave an access approval, an overdue review item and a stale source unresolved across a weekend/DST change and a restart.
2. Observe that decider reminders and escalation happen.
3. Decide, cancel or refresh each through its normal door, and verify reminders cease while the history remains.

#### AUTH-FOLLOWUP-004 — Slack, Teams and Oncall follow-up channels

*Tier:* Core · *Cites:* BASE-INPUT-001 · *Rules:* D-1, D-4 · *Register:* R-1, R-2, R-4

**Requirement.** Reminders the policy allows are also delivered through Slack and Microsoft Teams, where recipients decide under AUTH-CHAT-001. Oncall can receive security escalation. Chat or Oncall acknowledgment never counts as access success.

**Acceptance.**
1. Through authorized Slack, Teams and Oncall test workspaces, deliver a reminder, decide a request from Slack and from Teams, and raise a security escalation to Oncall.
2. A recipient whose binding or authority has lapsed receives nothing and the reminder escalates.
3. Reminders contain no credentials and no links that act without their door's own proof.

#### AUTH-DELIVERY-001 — Email and SMS delivery operations

*Tier:* Core · *Cites:* BASE-BACKUP-001, BASE-DATA-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Employers use configured Base mail adapters or Amazon SES with verified sending identities for invitations, verification, recovery and security notices; Twilio supplies optional SMS verification. Private credentials, scoped templates, bounce/suppression handling, rate limits and durable delivery/uncertainty outcomes protect these messages. Admin diagnostics distinguish queued, provider-accepted and delivered/bounced evidence without exposing a usable link/token; local outbox remains private and sends no external mail. Provider failure does not grant identity proof. Recipient suppression is a minimal private installation-local fence with the actual provider outcome, excluded from portable archives, with no automatic expiry or self-service bypass. Only explicitly authorized reviewed correction changes it; enrollment, recovery and historical-message restore do not. After restore or reconnect, sending remains held until current provider suppressions or equivalent current local fences are reconciled. (RL-102).

**Acceptance.**
1. Configure SES and Twilio in authorized test accounts, enroll/recover a worker and observe accepted, bounced, throttled and unavailable outcomes.
2. Prove tokens/credentials absent from logs/exports and a notification failure leaves the original access obligation unresolved.
3. Recipient suppression is a minimal private installation-local fence with the actual provider outcome, excluded from portable archives, with no automatic expiry or self-service bypass. Only explicitly authorized reviewed correction changes it; enrollment, recovery and historical-message restore do not. After restore or reconnect, sending remains held until current provider suppressions or equivalent current local fences are reconciled.

#### AUTH-OPS-001 — Operate a company identity service

*Tier:* Core · *Cites:* BASE-BACKUP-001, BASE-DATA-001, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4, R-6

**Requirement.** An install RER Managed provisions holds RER link-approval trust (AUTH-RER-TRUST-001), and that provisioning belongs to RER Managed, not to this seed (the installation boundary); the operations page names who operates each installation, and the objectives below bind whichever operator runs it. Owners can deploy, upgrade, monitor, back up and recover a US-first identity installation with explicit issuer/key custody, US data-region choices, maintenance/incident runbooks, capacity and recoverable connector state. The published objectives for the supported production deployment (Cloudflare Workers with D1) are: 99.99% monthly availability of sign-in, token, SAML, WS-Federation, RADIUS and launcher endpoints and 99.9% of the admin console; recovery time objective 1 hour and recovery point objective 5 minutes for a regional failure or a restore from backup; p95 server-side latency at a US edge of at most 300 ms for an authorization or SAML response and at most 200 ms for a token or UserInfo response, excluding the person's own interaction and upstream/push wait; and RADIUS responses within 2 seconds plus the person's push response. Measurements over each month are published on the operations page with the method used. Uptime monitors sign-in/provisioning health and Oncall receives actionable incidents. Administrators see active-worker, app, SMS/email and connector usage with USD price/cost rules and exportable forecasts before enabling billable providers; estimates distinguish measured usage and provider charges. No certification, service level or hosted capacity is claimed without measurement.

**Acceptance.**
1. Deploy to the supported production host, perform a rolling/key-certificate upgrade, fail a dependency, restore a backup and measure against each numeric objective: availability from synthetic sign-ins at one-minute intervals across a month, the restore's elapsed time against the 1-hour RTO and its newest recovered write against the 5-minute RPO, p95 authorization/SAML and token/UserInfo latency under a load of 50 sign-ins per second, and leaver processing against AUTH-TIMING-001.
2. Trigger Uptime/Oncall escalation and reconcile the USD usage forecast to actual provider usage without exposing secrets.

#### AUTH-RECOVERY-002 — Emergency continuity and recovery drills

*Tier:* Core · *Cites:* BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001, BASE-SIGNIN-002 · *Rules:* D-1 · *Register:* R-1, R-2

**Requirement.** Employers maintain separately protected emergency administrators, redundant factors/keys and documented issuer, upstream-outage, lost-factor and connector recovery paths. Scheduled drills prove those paths with scoped test identities, without bypassing the existing local email/hardware gates or turning an offline archive into active authority. High-risk recovery changes require independent approval, notify the affected employee/security owner and are cancelable where a delay applies; rotation after use is explicit. A drill reports failed and unmeasured steps.

**Acceptance.**
1. Drill lost phone/key, unavailable upstream, expired signing certificate and restoration of an owner installation through the public account/CLI doors.
2. Confirm ordinary workers cannot invoke emergency authority, cancellation wins against completion where applicable, all notices persist and used credentials cannot be replayed.

#### AUTH-RECOVERY-003 — Same-day help-desk recovery for employees

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-BACKUP-001, BASE-INPUT-001, BASE-MAIL-001, BASE-ROLE-001, BASE-SIGNIN-002 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** A non-privileged employee who has lost every factor and holds no recovery code is restored the same business day through help desk. A help-desk holder whose AUTH-ROLES-001 scope covers the employee opens a recovery case and records a verification step the employer's policy accepts: attestation by the employee's manager from the manager's own signed-in session, a remaining enrolled factor (push or TOTP), or an ID-document and selfie check through Persona or CLEAR, whose result (not the document) is stored. On a passed check, help desk resets the employee's factors and issues a single-use enrollment link, a temporary access pass (AUTH-TAP-001) or a desktop recovery PIN (AUTH-DESKTOP-001), valid for at most 1 hour and bound to the case; all the employee's sessions and devices are revoked, and the employee and their manager are notified on every enrolled channel and by email. There is no 72-hour wait for these employees. The path is refused for anyone holding an administrator or privileged role (AUTH-DECISIONS-001), who stay on AUTH-IDENTITY-001's approval, delay or emergency rules, and for anyone outside the help-desk holder's scope. Help desk's own action is under the administrator gate, and every case records who verified what, how and when.

**Acceptance.**
1. As help desk scoped to the employee's group, restore a non-admin employee with no recovery code through manager attestation, and another through a Persona check in an authorized test account, each from case opening to a newly enrolled passkey in under 1 hour.
2. Refuse the path for an administrator, for an employee outside scope, without a recorded verification, and on reuse or after an hour of the enrollment link; see the revoked sessions and every notice.

### Privacy, custody and Base replacements

#### AUTH-ERASURE-001 — Authorized erasure with retained accountability

*Tier:* Core · *From:* AUTH-ERASURE-001 · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-BACKUP-001, BASE-DATA-001, BASE-DATA-003, BASE-DATA-006, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Owners erase under explicit retention/legal-hold policy, after an exact preview tied to the current revision and counts and a confirmation rechecked at commit, with hardware passkey and fresh local email proof (AUTH-IDENTITY-001); erasure is never scheduled and no erase permission is delegable. An organization owner erases people, app connections and memberships in their organization; the installation owner erases or resets organizations and the installation, and erases a person's installation identity under AUTH-ERASURE-002. Erasure removes profiles, factor keys, invitations, grants, staged/import copies, connector credentials and dependent personal data across one shared store registry used by preview, erasure, export and restore, which refuses any store it does not know. It cuts off access at once (sessions, tokens, back-channel logout, connector deactivation) without further consent; deleting data held by a downstream app needs the owner's consent per destination, and no remote deletion is automatic. Unfinished remote work is reported separately and keeps only the minimum destination identifier it needs, sealed, until it completes or is explicitly abandoned. A legal hold naming the subject refuses the whole erasure (target: erase the unheld remainder and keep the held part restricted behind audited access, erased later only on a fresh preview and reconfirmation). Restore cannot resurrect erased records when given the later erasure journal (AUTH-TRANSFER-002). AUTH-RETENTION-001 expiry is not erasure and is unaffected. Already delivered messages, exported archives, external audit sinks and independently held provider data have named limits, owners and partner deletion instructions and are never reported as erased. Suspension alone is not erasure; the last owner requires a protected reset/transfer path. Related outcomes: AUTH-ERASURE-004. Auth retains a per-store completion receipt, verified tamper evidence on anonymous decision commitments and a portability fence for the later erasure journal.

**Acceptance.**
1. Erase a worker with multiple factors, imports, agent grants and SaaS access through the owner door; query/export all stores, inspect receipt and anonymized audit, and attempt restore of a pre-erasure archive with the later journal.
2. Keep a blocked remote deletion visible, test legal hold and last-owner protection.

#### AUTH-ERASURE-004 — Protected organization reset and pending-work custody

*Tier:* Core · *From:* AUTH-ERASURE-001 · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-BACKUP-001, BASE-DATA-001, BASE-DATA-003, BASE-DATA-006, BASE-INPUT-001, BASE-INSTALL-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** A protected organization reset, which removes the organization's issuer and its last owner and sessions, leaves only anonymous receipts and outcomes (no name, email, profile, directory, destination identifier, signing key or credential) and sealed remote work pending at reset, sealed to the installation and never shown or exported in clear; both pass to installation owner custody alone. No other caller authority from the organization survives: its owners, administrators, members, sessions, service apps, preparer keys and invitations end, and the erased issuer answers not found at every door. The installation owner sees each item's app, operation, state and outcome, never the person or destination identifier, and may retry or abandon it under AUTH-IDENTITY-001 proof. A retry performs only work already authorized: revocation as recorded, and deletion only where the organization's owner consented per destination before the reset. Because the organization's connector credential is destroyed, a retry needs a new connection the installation owner explicitly authorizes for that destination, verified to reach the same remote tenant, limited to that work and destroyed with it; without one the item stays blocked with partner deletion instructions. Completion or abandonment destroys the sealed identifier and keeps an anonymous outcome. Every view, retry, connection and abandonment is recorded in the installation audit.

**Acceptance.**
1. Reset an organization and prove its issuer and all former caller authority end, leaving only anonymous receipts/outcomes and sealed pending work in installation-owner custody.
2. Inspect each pending item as installation owner: app, operation, state and outcome are visible; the person and destination identifier are absent from UI and exports.
3. Retry only previously authorized work through a fresh, explicitly authorized connection bound to the same remote tenant; without it retain the blocked item and deletion instructions.
4. Complete or abandon the item and prove the sealed identifier and replacement credential are destroyed while the anonymous outcome and installation audit remain.
5. Reset a local installation through its protected last-owner door.

#### AUTH-ERASURE-002 — Per-person erasure across separate organization identities

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-INSTALL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** A person's installation identity and each membership are separate identities (AUTH-TENANCY-002), each erased by its own owner. A person may link a membership only while holding independently proved live sessions in both, confirming with a passkey in each. The link is a random per-pair handle, visible only to that person and in their own export, and the person may remove it. Installation-identity erasure erases installation-held data and never waits on, enumerates or matches memberships. Each linked membership receives an opaque release notice (handle and erasure reference only). The notice becomes an AUTH-FOLLOWUP-001 obligation for that employer's owner to erase the membership under AUTH-ERASURE-001 or record the hold preventing it. The installation owner learns neither which employers were notified nor how many. Unlinked or unproved memberships are never searched, seen, erased or reported erased. Every organization's sign-in names how to ask its owner for erasure. The person's receipt lists each notice's state and says: "Auth erased your installation identity. Memberships you did not link are held separately by those employers; Auth did not see or erase them. Ask each employer to erase them." Organization erasure destroys its handles. A person requests their own receipt key from their own passkey session; it is shown once, stored as a digest, sent only in a request body and never logged. It reads only their receipt, not sign-in or membership inventory. The key expires after thirteen months; expiry or surrender clears its payload and retains anonymous facts. Each receipt notice contains only its random handle, erasure reference and state. Possession of the full body-posted key plus explicit confirmation surrenders only that receipt capability, even after sign-in ends. Digest comparison reveals no account or membership lookup, clears the payload under receipt policy and makes replay inert with a revoked result; no URL token or session is created. (RL-103).

**Acceptance.**
1. Give one person isolated memberships A, B and C.
2. Link A from proved sessions, refuse a link to B from a root session alone, and leave C unlinked.
3. No administrator sees the link in UI, admin API or export.
4. Installation-identity erasure commits without a membership check; only A gets a handle-only obligation; the root preview and receipt name no employer or count; the person's receipt shows A's notice and the unlinked sentence.
5. Erasing an organization's creator leaves the organization.
6. Possession of the full body-posted key plus explicit confirmation surrenders only that receipt capability, even after sign-in ends. Digest comparison reveals no account or membership lookup, clears the payload under receipt policy and makes replay inert with a revoked result; no URL token or session is created.

#### AUTH-ERASURE-003 — Erasure revokes everything

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AUDIT-001, BASE-BACKUP-001, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Erasing an account revokes at once every session, API key, passkey, OAuth client token and refresh token, and delegation the account holds or issued. The audit row keeps only an opaque id and the revocation counts by credential kind, never a name, email or other personal data. Exports and backups never restore an erased account's credentials: a restore drops them and writes the same opaque-id audit row. A failed revocation step aborts the erasure with nothing half-done. The receipt rules of AUTH-ERASURE-002 (digest-only, no employer or count) are unchanged.

**Acceptance.**
1. Erase an account holding sessions, API keys, passkeys, OAuth client tokens, refresh tokens and delegations it holds or issued; each authority is revoked immediately.
2. Read the audit record: only the opaque identifier and revocation counts by credential kind remain, without name, email or other personal data.
3. Restore a pre-erasure export or backup with the later journal; erased credentials stay absent and the same opaque audit is written.
4. Fail one revocation step and observe atomic refusal with no partial erasure. Receipt custody remains governed by AUTH-ERASURE-002.

#### AUTH-RETENTION-001 — Explicit retention and secret custody

*Tier:* Core · *From:* AUTH-RETENTION-001 · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-DATA-002, BASE-DATA-003, BASE-DATA-006, BASE-INPUT-001, BASE-INSTALL-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** The product publishes employer-controlled retention for profiles, source snapshots, authentication/decision history, provisioning obligations, audit, model traces and erasure receipts, including retention holds and US storage/processor choices. Out of the box, sign-in, administration and decision audit is kept for 13 months, configurable up to 7 years; the employer can never set it below 90 days, and no event is deleted while an open access review, access request, investigation or legal hold refers to its period. Before any scheduled deletion, the employer can export what will be deleted. Expiry of short-lived challenge/rate-limit/token state cannot delete the only evidence of an unfinished obligation or improve a completion report. Signing and connector rotation preserve Auth’s token and archive exclusions. Supersedes `BASE-DATA-002` under RL-106. Eight retained classes use thirteen calendar months, a ninety-day floor and seven-calendar-year maximum, after explicit audited confirmation; pending confirmation is published. Scheduled batches preserve review, request, investigation, legal and unfinished-period holds, expose the exact seven-day pre-delete export set, recheck holds before each batch of at most 200 rows and retain authenticated anonymous expiry commitments. Terminated identity/state retains only minimal non-identifying replay and obligation control, with no permanent personal profile or authority revival. (RL-106). Related outcomes: AUTH-RETENTION-002. Encryption, scoped access and rotation protect Auth signing and connector secrets at rest and in transit; raw credentials and Auth authentication links never enter model context, ordinary logs, public assets or portable archives.

**Acceptance.**
1. On a default installation, confirm 13-month audit retention; try to set it to 30 days and be refused; open a review over a period and see its events kept past their expiry.
2. Populate every retained class, age it across each configured expiry, restart and inspect the public history/export doors: transient secrets expire, retained history and unresolved obligations remain, held data is preserved and scheduled deletion produces accountable results.
3. Rotate a connector/signing key and verify secrets absent from logs/assets/archive.
4. Expiry uses eight configurable classes with a 13-calendar-month default, a 90-day floor and seven-calendar-year maximum.
5. Each exact deletion set has a seven-day export window and at most 200 rows, with live hold/state rechecks and authenticated anonymous expiry commitments preserving erasure audit verification.
6. Storage/processor selection is disclosed as employer deployment configuration, without claiming verified residency.
7. Eight retained classes use thirteen calendar months, a ninety-day floor and seven-calendar-year maximum, after explicit audited confirmation; pending confirmation is published.
8. Scheduled batches preserve review, request, investigation, legal and unfinished-period holds, expose the exact seven-day pre-delete export set, recheck holds before each batch of at most 200 rows and retain authenticated anonymous expiry commitments.

#### AUTH-RETENTION-002 — Non-identifying terminated-profile expiry

*Tier:* Core · *From:* AUTH-RETENTION-001 · *Cites:* BASE-AUDIT-001, BASE-DATA-001, BASE-DATA-002, BASE-DATA-003, BASE-DATA-006, BASE-INPUT-001, BASE-INSTALL-001, BASE-SECRET-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Under RL-106, expiry of a terminated profile follows AUTH-RETENTION-001’s confirmed policy and hold checks. Only minimal non-identifying replay and obligation control may remain; it cannot become a permanent personal profile or revive authority.

**Acceptance.**
1. Terminated identity/state retains only minimal non-identifying replay and obligation control, with no permanent personal profile or authority revival.

#### AUTH-TRANSFER-002 — Complete workforce portability

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-BACKUP-001, BASE-DATA-001, BASE-DATA-003, BASE-INPUT-001, BASE-INSTALL-001 · *Rules:* D-1 · *Register:* R-1, R-2, R-4

**Requirement.** Beyond AUTH-TRANSFER-001’s current identity archive, versioned export includes organizations, workforce attributes, groups, source/subject maps, app recipes/assignments, policies, access requests/reviews, lifecycle obligations/outcomes, delegated-grant definitions, audit and erasure journals. Import previews validation/conflicts and restores inactive into an empty authorized destination; no app send, provisioning write, trusted agent or session starts until the receiving owner reauthorizes. Installation-local signing/wrapping keys, connector credentials, refresh/bearer tokens and passkey private material never travel. Same-host public passkey/subject continuity and cross-host reenrollment/re-link limits are explicit. Reconnected notice sending follows AUTH-DELIVERY-001’s current-suppression reconciliation.

**Acceptance.**
1. Create a populated workforce installation, export/import/export through rer and compare every declared portable record.
2. Refuse corrupt/foreign/unknown schema and nonempty destination; restore with later erasure journal, confirm all jobs/grants are inactive, then reauthorize one connector and verify exactly its approved work resumes.

### Agent surface

**Specialist: identity steward.** It gets workers into the right apps, investigates broken sign-in and verifies access ends.

Inherits BASE-AGENT-001 to BASE-AGENT-013. The company’s policy decides every call.

**How Auth computes each class.**

- **standard.** Reversible internal identity notes, previews, preferences and redacted diagnostics; facts are item count and current organization.
- **external.** A notice, webhook, disclosure, export or provider change reaches outside the employer; facts are recipient count and known, new or public counterparty from trusted records, including exposure caused indirectly by a restored or changed assignment.
- **money.** A lifecycle step changes a paid license, seat or subscription cost; facts are amount, currency and provider counterparty from the saved license record.
- **commitment.** A certification, signed access decision or sign-off binds the employer and is relied on by others; facts are affected access items, counterparty and any recorded value.
- **accounts.** A provisioning or catalog step creates an identity, service account or paid resource at an outside provider; facts name provider and resource count.
- **gated.** The provider requires account consent, identity verification, personal terms or hosted card entry; facts identify provider and exact step, including a provider answer requiring a person.
- **access.** A change widens or narrows people, roles, groups, app assignments, devices or task grants; facts are affected people and direction, from current and proposed authority.
- **security.** A change handles credentials or changes factor rules, issuer trust, recovery, signing keys, protective settings or secret custody; facts identify the setting.
- **destructive.** Erasure, irreversible expiry, credential destruction or a provider deletion cannot be undone in Auth; facts identify item count and kind.
- **sensitive.** A call reads or changes regulated identity-verification documents, bank/card data supplied for a provider step or other regulated personal data; facts are record count and data kind, excluding ordinary directory fields alone.
- **live.** Publishing a running issuer, hook, connector, federation or gateway configuration changes service behavior; facts name the affected service.

| Tool | Does | Core clauses | Risk class | Today |
| --- | --- | --- | --- | --- |
| `auth.identity.inspect` | Inspect scoped identities and sign-in state | AUTH-PRIVACY-001, AUTH-IDENTITY-001, AUTH-BOUNDARY-001, AUTH-ENROLLMENT-001, AUTH-EXPERIENCE-001, AUTH-LOCALE-001, HTTP-001 | standard or sensitive | Not exposed as an Auth MCP tool |
| `auth.links.manage` | Configure app links and issuer trust | AUTH-RER-TRUST-001, AUTH-LINK-001 | access · security (+ external) | Not exposed as an Auth MCP tool |
| `auth.directory.manage` | Manage people, organizations, memberships and roles | AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-PROFILE-001 | standard or access (+ sensitive) | Not exposed as an Auth MCP tool |
| `auth.domains.manage` | Prove and configure employer domains | AUTH-DOMAINS-001 | security · access (+ gated) | Not exposed as an Auth MCP tool |
| `auth.credentials.manage` | Configure factor, password and temporary-pass policy | AUTH-PASSWORD-001, AUTH-PASSWORD-002, AUTH-TAP-001, AUTH-MFA-001, AUTH-POLICY-001, AUTH-ABUSE-001, AUTH-RISK-001 | security (+ access) | Not exposed as an Auth MCP tool |
| `auth.onboarding.manage` | Schedule prehire activation and contact custody | AUTH-ONBOARD-001, AUTH-ONBOARD-002 | access (+ external) (+ sensitive) | Not exposed as an Auth MCP tool |
| `auth.launcher.inspect` | Inspect launch choices, preferences and access explanations | AUTH-LAUNCHER-001 | standard | Not exposed as an Auth MCP tool |
| `auth.notifications.manage` | Configure notices, inspect delivery and report a bound event | AUTH-NOTIFY-001, AUTH-DELIVERY-001, AUTH-NOTIFY-002 | standard or security (+ external) (+ destructive) | Not exposed as an Auth MCP tool |
| `auth.sessions.revoke` | End Auth and connected SaaS sessions | AUTH-LOGOUT-001, AUTH-LOGOUT-002 | access · security | Not exposed as an Auth MCP tool |
| `auth.apps.configure` | Configure SAML, OIDC, mappings, hooks and catalog recipes | AUTH-SAML-001, AUTH-OIDC-001, AUTH-MAPPING-001, AUTH-HOOKS-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-M365-001 | security (+ live) (+ accounts) (+ gated) | Not exposed as an Auth MCP tool |
| `auth.provisioning.run` | Provision and reconcile user, group and role changes | AUTH-SCIM-001, AUTH-SCIM-002, AUTH-SCIM-003, AUTH-SCIM-004 | access (+ accounts) (+ external) (+ destructive) | Not exposed as an Auth MCP tool |
| `auth.sources.manage` | Configure HR and reviewed file sources | AUTH-HRIS-001, AUTH-HRIS-002 | security (+ sensitive) (+ access) | Not exposed as an Auth MCP tool |
| `auth.lifecycle.run` | Plan and reconcile joiner, mover and leaver work | AUTH-LIFECYCLE-001, AUTH-TIMING-001, AUTH-WORKFLOWS-001 | standard or access (+ external) (+ money) (+ destructive) | Not exposed as an Auth MCP tool |
| `auth.federation.manage` | Configure upstream trust and activation | AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-SOCIAL-001 | security · access (+ accounts) (+ gated) | Not exposed as an Auth MCP tool |
| `auth.devices.manage` | Configure and revoke device trust and network/server grants | AUTH-DEVICE-001, AUTH-PRIVILEGED-001 | access · security | Not exposed as an Auth MCP tool |
| `auth.grants.manage` | Configure app/API authority and offline grant definitions | AUTH-GRANTS-001, AUTH-TOKENS-001, AUTH-TOKENS-002 | access · security | Not exposed as an Auth MCP tool |
| `auth.requests.decide` | Submit and decide exact access requests | AUTH-REQUESTS-001, AUTH-DECISIONS-001, AUTH-CHAT-001 | access (+ commitment) | Not exposed as an Auth MCP tool |
| `auth.reviews.manage` | Manage campaigns, delegate and record decisions | AUTH-REVIEWS-001 | access (+ commitment) | Not exposed as an Auth MCP tool |
| `auth.reports.read` | Investigate identity events and export reports | AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001 | standard (+ sensitive) (+ external) | Not exposed as an Auth MCP tool |
| `auth.migration.manage` | Preview migration, subjects, campaigns and manager notices | AUTH-MIGRATION-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004 | security · access (+ external) (+ sensitive) | Not exposed as an Auth MCP tool |
| `auth.automation.manage` | Manage scoped machine API and infrastructure definitions | AUTH-ADMINAPI-001, AUTH-TERRAFORM-001 | access · security (+ live) | Not exposed as an Auth MCP tool |
| `auth.events.manage` | Subscribe and replay lifecycle events | AUTH-EVENTS-001 | standard or external | Not exposed as an Auth MCP tool |
| `auth.followup.manage` | Manage obligations, recipient policy and dispatch | AUTH-FOLLOWUP-001, AUTH-FOLLOWUP-002, AUTH-FOLLOWUP-003, AUTH-FOLLOWUP-004 | standard (+ external) | Not exposed as an Auth MCP tool |
| `auth.recovery.manage` | Run bounded employee recovery and emergency drills | AUTH-RECOVERY-002, AUTH-RECOVERY-003 | security · access (+ sensitive) | Not exposed as an Auth MCP tool |
| `auth.erasure.run` | Preview and execute identity erasure and protected reset | AUTH-ERASURE-001, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-ERASURE-004 | destructive · access (+ security) | Not exposed as an Auth MCP tool |
| `auth.retention.manage` | Manage retention confirmation, holds, expiry and secret rotation | AUTH-RETENTION-001, AUTH-RETENTION-002 | security (+ destructive) | Not exposed as an Auth MCP tool |
| `auth.archives.manage` | Export, validate and restore Auth records | AUTH-TRANSFER-001, AUTH-TRANSFER-002 | security (+ destructive) (+ sensitive) | Not exposed as an Auth MCP tool |
| `auth.diagnostics.run` | Onboard apps, diagnose sign-in, repair and verify revocation | AUTH-ADMIN-001, AUTH-AGENT-001, AUTH-AGENT-002, AUTH-AGENT-003, AUTH-AGENT-004, AUTH-AGENT-005, AUTH-AGENT-006, AUTH-AGENT-007 | standard or access (+ security) (+ external) (+ sensitive) | Not exposed as an Auth MCP tool |

**Resources.** `auth://organizations/{organization}`, `auth://people/{person}`, `auth://apps/{app}`, `auth://requests/{request}`, `auth://reviews/{review}`, `auth://obligations/{obligation}`, `auth://tasks/{task}` and `auth://events/{event}`. **Events.** Person, membership, assignment, policy, recovery, provisioning, request, review and obligation changes; exact types follow the Auth lifecycle vocabulary, plus the Base policy and review events. **Prompts.** Onboard a worker (AUTH-LIFECYCLE-001), repair sign-in (AUTH-AGENT-002), review access (AUTH-REVIEWS-001), offboard and verify (AUTH-AGENT-005).

**Not tools, and why.**

- AUTH-MOVEIN-001: Reviewed move-in is the import door; admission and undo use its existing owner-authorized workflow.
- AUTH-HOST-001: An issuer host is an installation fact; moving it is a provider move, with owner relinking through the link tool.
- CMD-001: Installation and local emergency-file custody are installation facts and local CLI operations.
- AUTH-PROTOCOL-001: The client sign-in handshake is a person’s interactive screen and protocol integration; registered-client configuration is available through apps.configure.
- AUTH-AUTHENTICATOR-001: Factor enrollment, number matching and device-held TOTP are device-only or a person’s sign-in screen; factor policy and device revocation remain tools.
- AUTH-SWA-001: Password filling and browser force-install run in a device connector; app recipes and assignments remain tools.
- AUTH-LEGACY-001: Private-network protocol execution belongs to the deployed connector; connector policy and authority use devices.manage.
- AUTH-DESKTOP-001: OS login, offline cache and Platform SSO execute on the device; directory and device-policy changes remain tools.
- AUTH-GATEWAY-001: Tunnel and Kerberos/header forwarding execute in the private-network connector; app trust and policy remain tools.
- AUTH-DEVELOPER-001: SDK embedding is integration code and a person’s app screen, rather than an Auth business action.
- AUTH-MOBILE-001: Native sign-in and device-protected credential handling are device-only screens; app grants and revocation remain tools.
- AUTH-OPS-001: Deployment, region and hosted-capacity observations are installation facts.

**Limits.** Installation request, body, byte, expression-work and page-size capacities are documented in the existing protocol and operator guides. Business thresholds and provider-spend caps are the company’s policy.

**Handoffs.** Listen for approved Willow employment changes and Business task events; emit typed access obligations, completion, unresolved provider outcomes and evidence-ready events for Business, Oncall and Evidence. Untrusted source text does not route work.

#### SURFACE-001 — Identity-steward registry

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-001, BASE-AGENT-002, BASE-AGENT-006, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** The Auth tool registry covers the table’s identity-steward jobs and publishes its non-tool explanations.

**Acceptance.**
1. Compare the Auth registry’s Core-clause coverage and non-tool reasons with this table.
2. Run the Base conformance journey against Auth’s organization, worker, app and access fixtures.

#### SURFACE-002 — Auth classification: standard, external

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-006, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth computes standard, external from the facts defined above on its own records.

**Acceptance.**
1. Exercise standard on the applicable Auth tools; computed classes and facts equal the standard definition above, including every listed conditional route.
2. Exercise external on the applicable Auth tools; computed classes and facts equal the external definition above, including every listed conditional route.
3. Agent-supplied labels and imported record instructions do not change the classification.

#### SURFACE-003 — Auth classification: money, commitment

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-006, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth computes money, commitment from the facts defined above on its own records.

**Acceptance.**
1. Exercise money on the applicable Auth tools; computed classes and facts equal the money definition above, including every listed conditional route.
2. Exercise commitment on the applicable Auth tools; computed classes and facts equal the commitment definition above, including every listed conditional route.
3. Agent-supplied labels and imported record instructions do not change the classification.

#### SURFACE-004 — Auth classification: accounts, gated

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-006, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth computes accounts, gated from the facts defined above on its own records.

**Acceptance.**
1. Exercise accounts on the applicable Auth tools; computed classes and facts equal the accounts definition above, including every listed conditional route.
2. Exercise gated on the applicable Auth tools; computed classes and facts equal the gated definition above, including every listed conditional route.
3. Agent-supplied labels and imported record instructions do not change the classification.

#### SURFACE-005 — Auth classification: access, security

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-006, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth computes access, security from the facts defined above on its own records.

**Acceptance.**
1. Exercise access on the applicable Auth tools; computed classes and facts equal the access definition above, including every listed conditional route.
2. Exercise security on the applicable Auth tools; computed classes and facts equal the security definition above, including every listed conditional route.
3. Agent-supplied labels and imported record instructions do not change the classification.

#### SURFACE-006 — Auth classification: destructive, sensitive, live

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-006, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth computes destructive, sensitive, live from the facts defined above on its own records.

**Acceptance.**
1. Exercise destructive on the applicable Auth tools; computed classes and facts equal the destructive definition above, including every listed conditional route.
2. Exercise sensitive on the applicable Auth tools; computed classes and facts equal the sensitive definition above, including every listed conditional route.
3. Exercise live on the applicable Auth tools; computed classes and facts equal the live definition above, including every listed conditional route.
4. Agent-supplied labels and imported record instructions do not change the classification.

#### SURFACE-007 — Employer-scoped identity resources

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-003, BASE-AGENT-005 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Identity-steward resources represent independently proved Auth identities and employer-local access records.

**Acceptance.**
1. Read the listed resources as two Auth roles and reconcile their identity and membership views with the corresponding Auth screens.
2. Reset an employer and prove its former resource identifiers never attach to a new employer with the same name, domain or people.

#### SURFACE-008 — Administration and person-bound tasks

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-004, BASE-AGENT-005, BASE-AGENT-007, BASE-AGENT-008 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Native preparer and delegated-task profiles retain their Auth-specific custody while joining the company policy decision.

**Acceptance.**
1. Under the held company policy, file an exact suspension and link proposal, approve one and reject one through the person’s browser, then verify the exact Auth effects.
2. Under the all-autonomous company policy, run the same permitted access/security calls through the registry without manufacturing a person’s passkey approval or widening the caller’s own authority.
3. Keep native assignment and registered external-resource tasks distinct and exercise their exact employer, person, resource and deadline boundaries.

#### SURFACE-009 — Identity decisions in the agent overview

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-008, BASE-AGENT-009 · *Rules:* D-2 · *Register:* R-5

**Requirement.** The Auth identity-steward view reconciles worker access obligations and policy-decided calls with identity audit.

**Acceptance.**
1. For a fixture week, reconcile class and decision totals with Auth identity events and unresolved provisioning obligations.
2. After a policy-required person approval, show that person as approver and the agent as preparer on the affected identity decision.

#### SURFACE-010 — Identity event handoffs

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-010 · *Rules:* D-2 · *Register:* R-5

**Requirement.** The specialist follows the Auth lifecycle and obligation records named above.

**Acceptance.**
1. Change a worker’s employment state through the UI and follow the same typed event and record through the specialist handoff.
2. After an employer is erased, subscriptions and cursor replay expose no former employer identity or credential data.

#### SURFACE-011 — Identity capacity and recovery jobs

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-011, BASE-AGENT-012 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth capacity protects identity proof and connector workloads without fixing business volume.

**Acceptance.**
1. Exercise documented identity request/body limits and inspect the bounded refusal without an identity or provisioning effect.
2. Interrupt a long reconciliation and retrieve its job through the Auth tool registry; resume exactly its authorized obligation set.

#### SURFACE-012 — Identity-steward documentation

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** Auth’s generated agent guide teaches the specialist’s worker-to-app and access-closure jobs.

**Acceptance.**
1. From only the installation URL, discover every table tool, identity resource, prompt and computed-class fixture description.
2. Follow the documented worker-onboarding and sign-in-repair prompts through Auth’s public agent door.

#### SURFACE-013 — A seeded workforce week through MCP

*Tier:* Agent surface · *From:* new · *Cites:* BASE-AGENT-007, BASE-AGENT-009, BASE-AGENT-011, BASE-AGENT-013 · *Rules:* D-2 · *Register:* R-5

**Requirement.** A stranger identity steward completes a seeded week using Auth tools and the company policy.

**Acceptance.**
1. Under the all-autonomous policy, onboard a hire, repair a broken app callback, certify access and offboard a leaver across three official-schema provider peers; no call waits for a person or is refused by policy.
2. Under the held policy, repeat the week with standard reviewed and every other used class approved by the named test person; effects and approval counts reconcile to the policy and audit.
3. Hold a provider offline, restart and recover; the leaver remains locally denied and every remote outcome remains an open obligation until verified.
4. Before setup is answered, the first call reports the missing policy with the setup link and makes no effect.


## Push further

### Push further: agents serving workforce identity

#### AUTH-AGENT-001 — Agent-led SaaS onboarding

*Tier:* Core · *Cites:* BASE-AGENT-005, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** The company’s policy decides access and security calls. Calls carry the classes in the Agent surface; the company’s policy decides their execution. Under the held company policy, with an app owner’s scoped consent, an agent reads vendor metadata, current catalog recipes and employer group/role policy, prepares SAML/OIDC and SCIM settings, proposes mappings and configures approved changes through actual vendor APIs or guided setup. Credential custody follows BASE-SECRET-001; the Auth delta is the scoped vendor connection used for this task. Domain trust and activation carry security and live, new scopes and role elevation carry access, and irreversible changes carry destructive; the company’s policy decides these calls. Under the held company policy the named person approves the exact diff; observed test-user sign-in, role change and revocation determine readiness. The agent chases missing decisions and preserves rollback plus failed/unverified steps.

**Acceptance.**
1. Under the held company policy, ask the agent to onboard Slack and a generic SAML/SCIM SaaS, approve a scoped configuration diff, and run a real assigned employee through sign-in/provision/change/revoke.
2. Under the held company policy, inject malicious vendor text, stale settings and withheld domain consent; prove no unauthorized change and a blocked readiness state with an actionable next step.

#### AUTH-AGENT-002 — Diagnose and repair broken sign-in

*Tier:* Core · *Cites:* BASE-AGENT-005, BASE-INPUT-001, BASE-MAIL-001, BASE-SECRET-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** The company’s policy decides access and security calls. Calls carry the classes in the Agent surface; the company’s policy decides their execution. Under the held company policy, an agent correlates approved redacted protocol traces, metadata/key/certificate state, policy decisions, mail outcomes and deployment/configuration changes to explain why a named worker cannot use an app. It proposes the smallest justified repair, tests it with a scoped test identity and verifies sign-in plus logout. Changes to issuer, redirects, certificates, factors and protective policy carry security and live, and scope changes carry access; the company’s policy decides these calls. Under the held company policy, the responsible owner approves the exact repair and disabling controls is refused. Logs do not establish identity proof and raw secrets stay out of model context. Uncertain diagnosis stays uncertain with a next diagnostic action.

**Acceptance.**
1. Under the held company policy, break a callback, expire a certificate and fail recovery mail on separate app journeys; ask the agent to diagnose with source citations, approve a repair and verify end-to-end behavior.
2. Under the held company policy, deny approval and inject untrusted trace instructions, confirming no configuration or authority changes.

#### AUTH-AGENT-003 — Find orphaned and excessive access

*Tier:* Core · *Cites:* BASE-AGENT-005, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** The company’s policy decides access, security and destructive calls. Calls carry the classes in the Agent surface; the company’s policy decides their execution. Under the held company policy, an agent joins HR employment/source state, directory groups, app-side assignments, observed usage and review history to identify orphaned accounts, role drift, dormant privileges and risky recovery changes. Findings show provenance, freshness, exact people/apps affected and counterevidence; missing use data never proves no need. Least-privilege changes carry access, adding security or destructive for the affected operation; the company’s policy decides. Under the held company policy, policy owners approve the current-state diff; the agent verifies actual removal and the worker’s permitted tasks, with rollback and exceptions explicit.

**Acceptance.**
1. Under the held company policy, feed real approved connector data containing a departed worker’s remote account, an excessive role and an unused but required emergency grant.
2. Under the held company policy, review the cited findings, approve only the first two, and verify downstream state plus the worker’s allowed tasks; stale data or changed employment invalidates the proposal.

#### AUTH-AGENT-004 — Person-bound delegated agent identities

*Tier:* Core · *From:* AUTH-AGENT-004 · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** The company’s policy decides access and security calls. Calls carry the classes in the Agent surface; the company’s policy decides their execution. Under the held company policy, people can consent to an OAuth/MCP or external-API task identity bound to accountable person, employer, agent, purpose, target resource/API, exact scopes, duration and expiry. A visible consent screen explains the concrete effects, required independent approvals and revocation reach; tokens are short-lived, target-bound and separately attributable, never reusable human sessions or preparer keys. New scopes/purpose/targets and privilege escalation require new explicit consent; employer/person/agent suspension, task completion or expiry ends authority. Future task profiles inherit these consent, approval, audience, resource, proof and live-revocation obligations before shipping. The native profile in RL-8: The first native profile changes one existing direct app assignment through a DPoP-bound (RFC 9449), audience-restricted, one-use token valid for at most five minutes. Related outcomes: AUTH-AGENT-007.

**Acceptance.**
1. Under the held company policy, authorize an agent to update one approved app assignment until a fixed deadline, invoke its target API/MCP tool and inspect attribution.
2. Deny another person, purpose, resource, target, scope, expired grant and replay/substitution; show and revoke the active grant in My account and prove its next request is refused.
3. Under the held company policy, the native assignment profile requires owner registration of public keys and exact employee/app limits, fresh employee passkey consent, and a different legacy owner/admin's hardware/fresh-email passkey approval.
4. Under the held company policy, the employee, agent custodian and approver are distinct.
5. Immutable purpose, employer, person, agent, target API, resource, scope and deadline bind a single existing direct employee assignment change.
6. At most five-minute target-bound tokens also require one-use signed execution proof; live authority is rechecked at each door.
7. No arbitrary target, new assignment, administrator target, group change or document instruction is accepted.
8. Under the held company policy, my account revocation ends the next local request; completed changes are not undone and downstream sessions are not claimed revoked.

#### AUTH-AGENT-007 — Native delegated assignment task profile

*Tier:* Core · *From:* AUTH-AGENT-004 · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-AUDIT-001, BASE-INPUT-001, BASE-MAIL-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** Auth’s native profile issues a DPoP-bound, audience-restricted, one-use task token valid for at most five minutes for one existing direct app-assignment change. It binds person, agent and exact change. Under the held company policy for access and security, employee consent and independent authorized employer approval bind the exact task digest. AUTH-AGENT-004 owns grant creation and live authority; this part owns native token execution and the non-undo/reversal notice. The separately registered AUTH-AGENT-006 resource profile inherits these sender, audience, exact-task, proof, attribution and live-revocation boundaries.

**Acceptance.**
1. The token names the person, the agent (RFC 8693 `act`) and the exact change (RFC 9396).
2. Under the held company policy for access and security, it is issued only after the employee's passkey consent and approval by someone who holds that authority and is not the agent's custodian.
3. Revoking in My account stops future use, says it does not undo a completed change, and offers a request to reverse it.
4. The native profile remains restricted to its assignment target.

#### AUTH-AGENT-005 — Verify revocation everywhere

*Tier:* Core · *Cites:* BASE-ACCESS-002, BASE-AGENT-005, BASE-INPUT-001, BASE-ROLE-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** The company’s policy decides access and security calls. On any human or agent grant ending, an agent inventories every issued derivative credential, session and provisioned role across the affected apps, sends revocation operations as the company’s policy decides for access and security and checks remote state or a safe denied-access probe. The UI distinguishes locally denied, provider-acknowledged, verified revoked, unsupported and unknown. Expiry/offboarding cannot be reported fully complete until every in-scope effect is verified or a named accountable owner accepts a documented exception under policy; unsupported vendor APIs produce an actionable manual/partner step, never fabricated success.

**Acceptance.**
1. Revoke a delegated grant and offboard its accountable worker while one SaaS is offline and another offers no session-revocation API.
2. Prove immediate Auth denial, enumerate all derivatives, resume verification after restart/provider recovery and retain the manual exception until a person resolves it; every final claim must match a remote read/probe.

#### AUTH-AGENT-006 — External and MCP delegated task identities

*Tier:* Core · *Cites:* BASE-AGENT-004, BASE-AGENT-005, BASE-INPUT-001 · *Rules:* D-1, D-2 · *Register:* R-1, R-2, R-4

**Requirement.** The company’s policy decides access and security calls. Calls carry the classes in the Agent surface; the company’s policy decides their execution. Under the held company policy: Remote MCP servers and external APIs are registered with Auth as resources, each with an audience, published scopes and `authorization_details` types. An agent calls one for a person only with a task identity issued for that resource under AUTH-AGENT-004. A resource that is not registered receives no Auth task token.

**Acceptance.**
1. Register a test MCP server and an external API.
2. Authorize one tool and one operation for one person.
3. At each resource, deny an unregistered audience, another tool or operation, scope, person, replay and an expired grant.
4. Revoke in My account and prove the next call is refused.

## Field proof register

| ID | Proof | Clauses | State | Date | Receipt |
| --- | --- | --- | --- | --- | --- |
| R-1 | Human screen-reader pass | AUTH-HOST-001, AUTH-PRIVACY-001, AUTH-RER-TRUST-001, AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-BOUNDARY-001, AUTH-MOVEIN-001, AUTH-ADMIN-001, CMD-001, HTTP-001, AUTH-LINK-001, AUTH-LOGOUT-001, AUTH-TRANSFER-001, AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-DOMAINS-001, AUTH-PROFILE-001, AUTH-ENROLLMENT-001, AUTH-PASSWORD-001, AUTH-PASSWORD-002, AUTH-ONBOARD-001, AUTH-ONBOARD-002, AUTH-TAP-001, AUTH-EXPERIENCE-001, AUTH-LOCALE-001, AUTH-LAUNCHER-001, AUTH-SWA-001, AUTH-MFA-001, AUTH-AUTHENTICATOR-001, AUTH-POLICY-001, AUTH-ABUSE-001, AUTH-RISK-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-SAML-001, AUTH-OIDC-001, AUTH-MAPPING-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-M365-001, AUTH-SCIM-001, AUTH-SCIM-002, AUTH-SCIM-003, AUTH-SCIM-004, AUTH-HRIS-001, AUTH-HRIS-002, AUTH-LIFECYCLE-001, AUTH-TIMING-001, AUTH-WORKFLOWS-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-SOCIAL-001, AUTH-LEGACY-001, AUTH-DEVICE-001, AUTH-DESKTOP-001, AUTH-GATEWAY-001, AUTH-PRIVILEGED-001, AUTH-GRANTS-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-HOOKS-001, AUTH-REQUESTS-001, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-CHAT-001, AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-DEVELOPER-001, AUTH-ADMINAPI-001, AUTH-TERRAFORM-001, AUTH-MOBILE-001, AUTH-EVENTS-001, AUTH-FOLLOWUP-001, AUTH-FOLLOWUP-002, AUTH-FOLLOWUP-003, AUTH-FOLLOWUP-004, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-002, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002, AUTH-AGENT-001, AUTH-AGENT-002, AUTH-AGENT-003, AUTH-AGENT-004, AUTH-AGENT-007, AUTH-AGENT-005, AUTH-AGENT-006 | not run | | |
| R-2 | VPAT for supported surfaces | AUTH-HOST-001, AUTH-PRIVACY-001, AUTH-RER-TRUST-001, AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-BOUNDARY-001, AUTH-MOVEIN-001, AUTH-ADMIN-001, CMD-001, HTTP-001, AUTH-LINK-001, AUTH-LOGOUT-001, AUTH-TRANSFER-001, AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-DOMAINS-001, AUTH-PROFILE-001, AUTH-ENROLLMENT-001, AUTH-PASSWORD-001, AUTH-PASSWORD-002, AUTH-ONBOARD-001, AUTH-ONBOARD-002, AUTH-TAP-001, AUTH-EXPERIENCE-001, AUTH-LOCALE-001, AUTH-LAUNCHER-001, AUTH-SWA-001, AUTH-MFA-001, AUTH-AUTHENTICATOR-001, AUTH-POLICY-001, AUTH-ABUSE-001, AUTH-RISK-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-SAML-001, AUTH-OIDC-001, AUTH-MAPPING-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-M365-001, AUTH-SCIM-001, AUTH-SCIM-002, AUTH-SCIM-003, AUTH-SCIM-004, AUTH-HRIS-001, AUTH-HRIS-002, AUTH-LIFECYCLE-001, AUTH-TIMING-001, AUTH-WORKFLOWS-001, AUTH-FEDERATION-001, AUTH-FEDERATION-002, AUTH-SOCIAL-001, AUTH-LEGACY-001, AUTH-DEVICE-001, AUTH-DESKTOP-001, AUTH-GATEWAY-001, AUTH-PRIVILEGED-001, AUTH-GRANTS-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-HOOKS-001, AUTH-REQUESTS-001, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-CHAT-001, AUTH-AUDIT-001, AUTH-REPORTS-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-001, AUTH-MIGRATION-002, AUTH-MIGRATION-003, AUTH-MIGRATION-004, AUTH-DEVELOPER-001, AUTH-ADMINAPI-001, AUTH-TERRAFORM-001, AUTH-MOBILE-001, AUTH-EVENTS-001, AUTH-FOLLOWUP-001, AUTH-FOLLOWUP-002, AUTH-FOLLOWUP-003, AUTH-FOLLOWUP-004, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-002, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002, AUTH-AGENT-001, AUTH-AGENT-002, AUTH-AGENT-003, AUTH-AGENT-004, AUTH-AGENT-007, AUTH-AGENT-005, AUTH-AGENT-006 | not run | | |
| R-3 | Native iOS, Android, browser-extension and desktop store/registry approvals | AUTH-SWA-001, AUTH-AUTHENTICATOR-001, AUTH-DESKTOP-001, AUTH-TERRAFORM-001, AUTH-MOBILE-001 | not run | | |
| R-4 | Live vendor-tenant and production delivery qualification, including the named SaaS, directories, HR, device, chat, compliance, SES, Twilio and identity-verification providers | AUTH-HOST-001, AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-BOUNDARY-001, AUTH-MOVEIN-001, AUTH-ADMIN-001, AUTH-LOGOUT-001, AUTH-TRANSFER-001, AUTH-DIRECTORY-001, AUTH-TENANCY-001, AUTH-TENANCY-002, AUTH-ROLES-001, AUTH-DOMAINS-001, AUTH-PASSWORD-001, AUTH-PASSWORD-002, AUTH-ONBOARD-001, AUTH-ONBOARD-002, AUTH-TAP-001, AUTH-EXPERIENCE-001, AUTH-LAUNCHER-001, AUTH-SWA-001, AUTH-MFA-001, AUTH-AUTHENTICATOR-001, AUTH-POLICY-001, AUTH-ABUSE-001, AUTH-RISK-001, AUTH-NOTIFY-001, AUTH-NOTIFY-002, AUTH-LOGOUT-002, AUTH-SAML-001, AUTH-OIDC-001, AUTH-CATALOG-001, AUTH-CATALOG-002, AUTH-M365-001, AUTH-SCIM-001, AUTH-SCIM-002, AUTH-HRIS-001, AUTH-HRIS-002, AUTH-LIFECYCLE-001, AUTH-TIMING-001, AUTH-WORKFLOWS-001, AUTH-FEDERATION-002, AUTH-DEVICE-001, AUTH-DESKTOP-001, AUTH-GATEWAY-001, AUTH-PRIVILEGED-001, AUTH-GRANTS-001, AUTH-TOKENS-001, AUTH-TOKENS-002, AUTH-HOOKS-001, AUTH-REQUESTS-001, AUTH-REVIEWS-001, AUTH-DECISIONS-001, AUTH-CHAT-001, AUTH-AUDIT-001, AUTH-COMPLIANCE-001, AUTH-MIGRATION-001, AUTH-MIGRATION-003, AUTH-DEVELOPER-001, AUTH-TERRAFORM-001, AUTH-MOBILE-001, AUTH-EVENTS-001, AUTH-FOLLOWUP-002, AUTH-FOLLOWUP-004, AUTH-DELIVERY-001, AUTH-OPS-001, AUTH-RECOVERY-003, AUTH-ERASURE-001, AUTH-ERASURE-004, AUTH-ERASURE-002, AUTH-ERASURE-003, AUTH-RETENTION-001, AUTH-RETENTION-002, AUTH-TRANSFER-002, AUTH-AGENT-001, AUTH-AGENT-002, AUTH-AGENT-003, AUTH-AGENT-004, AUTH-AGENT-007, AUTH-AGENT-005, AUTH-AGENT-006 | not run | | |
| R-5 | Operation in Claude, ChatGPT, Codex and Copilot clients; real Okta or Entra enterprise authorization | SURFACE-001, SURFACE-002, SURFACE-003, SURFACE-004, SURFACE-005, SURFACE-006, SURFACE-007, SURFACE-008, SURFACE-009, SURFACE-010, SURFACE-011, SURFACE-012, SURFACE-013 | not run | | |
| R-6 | Elapsed hosted resilience and SLO observations | AUTH-OPS-001 | not run | | |

## Boundaries

Auth owns the complete workforce identity job, including the private connectors, native software, provider app registrations and security engineering needed for it. Required provider permissions, licensed editions, certificate rotation, privacy agreements and operating work are connector deliverables, never reasons to omit a category requirement. Every integration names direction, supported operations, required permission and the point at which access is actually verified.

- **HR and payroll:** [Willow](https://github.com/just-every/run-willow) owns employee records, onboarding HR work, time off and HR documents. Auth consumes approved changes and returns access outcomes. Rippling, Gusto, BambooHR, Workday, ADP Workforce Now, UKG Pro, Paylocity, Namely and SAP SuccessFactors remain supported sources, and any other HR system feeds Auth by scheduled file (AUTH-HRIS-002); Auth does not run payroll, file W-2/1099 or taxes, administer benefits or absorb that unowned category.
- **Endpoint and network operations:** Auth owns directory/device identity, sign-in to the computer itself (AUTH-DESKTOP-001), posture-based access, LDAP/RADIUS, gateway access to on-premises web apps (AUTH-GATEWAY-001), server and SSH access (AUTH-PRIVILEGED-001) and the connector/native software needed to deliver them. Intune, Jamf Pro, JumpCloud, AD and VPN/Wi-Fi vendors supply broad endpoint management, EDR, patch deployment and network transport; Auth integrates and reports their trust evidence and access limits.
- **Secrets and application ownership:** Connector/signing credentials are protected installation secrets. Auth stores and fills app sign-in credentials for password-based apps (AUTH-SWA-001); it is not a personal password manager or a general secrets-management product for infrastructure secrets and API keys, which stay with 1Password, AWS Secrets Manager or HashiCorp Vault. It supplies identity, app-role assignments, scoped API credentials and permission decisions; app owners enforce business-resource rules and retain ownership of app data. No group/claim implies authority until its target enforces it.
- **Compliance and operations:** [Evidence](https://github.com/just-every/run-evidence) owns audit readiness and auditor workspaces. Auth supplies exportable control evidence and is the identity-provider connection of Vanta, Drata, Secureframe and Thoropass (AUTH-COMPLIANCE-001), without claiming SOC 2 certification; those platforms and Evidence run the control tests. [Uptime](https://github.com/just-every/run-uptime) owns external monitoring and [Oncall](https://github.com/just-every/run-oncall) paging; Datadog/Splunk/Sentinel own log analytics. Auth still owns visible durable outcomes and operation of its identity service.
- **Delivery and external custody:** Amazon SES/Base mail and Twilio deliver messages; licensed SaaS providers enforce remote account/session controls. Provider acceptance is not human receipt, completed access or verified revocation. Where a vendor cannot revoke a session, the employer sees the residual risk, expiry and manual/partner step. No universal compatibility, uptime promise, region guarantee, identity-document verification or telecom network is claimed without the declared integration and measurement.
- **Portability and issuer limits:** Base command and transport machinery is retained, while Auth replaces Base operator privilege with its own proof, private authorization, identity archive and grant-map policy. AUTH-TRANSFER-001 records the current narrower replacement; AUTH-TRANSFER-002, AUTH-ERASURE-001, AUTH-RETENTION-001 and AUTH-AUDIT-001 define the complete target. Copied Base erasure/portability source alone is not product acceptance. Host moves require reenrollment/re-linking; an archive cannot reproduce hardware private keys or reveal a later erasure journal it was never given.

Real vendor certification, production recipient delivery, store acceptance and human accessibility proof are claimed only when their register receipts say so. Auth owns identity/access; payroll, benefits, time off, employee files, broad endpoint patching, EDR and software distribution stay with their respective products.

## Homepage claims

| # | Claim | Clauses |
| --- | --- | --- |
| 1 | Sign in with a touch. Passkeys and email links for your team, and one sign-in across the apps you link. | AUTH-IDENTITY-001, AUTH-PROTOCOL-001, AUTH-LINK-001 |
| 2 | Each person confirms their email once, then registers a passkey. Administrators always sign in with one. | AUTH-IDENTITY-001 |
| 3 | Approve an app and your team signs in to it with Auth. Sign out everywhere reaches every app you linked. | AUTH-LINK-001, AUTH-LOGOUT-001 |
| 4 | Invite people, allow your company’s domain and suspend access from one list. | AUTH-DIRECTORY-001, AUTH-DOMAINS-001 |
| 5 | Stage a user export from Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud, review it, then admit people as invitations. | AUTH-MOVEIN-001 |
| 6 | Free as in code, free as in cost. MIT licensed, nothing to pay. | CMD-001, AUTH-OPS-001 |
| 7 | Run Auth on your own computer. Your people, passkeys and apps stay in your installation, and export with you. | AUTH-HOST-001, AUTH-TRANSFER-001 |
| 8 | Passkey recovery: another administrator approves, or a notified 72-hour delay passes. | AUTH-IDENTITY-001, AUTH-RECOVERY-002 |
| 9 | Sign out everywhere: end every session in every linked app. | AUTH-LOGOUT-001 |
| 10 | Activity: every account and issuer event, recorded. | AUTH-AUDIT-001 |
| 11 | Required providers: require Google, Microsoft or Okta for a domain. | AUTH-FEDERATION-001, AUTH-DOMAINS-001 |
| 12 | Agent proposals: an agent prepares a change; a person approves it with a passkey under the held company policy. | AUTH-ADMIN-001 |
| 13 | Export and import: people, apps and a signed grant map move with you. | AUTH-TRANSFER-001 |
| 14 | Run Auth on your own computer, register a passkey and link your first app. Free and open source, MIT licensed. | CMD-001, AUTH-IDENTITY-001, AUTH-LINK-001 |

## Status

Judged from the code and tests at commit `4565fd3f48b1cfe6b518f27e168a215d9e549ac4` (17 October 2026).

| Clauses | Done | Partial | Missing | Total |
| --- | ---: | ---: | ---: | ---: |
| Published | 1 | 12 | 0 | 13 |
| Target and push further | 4 | 68 | 30 | 102 |
| All | 5 | 80 | 30 | 115 |

| Clause | Title | Kind | Status | Evidence | Gap |
| --- | --- | --- | --- | --- | --- |
| `AUTH-HOST-001` | Issuer host | published | partial | `tests/integration/dev.test.mjs` — "fresh rer setup chooses localhost; rer dev bridges only the gated real owner and refuses private paths"; `tests/auth/linking.test.mjs` — "an app links with a one-use token, signs a person in through Auth, and Sign out everywhere ends that app session"; `scripts/installer/local.mjs` | Missing a cited journey covering: preserved explicit issuer; preserved saved issuer; native passkey enrollment; host move requires a fresh app-owner approval; issuer authority is not silently preserved. Existing cited journeys show: fresh localhost; link an app. |
| `AUTH-PRIVACY-001` | Shared claims | published | partial | `src/auth/userinfo.mjs`; `tests/auth/userinfo.test.mjs` — "ES256 and RS256 tokens resolve matching scoped userinfo through GET and POST"; `tests/auth/rer-approval.test.mjs` — "Auth links an app only on a fresh, trusted RER approval that binds its origin and key, and claims only for its owner" | Missing a cited journey covering: scoped token identity claims; two independently linked app grants; trust key alone grants no user-data read without app sign-in. Existing cited journeys show: scoped UserInfo email; scoped UserInfo name; RER trust key installation. |
| `AUTH-RER-TRUST-001` | RER trust | published | partial | `src/auth/links/rer-trust.mjs`; `src/auth/links/rer-approval.mjs`; `tests/auth/rer-approval.test.mjs` — "Auth links an app only on a fresh, trusted RER approval that binds its origin and key, and claims only for its owner" | Missing a cited journey covering: wrong issuer; stale assertion; RER-signed withdrawal ends use; withdrawn key cannot be restored. Existing cited journeys show: valid signed RER link; origin mismatch; link-key mismatch; foreign owner claim; assertion replay; administrator withdrawal ends use. |
| `AUTH-IDENTITY-001` | Owner and sign-in proof | published | partial | `src/auth/local-email.mjs`; `src/auth/recovery.mjs`; `tests/auth/security.test.mjs` — "email proof is uniform, browser bound, one use and preserves a safe return path"; `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation"; `tests/auth/local-email.test.mjs`; `tests/auth/recovery-cli.test.mjs` | Missing a cited journey covering: fresh email at commit. Existing cited journeys show: same-browser proof; one-use confirmation; first enrollment; additional enrollment gate; wrong-session enrollment refusal; revoked-session enrollment refusal; independent approved recovery; delayed recovery; canceled recovery; emergency recovery replay refusal; additional enrollment persists a new key. |
| `AUTH-PROTOCOL-001` | OpenID Connect profile | published | partial | `src/auth/protocol.mjs`; `src/auth/userinfo.mjs`; `src/auth/keys.mjs`; `tests/auth/protocol.test.mjs` — "code flow preserves ES256 ID token claims and adds a userinfo access token" — "bad client and callback show local error without redirect; code needs matching PKCE and assertion"; `tests/auth/userinfo.test.mjs`; `tests/auth/authorization-policy.test.mjs` | Missing a cited journey covering: token audience; code replay; encrypted RS256 private keys. Existing cited journeys show: code and PKCE; private-key client proof; nonce; issuer; pairwise subject; scoped GET UserInfo; scoped POST UserInfo; assertion replay; inactive client; inactive person; inactive session; revoked grant; current policy; encrypted ES256 private keys; publish before use; retained-key retirement. |
| `AUTH-BOUNDARY-001` | Private authorization | published | partial | `src/server.ts`; `src/auth/index.mjs`; `tests/integration/http.test.mjs` — "emitted Auth protects private documents and Base authority seams; email proof belongs to the requesting browser"; `tests/integration/dev.test.mjs` — "fresh rer setup chooses localhost; rer dev bridges only the gated real owner and refuses private paths" | Missing a cited journey covering: passkey administrator page access; production dev proof refusal. Existing cited journeys show: signed-out private document; signed-out private API; email-only page refusal; email-only mutation refusal; revoked authority; inherited Base management denied; removing checkout gate ends dev authority. |
| `AUTH-MOVEIN-001` | Staged move-in | published | partial | `src/auth/move-in/routes.mjs`; `src/auth/move-in/sources.mjs`; `tests/auth/move-in-staging.test.mjs` — "review flags every conflict class; disabled-at-source rows start unselected and groups stay context"; `tests/auth/move-in-admission.test.mjs` — "admission is the ordinary invitation: administrators only, no proof, right, session or mail, and existing people never rebound"; `tests/integration/move-in-browser.test.mjs` | Missing a cited journey covering: concurrent administrator authority at commit. Existing cited journeys show: Google export rows; Entra export rows; Auth0 export rows; Okta export rows; JumpCloud export rows; collision flags; disabled flags; admitted member role and invited state; no email proof; no factor; no session; no app grant; no admission mail; explicit invitation recipient; untouched admission removed; changed admissions retained; undo audit records removed and kept; former Auth0 subject rejected as token code; former subject never pairwise identity; stale administrator proof refused. |
| `AUTH-ADMIN-001` | Agent preparation | published | partial | `src/auth/agents/keys.mjs`; `src/auth/agents/preparer.mjs`; `src/auth/agents/approval.mjs`; `tests/auth/agents-keys.test.mjs` — "preparer keys: only a passkey administrator with fresh email proof mints, renews and revokes; expired, revoked and orphaned keys are refused; the key is shown once and stored, listed, audited and logged nowhere"; `tests/auth/agents-proposals.test.mjs` — "the inventory returns only allow-listed fields and no session, passkey, key or token material from a populated store"; `tests/integration/agents-browser.test.mjs` | Missing a cited journey covering the whole clause. The old outcomes are asserted; the previously published partial status is retained for fresh judgment of the requirement and its policy integration. |
| `CMD-001` | Commands | published | partial | `AUTH-COMMANDS.md`; `scripts/installer/local.mjs`; `tests/integration/dev.test.mjs` — "fresh rer setup chooses localhost; rer dev bridges only the gated real owner and refuses private paths"; `tests/auth/recovery-cli.test.mjs` — "local recovery command writes only token digest through wrangler and protects saved token" | Missing a cited journey covering: repeated setup preserves owner; repeated setup preserves settings; repeated setup preserves data; local-command token redeemed through the same installation. Existing cited journeys show: real install/setup/dev readiness; browser sign-in; owned process shutdown; generated local token digest; raw token is mode 0600. |
| `HTTP-001` | HTTP surfaces | published | done | `tests/runtime.mjs` — "HTTP-001 passed against emitted Auth Worker: health, protected root, real sign-in document and HTTP/document 404s"; `tests/integration/http.test.mjs` — "emitted Auth protects private documents and Base authority seams; email proof belongs to the requesting browser" |  |
| `AUTH-LINK-001` | App links | published | partial | `src/auth/links/handshake.mjs`; `src/auth/links/routes.mjs`; `src/auth/links/versions.mjs`; `tests/auth/linking.test.mjs` — "a link that would take over another app's identity names that app to the approver, and runs only on an approval that named it" — "an app links with a one-use token, signs a person in through Auth, and Sign out everywhere ends that app session"; `tests/auth/agents-proposals.test.mjs` | Missing a cited journey covering: removal ends linked app; mismatched callbacks; mismatched origin; concurrent code redemption; unauthorized key swap; app session ends upon removal. Existing cited journeys show: pull protocol links Base app; employee signs in; relink keeps client and subject; link-token replay; unapproved version downgrade. |
| `AUTH-LOGOUT-001` | Sign-out reach | published | partial | `src/auth/links/logout.mjs`; `src/auth/links/end-session.mjs`; `tests/auth/linking.test.mjs` — "an app links with a one-use token, signs a person in through Auth, and Sign out everywhere ends that app session"; `tests/auth/protocol.test.mjs` | Missing a cited journey covering: suspension ends app session; RP-initiated logout ends app session; replayed logout token is refused; bounded logout retries; persisted delivery outcome read back; discovery advertises end-session; discovery advertises back-channel support. Existing cited journeys show: sign out everywhere ends app session. |
| `AUTH-TRANSFER-001` | Export and import | published | partial | `scripts/installer/transfer.mjs`; `src/auth/links/grant-map.mjs`; `tests/auth/linking.test.mjs` | Missing a cited journey covering: populated installation exported; same-host empty import; post-restore client continuity; post-restore sector continuity; post-restore pairwise subject continuity; all declared retained records read back; sessions and authority absent after import; incompatible origin refused; active dev persona refused. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. |
| `AUTH-DIRECTORY-001` | One workforce directory | target | partial | `src/auth/workforce/people/`; `src/auth/admin.mjs`; `tests/auth/directory.test.mjs` — "source precedence, manual overrides and conflicts are visible; a source finds people by its own id, never by email; an email change keeps the same person, sessions end and apps follow" — "onboard, rename, transfer, bulk preview, dynamic groups, suspend and rehire keep one stable account per person"; `tests/integration/directory-browser.test.mjs` | Missing a cited journey covering: suspend state read back. Existing cited journeys show: W-2 onboarding; contractor onboarding; rename; transfer; exact bulk preview; dynamic membership; rehire preserves identifier; source conflict visible; resulting assignments; no duplicate account. |
| `AUTH-TENANCY-001` | Organizations and delegated administration | target | partial | `tests/auth/security.test.mjs` — "organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions"; `tests/integration/directory-browser.test.mjs`; `docs/administrator-roles.md`; `tests/integration/http.test.mjs` | Missing a cited journey covering: contractor in two employers; proved organization switch; one-app delegation; one-case help-desk delegation; active-employer export refusal; active-employer import refusal; active employer within source archive refused; anonymous erased-employer evidence remains portable; portable credentials absent; sealed remote work excluded. Existing cited journeys show: cross-employer reads denied; cross-employer writes denied; cross-employer export denied; role escalation refused; installation session creates no employer session; installation hosting creates no membership; installation role has no employer directory authority. Relevant assertions are in tests/integration/erasure-portability.mjs, outside this clause’s old Evidence set. |
| `AUTH-TENANCY-002` | No cross-organization linking or proof transfer | target | partial | `tests/auth/security.test.mjs` — "organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions"; `tests/auth/provisioning.test.mjs` | Missing a cited journey covering: identical upstream subject remains separate; no automatic link or match; foreign-membership UI hidden; replacement organization with same name cannot attach receipts; matching domain cannot attach receipts; matching people cannot attach sealed work; retained work never appears; retained work cannot be linked; retained work cannot be retried from replacement. Existing cited journeys show: same-email identities remain separate; cross-employer passkey refused; cross-employer step-up refused; cross-employer recovery refused; cross-employer approval refused; foreign admin API read denied; foreign export denied. Relevant assertions are in tests/auth/scoped-upstream-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-ROLES-001` | Custom administrator roles and resource sets | target | done | `tests/auth/directory.test.mjs` — "scoped help desk separates view and edit, refuses privileged and out-of-group people, and follows live membership"; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile" |  |
| `AUTH-DOMAINS-001` | Verified employer domains | target | partial | `tests/auth/domains.test.mjs` — "revocation reevaluates existing sessions and enrollment while emergency owners retain audited access and can reverify" — "domain setup refuses unproved, incorrect, expired and competing ownership; exact aliases need proof and eligible enrollment still needs individual email proof"; `tests/auth/upstreams.test.mjs`; `tests/auth/fresh-proof.test.mjs`; `tests/integration/security-settings-browser.test.mjs`; `docs/verified-domains.md` | Missing a cited journey covering: eligible worker signs in; required-provider routing; emergency owner remains admitted. Existing cited journeys show: correct domain enables enrollment; incorrect challenge refused; expired challenge refused; competing employer refused; domain revoked; current worker policy denied; emergency access audit. |
| `AUTH-PROFILE-001` | Profiles and safe identity linking | target | done | `tests/auth/profile.test.mjs` — "an employee edits only permitted profile fields; fields held by HR or an administrator are protected and say who holds them; hidden fields stay hidden; groups follow"; `tests/auth/upstreams.test.mjs` — "a signed-in person connects a second proven identity after confirming, and disconnects it; an email collision, a foreign subject, a replay and a concurrent binding are refused"; `tests/auth/upstreams.test.mjs` — "an agent proposal, imported metadata or a matching email never connects an identity, and the last usable sign-in cannot be disconnected"; `tests/auth/profile.test.mjs` — "apps receive the edited name only under the profile scope, and never a custom or hidden field" |  |
| `AUTH-ENROLLMENT-001` | Managed enrollment and password compatibility | target | partial | `src/auth/email.mjs`; `src/auth/passkeys.mjs`; `tests/auth/security.test.mjs`; `tests/auth/registration.test.mjs` | email/domain enrollment and passkeys exist; passwords and SMS do not. |
| `AUTH-PASSWORD-001` | Password policy per group | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-PASSWORD-002` | Self-service password reset, unlock and propagation | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-ONBOARD-001` | New-hire activation before the start date | target | partial | `tests/auth/onboarding.test.mjs`; `tests/integration/browser.test.mjs`; `docs/onboarding.md`; `tests/auth/temporary-passes.test.mjs` | Administrator-created hires support unverified personal contacts, employer-local start times, bounded lead time, digest-only single-use activation, passkey enrollment, reissue and rescission. Personal activation is enrollment-only; ordinary work-address proof remains required for application access. Local scheduling and native SAML and OIDC gates are proved. HR-source ingestion and start-date qualification, authorized HR test source and verified delivery recipient, live delivered invitations and reminders, manager escalation with outbound authority, optional SMS and Persona or CLEAR checks, Auth authenticator and password enrollment, temporary-pass fallback, downstream joiner provisioning, RADIUS, desktop and every other device or network acceptance point remain unproved. Uncertain activation delivery needs explicit reissue. Zero-day lead has no pre-start activation window; late enrollment still depends on the unbuilt temporary-pass path. CT policy approval does not complete AUTH-ONBOARD-001. Zero-day and missed-window onboarding still require the unbuilt AUTH-TAP-001 fallback and its scoped issuance and refusal proof. Recorded personal-contact authority, required notice and consent handling, dispatch-boundary proofs for initial activation, reissue, retry and reminder, and live recipient proof remain unestablished. Mail accepted by a provider before start may arrive afterward; the original delivered-message acceptance sentence remains unproved, including that in-flight delivery boundary. The strict cutoff is interim and does not remove day-one onboarding or any existing acceptance obligation. Native contact-authority recording, dispatch-boundary refusals for initial sends and explicit reissues, retries and reminders, and hosted manager-requested scoped temporary-pass enrollment are implemented; the complete AUTH-TAP-001 obligation, live recipient delivery and in-flight provider boundary remain open. |
| `AUTH-ONBOARD-002` | Personal-contact dispatch custody | target | partial | `tests/auth/onboarding.test.mjs`; `tests/integration/browser.test.mjs`; `docs/onboarding.md`; `tests/auth/temporary-passes.test.mjs` | Administrator-created hires support unverified personal contacts, employer-local start times, bounded lead time, digest-only single-use activation, passkey enrollment, reissue and rescission. Personal activation is enrollment-only; ordinary work-address proof remains required for application access. Local scheduling and native SAML and OIDC gates are proved. HR-source ingestion and start-date qualification, authorized HR test source and verified delivery recipient, live delivered invitations and reminders, manager escalation with outbound authority, optional SMS and Persona or CLEAR checks, Auth authenticator and password enrollment, temporary-pass fallback, downstream joiner provisioning, RADIUS, desktop and every other device or network acceptance point remain unproved. Uncertain activation delivery needs explicit reissue. Zero-day lead has no pre-start activation window; late enrollment still depends on the unbuilt temporary-pass path. CT policy approval does not complete AUTH-ONBOARD-001. Zero-day and missed-window onboarding still require the unbuilt AUTH-TAP-001 fallback and its scoped issuance and refusal proof. Recorded personal-contact authority, required notice and consent handling, dispatch-boundary proofs for initial activation, reissue, retry and reminder, and live recipient proof remain unestablished. Mail accepted by a provider before start may arrive afterward; the original delivered-message acceptance sentence remains unproved, including that in-flight delivery boundary. The strict cutoff is interim and does not remove day-one onboarding or any existing acceptance obligation. Native contact-authority recording, dispatch-boundary refusals for initial sends and explicit reissues, retries and reminders, and hosted manager-requested scoped temporary-pass enrollment are implemented; the complete AUTH-TAP-001 obligation, live recipient delivery and in-flight provider boundary remain open. |
| `AUTH-TAP-001` | Temporary access pass | target | partial | `tests/auth/temporary-passes.test.mjs`; `tests/integration/browser.test.mjs`; `tests/integration/helpers/temporary-pass-journey.mjs` | Native onboarding-only manager attestation, scoped issuance, digest-only custody, hosted redemption, real work-email confirmation and passkey enrollment are implemented. Group lifetime policy, optional reusable passes, scheduled validity, remaining-factor and identity-provider verification, general recovery targets, desktop login and local account creation, RADIUS refusal, and employee and manager notices remain unproved. |
| `AUTH-EXPERIENCE-001` | Hosted and embedded identity journeys | target | partial | `src/ui/pages/signin.ts`; `src/ui/pages/account.ts`; `tests/integration/browser.test.mjs` | hosted responsive pages exist; branding controls, embedded components and journey orchestration are missing. |
| `AUTH-LOCALE-001` | End-user display languages | target | missing | `src/ui/shell.ts`; `src/ui/pages/signin.ts` | every page renders English only (`lang="en"`); language selection, translations and per-language employer text are missing. |
| `AUTH-LAUNCHER-001` | Employee app launcher | target | partial | `src/auth/launcher/index.mjs`; `tests/auth/saml.test.mjs`; `tests/auth/oidc-apps.test.mjs`; `tests/integration/company-apps-browser.test.mjs`; `tests/auth/access-decisions-flow.mjs`; `tests/auth/review-reduction-flow.mjs` | Native search, per-person durable favorites and recent opens, request links using the existing passkey decision flow, group-only credential-free bookmarks, and denied, expired, unprovisioned and connector-blocked explanations are implemented. Shared native assignment checks refuse removed and expired temporary grants at SAML launch and OIDC authorization and token issuance; saved preferences confer no access. Held: password-app tiles and extension fill and enforcement need the browser-extension release; RER tiles need the Base local link and Spool owner-link path; the complete five-app journey needs authorized Google Workspace, Slack and AWS tenants and a password-app account. Native protocol peers do not establish vendor or extension qualification. |
| `AUTH-SWA-001` | Password-based app sign-in | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-MFA-001` | Passkey-first multifactor policy | target | partial | `tests/auth/security.test.mjs`; `tests/auth/local-email.test.mjs`; `tests/integration/security-settings-browser.test.mjs` | Native web TOTP, digest-only single-use recovery codes, factor inventory and lost-factor revocation, app assurance and current-session revocation built. Conservative native default: only the owner with passkey and fresh email configures app assurance; TOTP never grants administration; recovery codes require fresh email, refuse every active delegated role and permit only replacement enrollment for members; factor removal and code rotation end all Auth sessions. Scoped factor-policy delegation and broader assurance policy await ct. Real Auth push and native authenticator TOTP need AUTH-AUTHENTICATOR-001 devices and gr signing; RADIUS and OS-login assurance need AUTH-LEGACY-001 and AUTH-DESKTOP-001. Live notification delivery, mobile and desktop inventory and revocation, and same-business-day lost-factor recovery remain unproved under AUTH-NOTIFY-001 and AUTH-RECOVERY-003. |
| `AUTH-AUTHENTICATOR-001` | Push authenticator in the Auth mobile app | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-POLICY-001` | Conditional access and session policy | target | partial | `src/auth/domain-policy.mjs`; `src/auth/authorization-login.mjs`; `tests/auth/authorization-policy.test.mjs`; `tests/auth/upstreams.test.mjs` | current domain, session and prompt/max-age checks exist; general device/location/risk engine is missing. |
| `AUTH-ABUSE-001` | Automated attack protection | target | partial | `src/auth/abuse/index.mjs`; `tests/auth/abuse.test.mjs`; `tests/auth/protocol.test.mjs`; `tests/integration/security-settings-browser.test.mjs` | Tenant-scoped configurable native throttling is proven for email, WebAuthn, recovery and token requests, with durable aggregate and source budgets, bounded cooldowns, explained refusal audit and commit-time administrator hardware and fresh-email protection. Tor-exit and impossible-travel proof awaits AUTH-RISK-001 and licensed MaxMind feeds; password spraying, breached-password screening, lockout and unlock await AUTH-PASSWORD-001 and AUTH-PASSWORD-002; remaining bot-challenge controls and protected notifications under AUTH-NOTIFY-001 remain unproved. |
| `AUTH-RISK-001` | Named sign-in behavior signals | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-NOTIFY-001` | Employee security notifications and suspicious-activity reports | target | partial | `tests/auth/notifications.test.mjs` — "security notifications report suspicious activity, escalate once and end sessions and refresh grants with back-channel logout"; `tests/auth/notifications.test.mjs` — "security notice preferences retain mandatory recovery and factor notices, and report links refuse forgery, cross-employer use and expiry"; `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation"; `tests/integration/security-settings-browser.test.mjs` — "security settings: prove and revoke employer ownership, preview affected workers, and authorize persistent notification preferences at desktop and mobile"; `tests/auth/notifications-flow.mjs` — "roleGrantNotices" (within the mandatory-notice journey); `tests/integration/directory-browser.test.mjs` — "organization and authority journey"; `docs/security-notifications.md` | Push notices depend on AUTH-AUTHENTICATOR-001. Password-changed and password-lockout notices depend on AUTH-PASSWORD-001; temporary access pass notice coverage remains under AUTH-TAP-001. Explicit scoped grants now atomically retain required email intents bound to the operation and verified work address, including before setup; failed or uncertain attempts remain actionable without automatic resend. Remaining: every role-grant path outside this existing explicit action, remaining factor-removal and other unbuilt event doors, required-notice intents before setup at those doors, connected SaaS session revocation under AUTH-LOGOUT-002, additional report responses, Oncall escalation and configured SIEM qualification. Live delivery qualification of this scoped-grant path remains unproved. |
| `AUTH-NOTIFY-002` | Mandatory channels and report authority | target | partial | `tests/auth/notifications.test.mjs` — "security notifications report suspicious activity, escalate once and end sessions and refresh grants with back-channel logout"; `tests/auth/notifications.test.mjs` — "security notice preferences retain mandatory recovery and factor notices, and report links refuse forgery, cross-employer use and expiry"; `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation"; `tests/integration/security-settings-browser.test.mjs` — "security settings: prove and revoke employer ownership, preview affected workers, and authorize persistent notification preferences at desktop and mobile"; `tests/auth/notifications-flow.mjs` — "roleGrantNotices" (within the mandatory-notice journey); `tests/integration/directory-browser.test.mjs` — "organization and authority journey"; `docs/security-notifications.md` | Push notices depend on AUTH-AUTHENTICATOR-001. Password-changed and password-lockout notices depend on AUTH-PASSWORD-001; temporary access pass notice coverage remains under AUTH-TAP-001. Explicit scoped grants now atomically retain required email intents bound to the operation and verified work address, including before setup; failed or uncertain attempts remain actionable without automatic resend. Remaining: every role-grant path outside this existing explicit action, remaining factor-removal and other unbuilt event doors, required-notice intents before setup at those doors, connected SaaS session revocation under AUTH-LOGOUT-002, additional report responses, Oncall escalation and configured SIEM qualification. Live delivery qualification of this scoped-grant path remains unproved. |
| `AUTH-LOGOUT-002` | Universal logout from connected SaaS for a compromised account | target | partial | `src/auth/links/logout.mjs`; `src/auth/index.mjs`; `tests/auth/linking.test.mjs` | Sign out everywhere ends the person's own Auth sessions and signs them out of linked RER apps by back-channel logout; ending another person's sessions, report and risk triggers, and vendor-API revocation in SaaS apps are missing. |
| `AUTH-SAML-001` | SAML 2.0 workforce identity provider | target | partial | `src/auth/saml/`; `src/auth/workforce/routes.mjs`; `tests/auth/saml.test.mjs` — "encrypted assertions open at the app with AES-256-GCM and AES-128-CBC; a Redirect-bound response is signed in its query; IdP-initiated launch only where the app permits it" — "an assigned employee signs in to a SAML app over both request bindings, with each NameID format, signature placement and algorithm"; `tests/integration/company-apps-browser.test.mjs` | Missing a cited journey covering: RSA-OAEP transport; stale assertion refused; replayed assertion refused. Existing cited journeys show: generic SP configured; POST request binding; Redirect request binding; persistent NameID; emailAddress NameID; unspecified NameID; transient NameID; mapped role; response signature; assertion signature; both signatures; SHA-256; SHA-512; AES-256-GCM assertion decryption; AES-128-CBC assertion decryption; overlapping certificate rollover; SP-initiated POST logout; SP-initiated Redirect logout; IdP-initiated POST logout; IdP-initiated Redirect logout; forged request refused; altered ACS refused; wrong audience refused; SHA-1 without exception refused; unassigned employee refused. |
| `AUTH-OIDC-001` | General SaaS OIDC and OAuth profiles | target | partial | `src/auth/oidc-apps/`; `src/auth/protocol.mjs`; `src/auth/links/end-session.mjs`; `tests/auth/oidc-apps.test.mjs` — "wrong, mismatched and rotated-out secrets, substituted redirects and codes, replays and unsupported grants are refused; legacy flows only where opted in; unassigned people get no tokens" — "SaaS clients sign in with client_secret_basic, client_secret_post and private_key_jwt, and a native app with none and PKCE; RP-initiated logout reaches front- and back-channel apps"; `tests/integration/company-apps-browser.test.mjs`; `COMPANY-APPS.md` | Missing a cited journey covering: logout for each profile; strict RER journey preserves advertised profile. Existing cited journeys show: client_secret_basic code flow; client_secret_post code flow; private_key_jwt code flow; public none plus PKCE code flow; secret rotation overlap; wrong secret refused; rotated-out secret refused; public client without PKCE refused; substituted redirect refused; substituted token refused; code replay refused; unsupported grant refused; each general connection advertises its profile. |
| `AUTH-MAPPING-001` | Attribute and NameID transform language | target | partial | `tests/auth/saml.test.mjs` — "app setup previews typed mappings for three people, launches computed collision-safe NameID and group role, provisions formatted dates, refuses unsafe programs and rolls back an audited version"; `tests/auth/oidc-apps.test.mjs` — "SaaS clients sign in with client_secret_basic, client_secret_post and private_key_jwt, and a native app with none and PKCE; RP-initiated logout reaches front- and back-channel apps"; `tests/integration/company-apps-browser.test.mjs`; `docs/attribute-mapping.md` | Missing a cited journey covering: elapsed-time budget refusal; typed version-one input projection; no runtime access; no dynamic code; node-count bound; output-size bound; elapsed-time bound; whole-directory collision allocation. Existing cited journeys show: collision-safe first.last preview; group-derived role at SP; formatted SCIM date read back; missing-field warning; three-person preview; launched NameID read back; secret expression refused; network expression refused; rollback value read back; manager projection; source projection; group projection; no credential access; no network operations; character-work bound; expression-depth bound; exact preview required; current version required; rollback publishes a new audited version; SAML output read back; SCIM output read back; generic OIDC output read back. |
| `AUTH-CATALOG-001` | Production SaaS application catalog | target | partial | `src/auth/catalog/recipes.mjs`; `tests/auth/catalog.test.mjs` | Google Workspace, Microsoft 365, Slack, GitHub Enterprise Cloud, AWS IAM Identity Center, Salesforce and Zoom recipes fill a working SAML app and, for the SCIM vendors, a provisioning connector, and state edition, permissions, roles, attributes, test-user procedure, certificate rotation and session limits. Missing: every authorized vendor-tenant journey (needs accounts), the Google Directory API and Microsoft Graph provisioning adapters, and Zoom's client-credentials token refresh. |
| `AUTH-CATALOG-002` | Catalog breadth and verification cadence | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-M365-001` | Microsoft 365 domain federation and licensing | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-SCIM-001` | Outbound provisioning and deprovisioning | target | partial | `src/auth/provisioning/`; `src/auth/workforce/`; `tests/auth/provisioning.test.mjs` — "a provider answering 429 and 503, or losing a response, is retried until it recovers with no duplicate account; a name collision waits for an administrator; drift is found across pages" — "a group assignment provisions its members and the group over SCIM; role changes update the one account; unassignment and suspension deactivate, verified by read-back"; `tests/auth/scim-server.mjs` | Missing a cited journey covering: email updated. Existing cited journeys show: group assigned; remote user values; remote group membership; role updated; 429 held outcome; 503 held outcome; provider recovery; verified revocation; one remote account per person; persisted verified state; healthy dispatch within bound; healthy verification within bound; no duplicate remote POST; remote deactivation read back. |
| `AUTH-SCIM-002` | Inbound directory synchronization | target | partial | `tests/auth/directory.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `tests/auth/provisioning.test.mjs`; `tests/auth/directory-source-flow.mjs`; `journeys/directory-sandboxes.mjs`; `docs/directory-sources.md` | Partial remains unchanged. Native connectors stage observations and apply only exact human-approved changes. Generic SCIM pull sources now refresh liveness on successful unchanged content and retain visible source-bound failure and overdue episodes under their registered custodian and existing polling schedule. Recovery closes an episode without approving changes; disablement and custody loss stop it with retained history. No global or HR follow-up consent authorizes a directory reminder. Remaining Gaps are complete live provider mover and leaver qualification, Google Workspace directory delegation, measured pushed and polling bounds, full-reconciliation timing, receipt-to-application timeliness while human approval is pending, stale-source follow-up for other directory profiles and every outbound reminder, and nested or external membership support. Timely provisioning and deprovisioning remain complete category requirements. CT approves approval-origin timing only for the interim approved-delivery execution profile; it does not redefine receipt-origin source performance, authorize recurring approval, infer termination from absence or grant outbound consent. |
| `AUTH-SCIM-003` | Inbound delivery approval and execution custody | target | partial | `tests/auth/directory.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `tests/auth/provisioning.test.mjs`; `tests/auth/directory-source-flow.mjs`; `journeys/directory-sandboxes.mjs`; `docs/directory-sources.md` | Partial remains unchanged. Native connectors stage observations and apply only exact human-approved changes. Generic SCIM pull sources now refresh liveness on successful unchanged content and retain visible source-bound failure and overdue episodes under their registered custodian and existing polling schedule. Recovery closes an episode without approving changes; disablement and custody loss stop it with retained history. No global or HR follow-up consent authorizes a directory reminder. Remaining Gaps are complete live provider mover and leaver qualification, Google Workspace directory delegation, measured pushed and polling bounds, full-reconciliation timing, receipt-to-application timeliness while human approval is pending, stale-source follow-up for other directory profiles and every outbound reminder, and nested or external membership support. Timely provisioning and deprovisioning remain complete category requirements. CT approves approval-origin timing only for the interim approved-delivery execution profile; it does not redefine receipt-origin source performance, authorize recurring approval, infer termination from absence or grant outbound consent. |
| `AUTH-SCIM-004` | Inbound receipt and application timing | target | partial | `tests/auth/directory.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `tests/auth/provisioning.test.mjs`; `tests/auth/directory-source-flow.mjs`; `journeys/directory-sandboxes.mjs`; `docs/directory-sources.md` | Partial remains unchanged. Native connectors stage observations and apply only exact human-approved changes. Generic SCIM pull sources now refresh liveness on successful unchanged content and retain visible source-bound failure and overdue episodes under their registered custodian and existing polling schedule. Recovery closes an episode without approving changes; disablement and custody loss stop it with retained history. No global or HR follow-up consent authorizes a directory reminder. Remaining Gaps are complete live provider mover and leaver qualification, Google Workspace directory delegation, measured pushed and polling bounds, full-reconciliation timing, receipt-to-application timeliness while human approval is pending, stale-source follow-up for other directory profiles and every outbound reminder, and nested or external membership support. Timely provisioning and deprovisioning remain complete category requirements. CT approves approval-origin timing only for the interim approved-delivery execution profile; it does not redefine receipt-origin source performance, authorize recurring approval, infer termination from absence or grant outbound consent. |
| `AUTH-HRIS-001` | HR-driven identity sources | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-HRIS-002` | Scheduled HR file feeds | target | partial | `tests/auth/directory.test.mjs` — "an explicitly approved HR file applies current and dated hires, moves and leavers once, resolves managers and resumes interruptions while preserving enrollment and authority refusals"; `tests/integration/directory-browser.test.mjs`; `docs/hr-file-feeds.md`; `tests/auth/provisioning.test.mjs`; `tests/integration/browser.test.mjs` | Missing a cited journey covering: saved SFTP mapping; hire preview and resulting access; mover preview and resulting access; leaver preview and resulting access; malformed delivery held; empty delivery held; twenty-percent termination held; skipped feed is stale; stale-source follow-up; wrong SFTP key refused; foreign-employer file refused. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/hr-file-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-LIFECYCLE-001` | Complete joiner, mover and leaver execution | target | partial | `src/auth/admin.mjs`; `src/auth/links/logout.mjs`; `tests/auth/linking.test.mjs` | manual invitations, suspension and RER fences exist; multi-app HR-driven execution is missing. |
| `AUTH-TIMING-001` | Measured lifecycle time bounds | target | partial | `src/auth/admin.mjs`; `src/auth/links/logout.mjs`; `src/auth/provisioning/obligations.mjs`; `tests/auth/security.test.mjs`; `tests/auth/linking.test.mjs`; `tests/auth/provisioning.test.mjs` | suspension denies Auth sessions at once and starts signed RER back-channel logout with bounded retries; each SCIM obligation records event, dispatch and remote-verified times and is flagged unverified past 15 minutes. Missing: source and joiner bounds, the 24-hour reconciliation of every source, and the timeliness report. |
| `AUTH-WORKFLOWS-001` | Employer-built identity automations | target | partial | `tests/auth/automations.test.mjs`; `tests/auth/events.test.mjs`; `tests/integration/automations-browser.test.mjs`; `docs/automations.md` | Under the held company policy for access, security, external and destructive, the bounded native slice implements one group-membership trigger, two signed HTTP steps, encrypted OAuth client-credentials custody, scoped authority, exact named approval for every run, person-specific zero-outbound dry runs and durable failure obligations. Held: authorized Google Workspace and Microsoft 365 tenants with Drive, Calendar, Gmail and Graph mailbox and license consent. All live HR-triggered leaver-template journeys, Drive and Calendar transfer, Gmail delegation and auto-reply, shared mailbox and OneDrive manager access, and Google, Microsoft 365, Slack, Zoom and Salesforce license reclaim remain unproved. Other trigger families, full mapping conditions, connector-action steps, waits, branches, notification steps, remaining authentication modes, template copying and editing, full remote verification and retry journeys, and complete lifecycle-plan integration remain unbuilt. Native peers qualify no vendor template. The shared class computation and company-policy decision adapter remain unproved. |
| `AUTH-FEDERATION-001` | Generic upstream federation | target | partial | `tests/auth/upstreams.test.mjs`; `tests/auth/security.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `docs/upstream-campaigns.md` | Partial remains unchanged. The owner-only delegated RS256 OIDC and plaintext SAML profile is implemented according to the cited repository evidence. Remaining Gaps are live Google callback and consenting test-user proof, an authorized Okta web registration, live Entra employee callback, full live downstream qualification, SAML upstream certificate-rotation and outage-recovery qualification, and broader federation-loop qualification. Every original generic and named-provider acceptance journey remains required. CT approves exact owner activation with isolated representative testing and the stated riders; this ruling certifies neither provider interoperability nor implementation completion. |
| `AUTH-FEDERATION-002` | Reviewed upstream activation custody | target | partial | `tests/auth/upstreams.test.mjs`; `tests/auth/security.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `docs/upstream-campaigns.md` | Partial remains unchanged. The owner-only delegated RS256 OIDC and plaintext SAML profile is implemented according to the cited repository evidence. Remaining Gaps are live Google callback and consenting test-user proof, an authorized Okta web registration, live Entra employee callback, full live downstream qualification, SAML upstream certificate-rotation and outage-recovery qualification, and broader federation-loop qualification. Every original generic and named-provider acceptance journey remains required. CT approves exact owner activation with isolated representative testing and the stated riders; this ruling certifies neither provider interoperability nor implementation completion. |
| `AUTH-SOCIAL-001` | Controlled external identity sign-in | target | partial | `src/auth/upstreams.mjs`; `tests/auth/upstreams.test.mjs` | Google OIDC is exercised; GitHub and Apple adapters are missing. |
| `AUTH-LEGACY-001` | LDAP, Active Directory and RADIUS access | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-DEVICE-001` | Device identity and trust | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-DESKTOP-001` | Sign in to the computer with company identity | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-GATEWAY-001` | On-premises web apps through an access gateway | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-PRIVILEGED-001` | Server and SSH access without standing keys | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-GRANTS-001` | App roles, APIs and service identities | target | done | `tests/auth/oidc-apps.test.mjs` — "resource APIs use live app roles and tenant resources for employees and distinct accountable OAuth services" |  |
| `AUTH-TOKENS-001` | Refresh and delegated session lifecycle | target | partial | `tests/auth/oidc-apps.test.mjs` — "native offline consent and SDK rotation preserve device binding, detect reuse and concurrency, and end resource authority on expiry, revocation, suspension and app removal"; `tests/integration/refresh-browser.test.mjs`; `tests/auth/protocol.test.mjs`; `docs/offline-sessions.md`; `packages/session-sdk/index.mjs` | Missing a cited journey covering: Use a native SDK to obtain an approved refresh grant; rotate it; replay an old token; revoke the family through My account; Run concurrent refresh; expiry; suspension; app removal; confirming the resource API refuses invalid authority; strict RER clients receive no refresh token; An administrator explicitly binds a general OIDC client to its own app's resource API; published scopes; chosen idle/absolute lifetimes; there are no implicit offline grants; Each person consents to the exact app/device; audience; scopes; lifetimes; S256 PKCE; registered client authentication; ES256 DPoP bind the grant; Refresh digests rotate with one winner; authenticated consumed-token reuse ends the family without a grace interval or cached successor; The SDK coalesces concurrent calls; commits storage before publishing a successor; failures require deliberate new consent; Resource decisions recheck the family; current account/app/assignment; policy; API/profile revisions; preserve the app's subject policy. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/refresh-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-TOKENS-002` | Offline resource endings and portability | target | partial | `tests/auth/oidc-apps.test.mjs` — "native offline consent and SDK rotation preserve device binding, detect reuse and concurrency, and end resource authority on expiry, revocation, suspension and app removal"; `tests/integration/refresh-browser.test.mjs`; `tests/auth/protocol.test.mjs`; `docs/offline-sessions.md`; `packages/session-sdk/index.mjs` | Missing a cited journey covering: Browser expiry alone does not end an offline grant; explicit source-session revocation; account/app/profile endings; either grant expiry do; My account; scoped administrator doors retain the existing permission; view/edit resource; hardware/fresh-email; account-rank fences; Supported OIDC logout is queued without claiming remote deletion; Credentials; family authority are nonportable; the shared registry covers erasure/retention. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/refresh-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-HOOKS-001` | Inline hooks for custom sign-in logic | target | partial | `tests/auth/oidc-apps.test.mjs` — "inline hooks add only approved token and SAML fields, deny registration and imports, enforce signed minimal payloads and timeout choices, and refuse private DNS and protected identity changes"; `tests/auth/protocol.test.mjs` — "code flow preserves ES256 ID token claims and adds a userinfo access token"; `tests/auth/move-in-admission.test.mjs`; `tests/integration/company-apps-browser.test.mjs`; `docs/inline-hooks.md` | Missing a cited journey covering: neither may change an identity binding or authority; Unavailable password-hook registration refuses; no password verifier is simulated. Existing cited journeys show: Register a token hook that adds a cost-center claim; see it in the ID token; a registration hook that denies an outside domain; a hook that tries to add an administrator role; change the subject; see both changes refused; Let a fail-closed hook time out; see the sign-in refused with a clear error; then a fail-open hook time out; see sign-in continue with the event logged; Refuse a hook URL that resolves to a private address; signed hooks run for strict RER; general OIDC ID tokens; SAML assertions; self-registration; staged move-in admission; source-id-matched directory imports; Token/SAML outputs are restricted to explicit custom fields; registration/import may alter only the currently exposed name field; Every remote call is bounded; audited; followed by a fresh issuance/commit authority check. |
| `AUTH-REQUESTS-001` | Access requests and time-bound grants | target | partial | `tests/auth/directory.test.mjs`; `src/auth/requests/index.mjs`; `docs/access-decisions.md` | Native single-decider temporary requests and exact decision/expiry foundation built for DECISIONS-001. Authorized Salesforce/AWS role/elevation tenants, multi-stage routing, extensions/emergency rules, chat and live remote expiry qualification remain. |
| `AUTH-REVIEWS-001` | Periodic access certification | target | partial | `tests/auth/directory.test.mjs`; `tests/auth/access-decisions-flow.mjs`; `src/auth/reviews/routes.mjs`; `docs/access-decisions.md`; `tests/auth/native-review-flow.mjs`; `tests/auth/review-scope-flow.mjs`; `tests/auth/review-reduction-flow.mjs`; `tests/auth/review-reminders-flow.mjs`; `tests/integration/directory-browser.test.mjs` | Employee/contractor/service snapshots, recurring quarterly runs, delegation, certify/reduce/revoke, new drift, calendar/DST reviewer reminders, absence/overdue escalation, provider-failure closure and immutable export built. Scoped published review permissions and optional native Auth administrator-grant snapshots are built; native revocation reuses live role/rank fences, terminates sessions and refuses owner removal. Generic obligations are FOLLOWUP-003; future POLICY/PASSWORD clauses inherit immutable policy-version evidence before shipping. |
| `AUTH-DECISIONS-001` | Proof levels for administration and everyday decisions | target | partial | `tests/auth/directory.test.mjs`; `tests/auth/access-decisions-flow.mjs`; `src/auth/decisions/routes.mjs`; `docs/access-decisions.md`; `tests/integration/directory-browser.test.mjs` | Native group/request submission/approval/review certify-reduce-revoke doors, exact UV proof, stale/lost/concurrent refusal built. Authorized Salesforce/AWS live request qualification remains under REQUESTS-001; configurable step-up policy inherits POLICY-001. Request submission now uses the same exact UV proof. |
| `AUTH-CHAT-001` | Approve, deny and certify from Slack and Microsoft Teams | target | missing |  | Slack interactivity requires main to choose and configure the shared app request URL or router; Teams requires Entra administrator consent. Native chat bindings and actions and the full authorized workspace journey remain unbuilt. |
| `AUTH-AUDIT-001` | Identity investigation and reporting | target | partial | `tests/auth/audit.test.mjs`; `tests/auth/agents-keys.test.mjs`; `tests/integration/directory-browser.test.mjs`; `docs/activity.md` | Native interactive Activity and role audit queries now have stable employer-bound event IDs, bounded time, person and event filters, as-of pagination and current authority checks. Twelve-month sign-in readback, reconciliation beyond the old cap despite concurrent appends, auditor write and related-target scope refusals before counts and pagination, recoverable Activity filter and cursor errors, and opaque erased-subject projections are implemented. Held: authorized Datadog, Splunk, Microsoft Sentinel and Evidence destinations, sink export and streaming, complete failed-sign-in, policy and provisioning correlation, full employee device and grant history, MFA and other report reconciliation including password, push and policy dependencies, and general durable tamper and gap evidence remain unproved. AUTH-RETENTION-001 and AUTH-ERASURE-002 policy holds are unchanged. |
| `AUTH-REPORTS-001` | Named per-person identity reports | target | partial | `tests/auth/directory.test.mjs`; `docs/identity-reports.md` | Native scoped JSON/CSV views, filters, stable columns, as-of roster counts, separate audited export, grants, dormancy and unresolved SCIM names are built. Password/push and employer MFA-policy qualification, full local/all-downstream timing reconciliation, every connector, schedules, machine exports and compliance/Evidence delivery remain unproved; missing facts stay unknown. |
| `AUTH-COMPLIANCE-001` | Identity-provider connectors for compliance platforms | target | missing |  | No implementing product path in audited src/ and tests/; acceptance journey remains to be built. |
| `AUTH-MIGRATION-001` | Switch from Okta, Entra ID or JumpCloud | target | partial | `src/auth/move-in/sources.mjs`; `src/auth/move-in/routes.mjs`; `tests/auth/move-in-staging.test.mjs`; `tests/auth/move-in-admission.test.mjs` | Export staging and admission exist for all three; full configuration, group and app migration and live cutover are missing. JumpCloud, Vanta and Drata accounts are not held. |
| `AUTH-MIGRATION-002` | Custom-directory and progressive move-in | target | partial | `tests/auth/move-in-staging.test.mjs`; `tests/auth/move-in-admission.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `docs/progressive-migration.md` | Missing a cited journey covering: Import Google; Auth0 records; migrate one eligible legacy worker at first login through the real bridge; compare downstream subject mapping before/after; Refuse a wrong password; email collision; disabled worker; interrupt migration; prove an idempotent outcome; a cleanly disabled bridge. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/legacy-bridge-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-MIGRATION-003` | Cutover enrollment campaign | target | partial | `tests/auth/move-in-admission.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `docs/upstream-campaigns.md` | Partial remains unchanged. Native campaign passkey readiness is distinct from complete enrollment. Remaining Gaps are the live twenty-worker Okta callback with an authorized web registration, live Entra employee proof and JumpCloud qualification, native Auth authenticator enrollment, optional eligible Okta password preservation and RADIUS cutover, Slack or Teams delivery, and temporary access passes after cutover. Every original campaign acceptance point remains required. CT approves the separately consented minimal cohort-manager reminder policy with the stated riders; this ruling supplies no implementation or live-provider proof. |
| `AUTH-MIGRATION-004` | Campaign manager reminder custody | target | partial | `tests/auth/move-in-admission.test.mjs`; `tests/integration/move-in-browser.test.mjs`; `docs/upstream-campaigns.md` | Partial remains unchanged. Native campaign passkey readiness is distinct from complete enrollment. Remaining Gaps are the live twenty-worker Okta callback with an authorized web registration, live Entra employee proof and JumpCloud qualification, native Auth authenticator enrollment, optional eligible Okta password preservation and RADIUS cutover, Slack or Teams delivery, and temporary access passes after cutover. Every original campaign acceptance point remains required. CT approves the separately consented minimal cohort-manager reminder policy with the stated riders; this ruling supplies no implementation or live-provider proof. |
| `AUTH-DEVELOPER-001` | Working integration SDKs and admin API | target | partial | `tests/auth/agents-keys.test.mjs`; `packages/session-sdk/README.md`; `packages/session-sdk/admin.mjs`; `packages/admin-python/README.md`; `packages/hono-sdk/README.md` | Versioned Node and Python administration SDKs and unchanged installed quickstarts prove scoped private-key OAuth, pagination, exact ETags, path confinement and cached-token revocation. The installed Hono quickstart proves employee enrollment, real consent, callback validation, protected API checks, rotation and next-request revocation. Next.js and React, embedded components, full Python employee sessions, authorized organization switching and complete fresh-install browser sign-in and logout journeys remain unproved. |
| `AUTH-ADMINAPI-001` | Admin API credentials for automation | target | partial | `tests/auth/agents-keys.test.mjs` — "admin service apps use private-key OAuth for scoped group and assignment writes; resource, IP, expiry, owner and ETag fences refuse automation while every scope excludes identity and credential custody"; `tests/auth/fresh-proof.test.mjs`; `tests/integration/agents-browser.test.mjs`; `docs/admin-api.md` | Missing a cited journey covering: service-app assignment grant; audit records every call. Existing cited journeys show: service-app group grant; allowed-IP group creation; denied policy scope; denied foreign IP; every excluded action under every scope; expired service app; suspended owner ends app; stale ETag refused. |
| `AUTH-TERRAFORM-001` | Terraform provider | target | partial | `packages/terraform-provider/README.md`; `tests/auth/terraform-provider.test.mjs`; `tests/integration/company-apps-browser.test.mjs`; `tests/integration/helpers/terraform-journey.mjs`; `packages/terraform-provider/internal/provider/provider_test.go` | Local installation and the three native resource types are implemented. Public Terraform Registry publication and signing remain gr-held. People, group rules, OIDC and password apps, attribute mappings, policies, identity providers, domains and automations remain unimplemented provider families. The required conditional-access policy remains AUTH-POLICY-001 device-held and automations remain AUTH-WORKFLOWS-001 account-blocked; the exact-domain provider rule does not replace that policy. Full policy and automation acceptance and public release remain unproved. |
| `AUTH-MOBILE-001` | Native employee and administrator access | target | partial | `src/ui/pages/account.ts`; `tests/integration/browser.test.mjs` | responsive account/admin web exists; native apps, mobile SDKs and launcher do not. |
| `AUTH-EVENTS-001` | Reliable lifecycle events and webhooks | target | partial | `src/auth/events/`; `src/auth/outbound.mjs`; `tests/auth/events.test.mjs` — "joiner, mover and leaver events reach a subscriber signed, in order and once each, through 429, a timeout and an outage; rotation, replay and the cursor rebuild the history"; `COMPANY-APPS.md` | Missing a cited journey covering: no duplicate grants; unresolved work not missing. Existing cited journeys show: subscriber configured; joiner event; mover event; leaver event recovered; 429 preserves event ID; timeout and outage recover; rotation overlaps; old secret stops after overlap; replayed event keeps original identifier; historical cursor reconstructs every event; cursor ordering; versioned rows. |
| `AUTH-FOLLOWUP-001` | Follow-through until access is resolved | target | partial | `tests/auth/provisioning.test.mjs` — "durable follow-up dispatches on the employer business calendar across DST and restart, escalates unresolved revocation and stops on source completion, cancellation and expiry"; `tests/integration/agents-browser.test.mjs`; `docs/follow-up.md` | Missing a cited journey covering: Leave an invitation; a recovery awaiting a distinct administrator's approval; a failed deprovision unresolved across a weekend/DST change; a process restart; Observe due actions; reminders; escalation; including for a legacy policy with no escalation recipient; Complete or cancel each through its normal door; verify reminders cease while the complete history remains. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/followup-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-FOLLOWUP-002` | Role-derived recipients, manage-follow-up authority and early send | target | partial | `tests/auth/provisioning.test.mjs`; `tests/integration/agents-browser.test.mjs`; `tests/integration/helpers/followup-roles-journey.mjs` — "followupRolesJourney"; `docs/follow-up.md` | Missing a cited journey covering: A custom role with 'manage follow-up' saves the policy. Existing cited journeys show: An installation role is refused; The employee receives their own enrollment; recovery reminders; the holding help desk receives its case reminders; A help-desk holder who loses the role escalates; A holder's early send reaches only allowed recipients; a non-holder is refused; All of this runs at 1440; 390. |
| `AUTH-FOLLOWUP-003` | Access-request, review and stale-source obligations | target | done | `tests/auth/provisioning.test.mjs` — "request, review and stale HR obligations retain decider reminders and resolution history across DST and restart"; `tests/integration/directory-browser.test.mjs` — "access decision and review journey: ordinary manager proof, request approval, immutable certification and unfinished removal, and retention controls at 1440 and 390" |  |
| `AUTH-FOLLOWUP-004` | Slack, Teams and Oncall follow-up channels | target | missing |  | Email only; no chat or Oncall adapters (depends on CHAT-001). |
| `AUTH-DELIVERY-001` | Email and SMS delivery operations | target | partial | `tests/auth/notifications.test.mjs`; `tests/integration/security-settings-browser.test.mjs`; `tests/integration/helpers/delivery-journey.mjs`; `docs/mail-delivery.md` | SendGrid native reconciliation, suppression and delivery diagnostics are implemented. Authorized SES and Twilio setup and live enrollment and recovery outcomes remain unproved; live SendGrid delivery and bounce through the shared event relay remain pending account-operator forwarding registration.  Full live credential-free archive qualification remains pending. |
| `AUTH-OPS-001` | Operate a company identity service | target | partial | `AUTH-COMMANDS.md`; `scripts/installer/local.mjs`; `src/auth/keys.mjs`; `tests/integration/dev.test.mjs` | local command/recovery and key operations exist; hosted resilience, SLO measurement, region selection and usage forecasting are missing. |
| `AUTH-RECOVERY-002` | Emergency continuity and recovery drills | target | partial | `tests/auth/security.test.mjs` — "scheduled continuity drill exercises protected lost-factor recovery, upstream outage and expired signing-certificate replacement"; `tests/integration/http.test.mjs`; `tests/auth/provisioning.test.mjs`; `tests/integration/browser.test.mjs`; `docs/continuity-drills.md`; `.github/workflows/continuity.yml` | Missing a cited journey covering: Drill lost phone/key; unavailable upstream; expired signing certificate; restoration of an owner installation through the public account/CLI doors; Confirm ordinary workers cannot invoke emergency authority; cancellation wins against completion where applicable; all notices persist; used credentials cannot be replayed. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/continuity-flow.mjs and tests/integration/continuity-drill.mjs, outside this clause’s old Evidence set. |
| `AUTH-RECOVERY-003` | Same-day help-desk recovery for employees | target | partial | `tests/auth/security.test.mjs`; `tests/auth/recovery-cases-flow.mjs`; `tests/integration/directory-browser.test.mjs` | Manager-session attestation, scoped reset, native session and passkey revocation, digest-only case-bound single-use enrollment, employee and manager email notices, and the native passkey journey are implemented. Closing a case or a later administrator factor reset voids incomplete enrollment requirements; active and expired case links retain their existing gates. Persona or CLEAR qualification requires an authorized test account and consenting subject; remaining push or TOTP verification, temporary access pass and desktop PIN alternatives, real-device revocation, every enrolled-channel notification and live delivery remain unproved. |
| `AUTH-ERASURE-001` | Authorized erasure with retained accountability | target | partial | `tests/auth/provisioning.test.mjs` — "owner erasure previews every store, honors legal holds, anonymizes decisions and keeps refused remote deletion visible"; `tests/integration/http.test.mjs`; `tests/auth/fresh-proof.test.mjs`; `tests/integration/directory-browser.test.mjs`; `docs/erasure.md` | Missing a cited journey covering: query/export all stores; attempt restore of a pre-erasure archive with the later journal; last-owner protection. Existing cited journeys show: Erase a worker with multiple factors; imports; agent grants; SaaS access through the owner door; inspect receipt; anonymized audit; Keep a blocked remote deletion visible; test legal hold. Relevant assertions are in tests/integration/erasure-portability.mjs, outside this clause’s old Evidence set. |
| `AUTH-ERASURE-004` | Protected organization reset and pending-work custody | target | partial | `tests/auth/provisioning.test.mjs` — "app erasure removes connector custody and protected organization reset retains only installation-owner anonymous outcomes and credential-free pending work"; `tests/integration/http.test.mjs`; `tests/auth/fresh-proof.test.mjs`; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile"; `docs/erasure.md` | Missing a cited journey covering: leaving only anonymous receipts/outcomes; Inspect each pending item as installation owner: app; operation; state; outcome are visible; person absent from UI; exports; Retry only previously authorized work through a fresh; deletion instructions; replacement credential are destroyed while the anonymous outcome; Reset a local installation through its protected last-owner door. Existing cited journeys show: Reset an organization; prove its issuer; all former caller authority end; sealed pending work in installation-owner custody; destination identifier are absent from UI; explicitly authorized connection bound to the same remote tenant; without it retain the blocked item; Complete or abandon the item; prove the sealed identifier; installation audit remain. Relevant assertions are in tests/integration/erasure-portability.mjs, outside this clause’s old Evidence set. |
| `AUTH-ERASURE-002` | Per-person erasure across separate organization identities | target | partial | `tests/auth/security.test.mjs`; `tests/integration/directory-browser.test.mjs`; `docs/erasure.md` | CT 23 Oct requires PARTIAL.   Pre-rider receipt payloads with already-destroyed notices cannot reconstruct opaque handles and fail closed. |
| `AUTH-ERASURE-003` | Erasure revokes everything | target | partial | `tests/auth/provisioning.test.mjs`; `tests/auth/oidc-apps.test.mjs`; `tests/auth/agents-proposals.test.mjs`; `tests/integration/http.test.mjs`; `tests/integration/directory-browser.test.mjs`; `docs/erasure.md` | AUTH-TRANSFER-002 receives the unproved assertion that restoring a pre-erasure product export or backup never revives the erased account or any credential, drops erased records and replays the same opaque audit. Product restore currently refuses the whole older archive with a later journal; the required Base staged journal hook is not in released rer 0.2.80. Counts enumerate removed durable credential authorities, not every signed stateless token string. Backups held by the platform operator outside the product are not covered. |
| `AUTH-RETENTION-001` | Explicit retention and secret custody | target | partial | `tests/auth/directory.test.mjs`; `tests/auth/provisioning.test.mjs`; `tests/auth/retention-flow.mjs`; `tests/auth/retention-integrity-flow.mjs`; `docs/retention.md`; `src/auth/retention/index.mjs`; `tests/integration/http.test.mjs`; `tests/integration/erasure-portability.mjs`; `tests/integration/directory-browser.test.mjs` | Eight-class retention, calendar default/bounds, review/request/investigation/legal holds, pre-delete export, restart/concurrent cleanup and authenticated expiry built. |
| `AUTH-RETENTION-002` | Non-identifying terminated-profile expiry | target | partial | `tests/auth/directory.test.mjs`; `tests/auth/provisioning.test.mjs`; `tests/auth/retention-flow.mjs`; `tests/auth/retention-integrity-flow.mjs`; `docs/retention.md`; `src/auth/retention/index.mjs`; `tests/integration/http.test.mjs`; `tests/integration/erasure-portability.mjs`; `tests/integration/directory-browser.test.mjs` | Eight-class retention, calendar default/bounds, review/request/investigation/legal holds, pre-delete export, restart/concurrent cleanup and authenticated expiry built. |
| `AUTH-TRANSFER-002` | Complete workforce portability | target | partial | `scripts/installer/transfer.mjs`; `src/auth/stores.mjs`; `src/auth/links/grant-map.mjs`; `tests/auth/linking.test.mjs`; `tests/integration/http.test.mjs` | Shared portable inventory, credential/session/sealed-work exclusions and the Base whole-older-archive fence are implemented; the actual CLI archive journey passes at `64d257be` in Verify Auth `39703632411`. Complete inactive workforce/grant/job restoration, validation/conflict preview, destination organization schemas and receiving-owner reauthorization remain obligations. Whole-archive refusal is interim and cannot complete AUTH-TRANSFER-002. |
| `AUTH-AGENT-001` | Agent-led SaaS onboarding | push-further | partial | `src/auth/agents/app-kinds.mjs`; `src/auth/agents/approval.mjs`; `tests/auth/agents-proposals.test.mjs` | Under the held company policy for access and security, exact human-approved RER link proposals exist; native SaaS onboarding remains unbuilt. Model access and the held Slack app are available. BLOCKED: the required generic SAML and SCIM SaaS acceptance journey needs an authorized tenant and assigned employee that this run does not hold. Scoped vendor setup, real employee sign-in, provisioning, change and revocation, plus malicious metadata, stale settings and withheld domain-consent readiness proof remain unproved. |
| `AUTH-AGENT-002` | Diagnose and repair broken sign-in | push-further | partial | `tests/auth/agents-proposals.test.mjs` — "the inventory returns only allow-listed fields and no session, passkey, key or token material from a populated store"; `tests/integration/agents-browser.test.mjs`; `docs/agent-diagnostics.md`; `scripts/diagnostic-probe.mjs` | Missing a cited journey covering the whole clause. Under the held company policy for access and security, missing cited journey coverage for: break a callback; expire a certificate; fail recovery mail on separate app journeys; ask the agent to diagnose with source citations; approve a repair; verify end-to-end behavior; deny approval; inject untrusted trace instructions; confirming no configuration or authority changes. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/diagnostic-flow.mjs, outside this clause’s old Evidence set. |
| `AUTH-AGENT-003` | Find orphaned and excessive access | push-further | partial | `src/auth/agents/preparer.mjs`; `src/auth/agents/approval.mjs`; `tests/auth/agents-proposals.test.mjs` | Under the held company policy for access and security, allow-listed inventory and human-approved suspension/domain proposals exist; cross-app usage analysis and regression verification do not. |
| `AUTH-AGENT-004` | Person-bound delegated agent identities | push-further | partial | `tests/auth/agents-proposals.test.mjs` — "a person-consented agent changes exactly one employer assignment after independent employer approval; substitutions, replay and every local ending deny its next request"; `tests/integration/agents-browser.test.mjs`; `docs/delegated-agents.md` | Missing a cited journey covering the whole clause. Under the held company policy for access and security, missing cited journey coverage for: downstream sessions are not claimed revoked. Existing cited journeys show: authorize an agent to update one approved app assignment until a fixed deadline; invoke its target API/MCP tool; inspect attribution; Deny another person; purpose; resource; target; scope; expired grant; replay/substitution; show; revoke the active grant in My account; prove its next request is refused; the native assignment profile requires owner registration of public keys; exact employee/app limits; fresh employee passkey consent; a different legacy owner/admin's hardware/fresh-email passkey approval; the employee; agent custodian; approver are distinct; Immutable purpose; employer; person; agent; target API; deadline bind a single existing direct employee assignment change; At most five-minute target-bound tokens also require one-use signed execution proof; live authority is rechecked at each door; No arbitrary target; new assignment; administrator target; group change or document instruction is accepted; my account revocation ends the next local request; completed changes are not undone. |
| `AUTH-AGENT-007` | Native delegated assignment task profile | push-further | partial | `tests/auth/agents-proposals.test.mjs` — "a person-consented agent changes exactly one employer assignment after independent employer approval; substitutions, replay and every local ending deny its next request"; `tests/integration/agents-browser.test.mjs`; `docs/delegated-agents.md` | Missing a cited journey covering the whole clause. Under the held company policy for access and security, missing cited journey coverage for: says it does not undo a completed change. Existing cited journeys show: The token names the person; the agent (RFC 8693 `act`); the exact change (RFC 9396); it is issued only after the employee's passkey consent; approval by someone who holds that authority; is not the agent's custodian; Revoking in My account stops future use; offers a request to reverse it; The native profile remains restricted to its assignment target. |
| `AUTH-AGENT-005` | Verify revocation everywhere | push-further | partial | `src/auth/links/logout.mjs`; `src/auth/agents/keys.mjs`; `tests/auth/linking.test.mjs`; `tests/auth/agents-keys.test.mjs` | Under the held company policy for access and security, local key revocation and RER fences exist; app-wide delegated-credential inventory and verified remote reconciliation are missing. |
| `AUTH-AGENT-006` | External and MCP delegated task identities | push-further | partial | `tests/auth/agents-proposals.test.mjs` — "registered MCP and external API resources execute one person-consented task; operation, person, scope, audience, replay, expiry and live revocation are enforced at each resource"; `tests/integration/agents-browser.test.mjs`; `docs/delegated-agents.md`; `packages/delegated-resource/index.mjs` | Missing a cited journey covering the whole clause. Under the held company policy for access and security, missing cited journey coverage for: Register a test MCP server; an external API; Authorize one tool; one operation for one person; At each resource; deny an unregistered audience; another tool or operation; scope; person; replay; an expired grant; Revoke in My account; prove the next call is refused. Existing cited journeys show: the old test entry points run their named journeys, but their outcome assertions have not been cited here. Relevant assertions are in tests/auth/external-delegation-flow.mjs, outside this clause’s old Evidence set. |
| `SURFACE-001` | Identity-steward registry | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-002` | Auth classification: standard, external | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-003` | Auth classification: money, commitment | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-004` | Auth classification: accounts, gated | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-005` | Auth classification: access, security | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-006` | Auth classification: destructive, sensitive, live | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-007` | Employer-scoped identity resources | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-008` | Administration and person-bound tasks | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-009` | Identity decisions in the agent overview | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-010` | Identity event handoffs | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-011` | Identity capacity and recovery jobs | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-012` | Identity-steward documentation | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
| `SURFACE-013` | A seeded workforce week through MCP | target | missing |  | Auth has no shared MCP registry, class/policy adapter or conformance proof for these Auth outcomes. |
