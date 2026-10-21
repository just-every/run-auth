# Auth acceptance

Target journeys for the 16 October 2026 workforce identity contract follow. Each paragraph carries the matching clause ID and its implementation status. Use the product’s real UI, HTTP, protocol or CLI doors, real persistence and real cryptography; fakes belong only at external paid/network edges in tests. Integration acceptance additionally needs authorized provider test tenants: synthetic export fixtures do not prove a real cutover or SaaS connector. For each unfinished journey, include success, denied authority and failure/recovery end states. Employee/admin web changes are checked at 1440 and 390 with realistic employer data; native journeys run on iOS and Android. No UI or code is changed in this contract round.

Status starts at main `cdd103e1ceeeedbacf52badf7a51bfc6b18296f6`, the unchanged code-audit revision. `done` is evidence for the bounded retained clause, `partial` has the specific missing part named, and `missing` remains a build target. Referenced test files are existing evidence, not a claim they were all rerun for this document edit. The check guidance and historical implementation/conformance notes below remain applicable. Build round gr-auth-contract-1 (17 October 2026) moved AUTH-SAML-001, AUTH-SCIM-001, AUTH-OIDC-001 and AUTH-EVENTS-001 to done and AUTH-CATALOG-001, AUTH-LAUNCHER-001 and AUTH-MAPPING-001 to partial, with the evidence named in each paragraph.

## Retained identity and RER guarantees

**AUTH-HOST-001 — Issuer host (done).** Choose localhost on fresh setup; repeat with an explicit/saved issuer; enroll a passkey and link an app. Attempt a host move and require a new app-owner approval rather than preserving issuer authority.

Existing evidence and limits: tests/integration/dev.test.mjs; tests/auth/linking.test.mjs; scripts/installer/local.mjs

**AUTH-PRIVACY-001 — Shared claims (done).** Sign in to two linked apps with different granted identity scopes; inspect UserInfo and tokens for only the permitted claims. Add a RER approval key and confirm it grants no user-data access without an ordinary app sign-in.

Existing evidence and limits: src/auth/userinfo.mjs; tests/auth/userinfo.test.mjs; tests/auth/rer-approval.test.mjs

**AUTH-RER-TRUST-001 — RER trust (done).** Link using a correctly signed RER approval, then refuse wrong issuer/origin/key/claim, stale assertion and jti replay. Withdraw trust through both supported doors and prove the key cannot be restored or used again.

Existing evidence and limits: src/auth/links/rer-trust.mjs; src/auth/links/rer-approval.mjs; tests/auth/rer-approval.test.mjs

**AUTH-IDENTITY-001 — Owner and sign-in proof (done).** Through the real email, WebAuthn and administration routes, prove same-browser one-use confirmation, first/additional enrollment, fresh local email step-up rechecked at commit, wrong-session and revoked-session refusal, and approved/delayed/canceled/emergency recovery.

Existing evidence and limits: src/auth/local-email.mjs; src/auth/recovery.mjs; tests/auth/security.test.mjs; tests/auth/fresh-proof.test.mjs; tests/auth/local-email.test.mjs; tests/auth/recovery-cli.test.mjs

**AUTH-PROTOCOL-001 — OpenID Connect profile (done).** A registered RER client completes code/PKCE/private_key_jwt, validates nonce/issuer/audience/pairwise subject, and calls scoped GET/POST UserInfo. Refuse code/assertion replay and inactive client/person/session/grant/policy; test encrypted ES256/RS256 publish-before-use and retirement.

Existing evidence and limits: src/auth/protocol.mjs; src/auth/userinfo.mjs; src/auth/keys.mjs; tests/auth/protocol.test.mjs; tests/auth/userinfo.test.mjs; tests/auth/authorization-policy.test.mjs

**AUTH-BOUNDARY-001 — Private authorization (done).** Request each private page/API signed out, as an email-only member, as a passkey administrator and with revoked authority; deny inherited Base management and production dev tokens. Remove the local dev gate and confirm authority ends.

Existing evidence and limits: src/server.ts; src/auth/index.mjs; tests/integration/http.test.mjs; tests/integration/dev.test.mjs

**AUTH-MOVEIN-001 — Staged move-in (done).** Stage Google, Entra, Auth0, Okta and JumpCloud exports through Move-in, inspect collision/disabled rows, admit selected members without proof/roles/mail, explicitly invite, and undo only untouched admissions. Refuse former Auth0 subjects as credentials and concurrent/stale administrative authority.

Existing evidence and limits: src/auth/move-in/routes.mjs; src/auth/move-in/sources.mjs; tests/auth/move-in-staging.test.mjs; tests/auth/move-in-admission.test.mjs; tests/integration/move-in-browser.test.mjs

**AUTH-ADMIN-001 — Agent preparation (done).** Mint/renew/revoke a preparer key, inspect its allow-listed inventory, file each supported proposal and approve its exact state with a person’s passkey and fresh local email. Prove expiry, stale-state refusal, one winner under concurrent approvals and permanent loss of key authority after administrator removal.

Existing evidence and limits: src/auth/agents/keys.mjs; src/auth/agents/preparer.mjs; src/auth/agents/approval.mjs; tests/auth/agents-keys.test.mjs; tests/auth/agents-proposals.test.mjs; tests/integration/agents-browser.test.mjs

**CMD-001 — Commands (done).** Run real install/setup/dev, start browser sign-in, repeat setup without replacing owner/settings/data, stop the managed process, and generate/redeem local recovery with only a digest in D1 and a mode-0600 raw token file.

Existing evidence and limits: AUTH-COMMANDS.md; scripts/installer/local.mjs; tests/integration/dev.test.mjs; tests/auth/recovery-cli.test.mjs

**HTTP-001 — HTTP surfaces (done).** Call health, Auth APIs and public/private documents through the emitted Worker; confirm identity interception, per-request authorization and an ordinary 404 for unknown routes.

Existing evidence and limits: src/server.ts; tests/integration/http.test.mjs; tests/runtime.mjs

**AUTH-LINK-001 — App links (done).** Use the pull/link-token flow to link a real Base app Worker, sign in, re-link with continuity, and remove it. Refuse mismatched callbacks/origins, replay/concurrent redemption, unauthorized key swap and unapproved downgrade; observe linked-app sessions end on removal.

Existing evidence and limits: src/auth/links/handshake.mjs; src/auth/links/routes.mjs; src/auth/links/versions.mjs; tests/auth/linking.test.mjs; tests/auth/agents-proposals.test.mjs

**AUTH-LOGOUT-001 — Sign-out reach (done).** Sign out everywhere, suspend a person and request RP logout through real Auth/app endpoints; the app rejects the old session and replayed logout tokens. Exercise bounded retries and inspect the persisted delivery outcome; discovery advertises the supported endpoints.

Existing evidence and limits: src/auth/links/logout.mjs; src/auth/links/end-session.mjs; tests/auth/linking.test.mjs; tests/auth/protocol.test.mjs

**AUTH-TRANSFER-001 — Export and import (done).** Export a populated installation, import into an empty installation at the same host, and re-link the app with unchanged client/sector/pairwise subject. Inspect retained records and absent authority; refuse incompatible origins and active dev personas.

Existing evidence and limits: scripts/installer/transfer.mjs; src/auth/links/grant-map.mjs; tests/auth/linking.test.mjs

## Target clauses

### The workforce directory and employee experience

**AUTH-DIRECTORY-001 — One workforce directory (done).** In People/API, onboard a W-2 employee and a contractor, rename and transfer one, preview a bulk edit, evaluate dynamic groups, suspend and rehire; verify stable identifiers, explicit source conflicts and resulting assignments without duplicate accounts.

Existing evidence and limits: src/auth/workforce/people/; tests/auth/directory.test.mjs; tests/integration/directory-browser.test.mjs — exact semantic: a person's values are kept per source (an administrator's override, the HR system, the directory feed, the employee) and the highest ranked wins; sources identify people by their own immutable id, never by email; states are invited, active, suspended, terminated, and rehire keeps the person id; groups are static or follow a rule over effective values, with manual members, explicit exclusions and owners; every edit, single or bulk, meets one planner and audit, and a bulk edit applies only against its exact preview. AUTH-ADMINAPI-001 credentials, AUTH-HRIS-001 and AUTH-SCIM-002 sources, AUTH-LIFECYCLE-001 plans and AUTH-ROLES-001 scopes inherit that planner (`directory/preview`, `directory/apply`, `directory/source`).

**AUTH-TENANCY-001 — Organizations and delegated administration (partial).** Invite a contractor into two employers, switch organization, delegate one app to an app administrator and one recovery case to help desk; deny cross-organization reads/writes/exports and unauthorized role escalation, including direct API requests.

Existing evidence and limits: src/auth/admin.mjs; src/auth/index.mjs; tests/integration/http.test.mjs — installation owner/admin/member permissions exist; organization isolation and scoped roles are missing.

**AUTH-ROLES-001 — Custom administrator roles and resource sets (partial).** Create a help-desk role with "reset factors" over group A and view-only over group B. As its holder, reset a factor for a person in A; be refused editing in B (view succeeds), refused on an administrator in A, and refused via direct API and export. Attempt to grant the role over a wider set and be refused; change group A's membership and observe the next decision follow it.

Existing evidence and limits: src/auth/admin.mjs; tests/auth/agents-proposals.test.mjs; tests/auth/fresh-proof.test.mjs — fixed owner/admin/member roles with owner-only actions and refusal to change, demote or suspend the owner exist; custom roles, resource sets and separate view/edit scope are missing.

**AUTH-DOMAINS-001 — Verified employer domains (partial).** Claim a domain through the admin setup door, fail an incorrect/expired challenge and competing claim, then enroll and route an eligible worker. Revoke domain ownership and confirm policy reevaluation and audited recovery access.

Existing evidence and limits: src/auth/domain-policy.mjs; src/auth/admin.mjs; tests/auth/upstreams.test.mjs — exact-domain enrollment/required-provider rules exist; domain ownership verification does not.

**AUTH-PROFILE-001 — Profiles and safe identity linking (done).** Edit an employee profile and protected HR field, connect a second proven upstream and then unlink it; refuse an email collision, foreign subject, concurrent binding and last usable sign-in removal. Inspect app claims for only consented fields.

Existing evidence and limits: src/auth/profiles/; src/auth/upstreams.mjs; src/auth/userinfo.mjs; tests/auth/profile.test.mjs; tests/auth/upstreams.test.mjs; tests/integration/directory-browser.test.mjs — exact semantic: connecting is for the signed-in account (this session with a fresh local email proof, one explicit confirmation, then the provider's verified response), is single use, binds one identity per provider and refuses an address that is another person's, a subject bound elsewhere and a replay; disconnecting refuses the last usable sign-in (a required provider is the only way in for everyone but the owner). Sign-in at a provider continues to admit by the provider-verified address under domain policy (AUTH-FEDERATION-001). GitHub, Apple and generic OIDC/SAML adapters (AUTH-SOCIAL-001, AUTH-FEDERATION-001) inherit this link door.

**AUTH-ENROLLMENT-001 — Managed enrollment and password compatibility (partial).** Enroll an invited employee and an approved-domain self-registrant, reject an outside address, complete a password reset under AUTH-PASSWORD-002 and a one-use SMS/email challenge, and prove weaker methods cannot administer or bypass required MFA. Cancel enrollment and verify its outstanding links stop.

Existing evidence and limits: src/auth/email.mjs; src/auth/passkeys.mjs; tests/auth/security.test.mjs; tests/auth/registration.test.mjs — email/domain enrollment and passkeys exist; passwords and SMS do not.

**AUTH-PASSWORD-001 — Password policy per group (missing).** Assign a policy of length 12, history 24, minimum age 1 hour and lockout at 10 attempts to group A, and a policy of length 16 with symbols required and a 90-day maximum age with a 14-day warning to group B; preview the affected people. Through the web change door and a RADIUS sign-in, refuse for a person in A each of: 11 characters, a password from their history, a second change within the hour, a password containing their last name, a block-list word and a breached password; refuse a password without a symbol for B. Fail 10 attempts for A's person across web and RADIUS and see the password locked while passkey sign-in still succeeds; self-unlock under AUTH-PASSWORD-002. Age B's person's password into the warning window and past expiry, and see the warning at each surface and the forced change. Move the person from A to B and see B's rules at their next change.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-PASSWORD-002 — Self-service password reset, unlock and propagation (missing).** For a person in group A with Auth push enrolled, reset a forgotten password through self-service with push, and be refused when offering email alone; unlock a locked password the same way. Within 60 seconds see the new password accepted and the old one refused at GlobalProtect RADIUS, an LDAPS bind, the WS-Trust endpoint and the Mac login in password-sync mode, and read the written-back password's change time from AD. Take the AD connector offline during a reset and see AD pending until it returns. Request a reset for an unknown address and receive the same response as for a known one; refuse a self-service reset by email alone for an administrator.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-ONBOARD-001 — New-hire activation before the start date (partial).** From an HR test source, add a hire starting in 10 days with a 7-day lead time; see no invitation until 7 days before start, then the invitation at the HR personal address. Enroll a passkey and push before start; be refused app launch and token issuance until the start time, then launch. Let a second hire's link expire, reissue it and refuse the old link. Move a start date earlier and later and see the gate follow; rescind an offer and see the enrollment revoked. Confirm no message reaches the personal address after start except enabled recovery notices.

Existing evidence and limits: src/auth/admin.mjs; src/auth/email.mjs; tests/integration/browser.test.mjs — administrators invite a person at an email address, and the invitation becomes active when that person signs in with email proof, after which they can enroll a passkey; HR-sourced personal-email invitations, lead time, expiring single-use activation links and start-time gating are missing.

**AUTH-TAP-001 — Temporary access pass (missing).** As help desk scoped to a new hire's group, record manager attestation and issue a pass. At a fresh Mac's login window (Platform SSO) and at a fresh Windows PC, sign in with it, create the local account and enroll a passkey. Refuse the pass on reuse, after expiry, at an app launch, at app MFA step-up and at GlobalProtect RADIUS. Refuse issuance without a recorded verification, outside the issuer's scope and for an administrator. Inspect the audit trail and the notices.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-EXPERIENCE-001 — Hosted and embedded identity journeys (partial).** Configure branding and an employee journey, use both hosted and embedded account/membership screens, preview a changed MFA step and roll it back. At 1440 and 390, in light/dark with keyboard and assistive technology, complete sign-in/recovery and expose durable errors without leaking hidden fields.

Existing evidence and limits: src/ui/pages/signin.ts; src/ui/pages/account.ts; tests/integration/browser.test.mjs — hosted responsive pages exist; branding controls, embedded components and journey orchestration are missing.

**AUTH-LOCALE-001 — End-user display languages (missing).** Set a person's language to Spanish and complete activation, sign-in, push approval with number matching, password reset, the launcher, an extension fill and the Mac login window entirely in Spanish; receive the new-device and password-changed notices in Spanish. On the sign-in page switch to Arabic and complete sign-in at 390 in right-to-left layout. Leave an employer notification template in English only and see the English fallback used and flagged in preview. A build check fails when any end-user string key is missing from a supported language.

Existing evidence and limits: src/ui/shell.ts; src/ui/pages/signin.ts — every page renders English only (`lang="en"`); language selection, translations and per-language employer text are missing.

**AUTH-LAUNCHER-001 — Employee app launcher (partial).** As an employee with Google Workspace, Slack, AWS, a password-only app and a RER app assigned, launch each into its proper account. Request an unassigned app, remove an assignment and expire a temporary grant; the dashboard, the extension and direct launch all enforce the changed access. Assign a bookmark tile to a group and see it only for members.

Existing evidence and limits: src/auth/workforce/directory.mjs; src/ui/pages/company-apps.ts; tests/auth/saml.test.mjs; tests/integration/company-apps-browser.test.mjs — My account lists each person's assigned SAML and OpenID Connect company apps with an Auth launch (IdP-initiated) or the app's own sign-in; unassigned people get no assertion or code. Missing: search, favorites, recent, access-request actions, explanations of blocked tiles, bookmark tiles, password-based and RER apps.

**AUTH-SWA-001 — Password-based app sign-in (missing).** Install the extension in each of the four browsers, and force-install it preconfigured through Intune on Windows and Jamf Pro on macOS, assign a shared-credential and an individual-credential app, sign in from the launcher and by direct visit, generate a password and refuse fill on a lookalike origin. Unassign one employee and offboard another; their next fill is refused within 60 seconds, the shared password is rotated, and the audit shows every reveal, fill and rotation without the secret. Import an Okta SWA app definition and launch it.

Existing evidence and limits: No implementing product path or acceptance test yet.

### Authentication, SSO and policy

**AUTH-MFA-001 — Passkey-first multifactor policy (partial).** Enroll a platform passkey, hardware key, Auth push and TOTP, require step-up for a sensitive app, revoke a lost factor and consume a recovery code once. Deny downgraded admin access and prove factor removal/rotation reaches current sessions according to policy.

Existing evidence and limits: src/auth/passkeys.mjs; src/auth/local-email.mjs; tests/auth/security.test.mjs; tests/auth/local-email.test.mjs — hardware passkeys and local email step-up exist; configurable factor policy/TOTP/recovery codes do not.

**AUTH-AUTHENTICATOR-001 — Push authenticator in the Auth mobile app (missing).** On real iOS and Android builds, enroll the authenticator, approve a web sign-in with number matching, deny another and see it refused and reported, and complete a sign-in with the app's offline TOTP. Replay an approval, answer after expiry and answer from a second unenrolled device; each is refused. Send repeated pushes and observe the fatigue control; remove the device and prove its next approval is refused.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-POLICY-001 — Conditional access and session policy (partial).** Preview and publish a payroll-app rule requiring a managed US device and fresh passkey; attempt allowed, foreign-network, stale-posture and expired-session launches through app and direct protocol routes. Add an AUTH-RISK-001 "step up on new country" condition and see a new-country sign-in stepped up with the signal named in the decision. Change group/policy during sign-in and verify the current decision at token issuance.

Existing evidence and limits: src/auth/domain-policy.mjs; src/auth/authorization-login.mjs; tests/auth/authorization-policy.test.mjs; tests/auth/upstreams.test.mjs — current domain, session and prompt/max-age checks exist; general device/location/risk engine is missing.

**AUTH-ABUSE-001 — Automated attack protection (partial).** Attack real authentication/reset/token HTTP doors with bot traffic, password spraying, a breached password and distributed source attempts; observe rate limits/lockouts, protected notifications and legitimate recovery. Sign in through a Tor exit and from a location implying impossible travel, and verify step-up or denial with the AUTH-RISK-001 signal named in an explainable log.

Existing evidence and limits: src/auth/email.mjs; src/auth/core.mjs; tests/auth/security.test.mjs — address/IP email throttling exists; configurable bot, password and adaptive attack controls are absent.

**AUTH-RISK-001 — Named sign-in behavior signals (missing).** Publish "step up on new country, allow new city, deny Tor" for a group. Sign in from a known location and pass; from a new US city and pass with "new city" logged; from a new country and be stepped up; from a location implying 900 km/h travel since the previous sign-in and be stepped up with velocity logged; through a Tor exit and be denied. Change the radius and look-back and see the next decision follow them. Each decision log names the signal, its value and the feed version. Simulate the draft rule over 30 days of history and see per-signal counts.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-NOTIFY-001 — Employee security notifications and suspicious-activity reports (partial).** Sign in from a new browser and receive the new-device email with its stated context. Enroll a factor, have help desk reset a factor and change a password, and receive each notification. From the new-device email, while signed out, click "Report suspicious activity": see the security owner's escalation in Slack and, under the end-sessions policy, the person's sessions ended and a linked app's back-channel logout delivered. Refuse the report link's reuse and use after expiry. Turn off new-device notices and receive none; try to turn off recovery notices and be refused.

Existing evidence and limits: src/auth/recovery.mjs; tests/auth/security.test.mjs — a cancelable recovery-requested notice is posted to each of the person's active sessions; email/push notifications for the other named events and the suspicious-activity report are missing.

**AUTH-LOGOUT-002 — Universal logout from connected SaaS for a compromised account (partial).** In authorized Google Workspace, Microsoft 365, Slack Enterprise Grid, Zoom and Salesforce test tenants, sign a person in to each through Auth on the web and in each vendor's desktop or mobile client. From a new-device notice, report suspicious activity under the end-sessions policy: within 60 seconds the person's Auth sessions and a linked app's session end; within 5 minutes each vendor's API shows the sessions or tokens revoked, and each web and client session is refused at its next request, while the person stays active and signs in again with a passkey. Repeat from help desk's End all sessions action and be refused outside the holder's scope. An app with no revocation API is shown as unsupported with its manual step, and a vendor failure stays an open obligation.

Existing evidence and limits: src/auth/links/logout.mjs; src/auth/index.mjs; tests/auth/linking.test.mjs — Sign out everywhere ends the person's own Auth sessions and signs them out of linked RER apps by back-channel logout; ending another person's sessions, report and risk triggers, and vendor-API revocation in SaaS apps are missing.

**AUTH-SAML-001 — SAML 2.0 workforce identity provider (done).** Configure a generic SAML SP through the admin door, launch as an assigned employee over each binding, validate mapped role/NameID in each of the four formats, sign the response, the assertion and both with SHA-256 and SHA-512, decrypt an encrypted assertion with each named algorithm at the SP, and roll certificates with overlap. Complete SP- and IdP-initiated logout over both bindings. Refuse a forged request, altered ACS, wrong audience, SHA-1 without an exception, stale/replayed assertion and unassigned user.

Existing evidence and limits: src/auth/saml/; src/auth/workforce/routes.mjs; tests/auth/saml.test.mjs; tests/integration/company-apps-browser.test.mjs — an independent SAML service provider library (node-saml with xml-crypto and xml-encryption) validates every response: SP- and IdP-initiated sign-in, Redirect and POST bindings, the four NameID formats, response/assertion/both signatures with RSA-SHA256 and RSA-SHA512, AES-256-GCM and AES-128-CBC encryption with RSA-OAEP, SP- and IdP-initiated single logout over both bindings, certificate rollover with overlap, and refusal of forged, SHA-1 without the named exception, replayed, stale, misaddressed and unassigned requests. Limits: attributes map from fixed directory sources (AUTH-MAPPING-001 is the expression language); metadata is pasted, not fetched by URL; RequestedAuthnContext is not interpreted.

**AUTH-OIDC-001 — General SaaS OIDC and OAuth profiles (done).** Register confidential SaaS clients with each of `client_secret_basic`, `client_secret_post` and `private_key_jwt`, and a public native client with `none` plus PKCE, through the catalog/API; complete code flows and logout for each and rotate a secret with overlap. Refuse a wrong or rotated-out secret, a public client without PKCE, redirect substitution, token substitution, code replay and unsupported grants. Re-run the strict RER journey unchanged and inspect each connection’s advertised profile.

Existing evidence and limits: src/auth/oidc-apps/; src/auth/protocol.mjs; src/auth/links/end-session.mjs; tests/auth/oidc-apps.test.mjs; tests/integration/company-apps-browser.test.mjs; COMPANY-APPS.md — openid-client (a certified relying party library) completes the code flow with client_secret_basic, client_secret_post, private_key_jwt and a public native client with none and PKCE, reads UserInfo, validates the opt-in implicit and hybrid flows, and follows RP-initiated logout with front-channel frames and signed back-channel logout tokens; secrets are 256-bit, shown once, stored as digests and rotated with an overlap; wrong, mismatched and rotated-out secrets, public clients without PKCE, redirect and code substitution, code replay, unsupported grants and unassigned people are refused; per-app pairwise or public subjects and mapped claims; the strict RER profile and its tests are unchanged apart from discovery listing the general methods and the fragment response mode. Limit: a fresh install signs only with keys published five minutes earlier.

**AUTH-MAPPING-001 — Attribute and NameID transform language (partial).** Through the app setup door, map NameID to a computed `first.last` value with a collision suffix, map a role from group membership and push a formatted date over SCIM; preview against three people including one with a missing field, then launch and provision and read the values back at the SP and SCIM service. Refuse an expression that reads a secret, calls out or exceeds the time bound; roll back to the previous version.

Existing evidence and limits: src/auth/saml/apps.mjs; src/auth/saml/assertion.mjs; tests/auth/saml.test.mjs — per-app SAML attributes map from fixed directory sources (email, name, first/last name, person ID, app role, groups) and the NameID source is selectable. Missing: the versioned expression language, preview against chosen people and SCIM attribute transforms.

### SaaS, directories and workforce lifecycle

**AUTH-CATALOG-001 — Production SaaS application catalog (partial).** For each of the seven named services, an authorized US test tenant connects from catalog, assigns a test group/role, creates or binds the correct account, launches SSO, changes role and offboards it; read back remote state and document any external-session limit. Inject one provider denial and prove it remains unresolved.

Existing evidence and limits: src/auth/catalog/recipes.mjs; tests/auth/catalog.test.mjs — Google Workspace, Microsoft 365, Slack, GitHub Enterprise Cloud, AWS IAM Identity Center, Salesforce and Zoom recipes fill a working SAML app and, for the SCIM vendors, a provisioning connector, and state edition, permissions, roles, attributes, test-user procedure, certificate rotation and session limits. Missing: every authorized vendor-tenant journey (needs accounts), the Google Directory API and Microsoft Graph provisioning adapters, and Zoom's client-credentials token refresh.

**AUTH-CATALOG-002 — Catalog breadth and verification cadence (missing).** The catalog door lists at least 100 recipes, every one named above among them, each with protocol tags and a last-verified date within 90 days. A random sample of 10 recipes, drawn by the test run, each passes AUTH-CATALOG-001's connect/assign/launch/role-change/offboard journey with remote state read back. Age one recipe past its date and see it marked stale at the catalog and at activation.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-M365-001 — Microsoft 365 domain federation and licensing (missing).** In an authorized Microsoft 365 test tenant, federate a verified domain in a staged-rollout group, then fully; sign in with each client in the matrix and inspect the ImmutableID and IDPEmail claims. Roll back to managed and sign in again. Add a person to a licensing group and see the SKU assigned, remove them and offboard another, and see each license reclaimed in Microsoft's admin data; a client that fails is shown as a failed matrix row, never omitted.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-SCIM-001 — Outbound provisioning and deprovisioning (done).** Assign a group through admin UI/API to a real SCIM service, provision users/groups, change a role and email, then revoke while the provider returns 429/503 and later recovers. Inspect one account per person, persisted per-app outcomes with dispatch and verification times inside the bounds while healthy, no duplicate side effect and verified deactivation rather than a green queue submission.

Existing evidence and limits: src/auth/provisioning/; src/auth/workforce/; tests/auth/provisioning.test.mjs; tests/auth/scim-server.mjs (the SCIM service at the network edge) — group and person assignments create, update (role), deactivate/delete and reactivate users and push groups; preview of attribute, role and destructive effects; credential sealed, tested and rotated; adoption only by Auth's external ID, a name collision held for an administrator's decision; 429 with Retry-After, 503 and a lost response retried without a duplicate account; paged reconciliation of remote drift; per-app obligations with event, dispatch and remote-verified times, unverified past 15 minutes flagged; suspension denies locally first. Limit: an email change travels the same update path (AUTH-DIRECTORY-001 edit door).

**AUTH-SCIM-002 — Inbound directory synchronization (partial).** Connect each named directory and a generic SCIM client through setup, import paginated users/groups, apply a mover and deactivate a leaver. Send a foreign-tenant request, duplicate event and incomplete/full-empty snapshot; verify isolation, stable IDs and a held destructive change pending confirmation.

Existing evidence and limits: src/auth/upstreams.mjs; src/auth/move-in/sources.mjs; tests/auth/upstreams.test.mjs; tests/auth/move-in-staging.test.mjs — upstream OIDC and staged exports exist; continuous SCIM/directory reconciliation is missing.

**AUTH-HRIS-001 — HR-driven identity sources (missing).** Connect each of the ten named HR sources in an authorized tenant; synchronize a future hire, US employment start, department/manager move, scheduled termination and rehire, and measure each change's arrival against its event or polling bound. Exercise DST/timezone effective times, conflicting sources, duplicate/out-of-order events and a stale feed; verify resulting access and unresolved source errors.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-HRIS-002 — Scheduled HR file feeds (missing).** Configure an SFTP feed with a mapping, deliver a file with a hire, a move and a termination and see the preview and resulting access; deliver a malformed file, an empty file and one terminating 20% of workers and see each held; skip a delivery and see the stale flag and follow-up. Refuse a wrong SFTP key and a file for another employer.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-LIFECYCLE-001 — Complete joiner, mover and leaver execution (partial).** From HR/admin doors, onboard a sales hire across Workspace, Slack and Salesforce, move them to engineering/GitHub, then terminate while one provider is unavailable. Restart the worker, inspect deadlines and approvals, restore the provider and confirm each remote outcome with its timestamps; local access must remain denied throughout.

Existing evidence and limits: src/auth/admin.mjs; src/auth/links/logout.mjs; tests/auth/linking.test.mjs — manual invitations, suspension and RER fences exist; multi-app HR-driven execution is missing.

**AUTH-TIMING-001 — Measured lifecycle time bounds (partial).** With healthy connectors to three SaaS test tenants, terminate a person and measure: local refusal on every door and logout delivery within 60 seconds, dispatch within 60 seconds and remote verification within 5 minutes per app. Hold one connector down past 15 minutes and see the escalation; add a future hire and see verified accounts before 06:00 local on the start date. Export the timeliness report for the period and reconcile each row's four timestamps with the audit trail.

Existing evidence and limits: src/auth/admin.mjs; src/auth/links/logout.mjs; src/auth/provisioning/obligations.mjs; tests/auth/security.test.mjs; tests/auth/linking.test.mjs; tests/auth/provisioning.test.mjs — suspension denies Auth sessions at once and starts signed RER back-channel logout with bounded retries; each SCIM obligation records event, dispatch and remote-verified times and is flagged unverified past 15 minutes. Missing: source and joiner bounds, the 24-hour reconciliation of every source, and the timeliness report.

**AUTH-WORKFLOWS-001 — Employer-built identity automations (missing).** In authorized Google Workspace and Microsoft 365 test tenants, enable the leaver templates and terminate a person through HR: read back Drive files owned by the manager, the transferred calendar, the Gmail auto-reply and delegate, the shared mailbox with manager access and every reclaimed license. Dry-run an edited automation and see no remote change; fail one step and see it held as an unresolved obligation in the person's plan; refuse a step outside the automation's granted scope. Call a generic REST endpoint with stored OAuth client credentials and use its response in a later step; refuse an HTTP step aimed at a private address.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-FEDERATION-001 — Generic upstream federation (partial).** Through delegated setup, connect generic SAML/OIDC plus the three named providers, sign in to an assigned downstream app and rotate upstream keys. Refuse an email-only collision, replay, changed issuer/configuration, malicious metadata URL and foreign organization setup; simulate upstream outage and use approved recovery.

Existing evidence and limits: src/auth/upstreams.mjs; src/auth/domain-policy.mjs; tests/auth/upstreams.test.mjs — Google/Microsoft/Okta OIDC presets exist; generic OIDC, SAML and self-service setup are missing.

**AUTH-SOCIAL-001 — Controlled external identity sign-in (partial).** Configure each adapter with a real provider app, sign in an invited contractor, exercise private/changed email and unlink/relink, then withdraw employer permission. Refuse a same-email unproven identity and observe immediate policy denial on further token issuance.

Existing evidence and limits: src/auth/upstreams.mjs; tests/auth/upstreams.test.mjs — Google OIDC is exercised; GitHub and Apple adapters are missing.

**AUTH-LEGACY-001 — LDAP, Active Directory and RADIUS access (missing).** Install the real private connector. Sign in to GlobalProtect through RADIUS with password plus push and with password plus TOTP; deny the push and let one time out, and each sign-in is refused. Join Meraki Wi-Fi with EAP-TLS and with EAP-TTLS plus push, bind an LDAPS app, and exercise each AD direction (source import, delegated authentication, password write-back, group push). Disable the employee, rotate trust and disconnect the connector; prove new access stops within AUTH-TIMING-001's leaver bound and unresolved external sessions remain visible.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-DEVICE-001 — Device identity and trust (missing).** Enroll one device per supported desktop OS and an iPhone and an Android phone, and read posture from each named management service; launch from a jailbroken or rooted phone and from one below the required OS version and be denied. Launch an app, stale the posture, mark a device noncompliant and revoke it; verify policy denial, trust removal and an auditable employee/help-desk recovery path.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-DESKTOP-001 — Sign in to the computer with company identity (missing).** On a managed Mac and Windows PC, sign in at the OS login with company identity using push, TOTP and a security key; on the Mac exercise both password-sync and Secure Enclave modes. Sign in offline within and beyond the cached period. Lock an employee out and restore them with a help-desk recovery PIN, then refuse the PIN's reuse and its use after an hour. Offboard the employee and see the next online login and unlock refused. On a domain-joined Windows PC, open the launcher and be signed in by Kerberos, then be stepped up where policy requires.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-GATEWAY-001 — On-premises web apps through an access gateway (missing).** Deploy the gateway on a private network with no inbound port and publish a header-based test app and an IIS app using Kerberos constrained delegation. Launch both as an assigned employee and read the identity headers and Kerberos identity at each app. Send a forged identity header and see it stripped; deny an unassigned employee and a path-level rule; offboard the employee and see the next request refused within 60 seconds.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-PRIVILEGED-001 — Server and SSH access without standing keys (missing).** Enroll two Linux servers (one with the agent, one with only the CA key) and one Windows server. As an engineer in a server group, sign in with a passkey, obtain a certificate and SSH in; RDP to the Windows server through the gateway. Be refused sudo until a time-bound request is approved, then gain it and see it expire. Refuse a server outside the person's groups, an expired certificate and an unassigned engineer. Offboard the engineer and see the next connection refused and the local account removed; the audit shows each session.

Existing evidence and limits: No implementing product path or acceptance test yet.

### Access governance and application authorization

**AUTH-GRANTS-001 — App roles, APIs and service identities (partial).** Register an API, map a group to read/write and resource-level permissions, and call it as an employee and a service identity. Deny an unassigned role, cross-employer resource, wrong audience, excessive scope and revoked service credential; role removal must change the next authorization decision.

Existing evidence and limits: src/auth/links/routes.mjs; src/auth/protocol.mjs; tests/auth/userinfo.test.mjs — client registration and identity scopes exist; app RBAC, API permissions, fine-grained checks and client credentials are missing.

**AUTH-TOKENS-001 — Refresh and delegated session lifecycle (missing).** Use a native SDK to obtain an approved refresh grant, rotate it, replay an old token and revoke the family through My account. Run concurrent refresh, expiry, suspension and app removal, confirming the resource API refuses invalid authority and strict RER clients receive no refresh token.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-HOOKS-001 — Inline hooks for custom sign-in logic (missing).** Register a token hook that adds a cost-center claim and see it in the ID token; a registration hook that denies an outside domain; and a hook that tries to add an administrator role and change the subject, and see both changes refused. Let a fail-closed hook time out and see the sign-in refused with a clear error, then a fail-open hook time out and see sign-in continue with the event logged. Refuse a hook URL that resolves to a private address.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-REQUESTS-001 — Access requests and time-bound grants (missing).** Request Salesforce access and temporary AWS elevation from the launcher, have the required independent people approve, provision only those roles, and let the grant expire while a connector fails. Reject self/stale/concurrent approvals and verify revocation/escalation before closing the request.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-REVIEWS-001 — Periodic access certification (missing).** Start a quarterly review of employee, contractor and service-account access, delegate one reviewer, certify one role and revoke another. Change membership mid-review, miss a deadline and fail a provider removal; inspect immutable snapshot, new drift and an export whose completion cannot conceal unfinished remediation.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-DECISIONS-001 — Proof levels for administration and everyday decisions (missing).** As a manager with an employee passkey and no local email confirmation, approve a Salesforce request, edit a non-privileged group as its owner, and certify access in a review; each commits after step-up. Attempt to approve a request for an administrator role, edit a privileged group and approve an administrator's recovery with the same proof; each is refused until the administrator gate is satisfied. Approve a stale request and one the decider lost authority over between view and commit; both are refused.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-CHAT-001 — Approve, deny and certify from Slack and Microsoft Teams (missing).** In authorized Slack and Teams test workspaces, bind a manager, approve one request and deny another from each, certify a review item, and see the outcomes provisioned and audited. Refuse an action from an unbound chat account, one bound to a different person, a stale or already-decided request and a removed binding; a privileged-role request offers only the web link.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-AUDIT-001 — Identity investigation and reporting (partial).** Investigate an employee’s failed sign-in through its policy decision and provisioning history, export a review period to each named sink/Evidence, and reconcile the AUTH-REPORTS-001 MFA-enrollment export for one employer row by row with its directory, with every person who has no factor present and marked non-compliant. Query an event 12 months old through the log API on a default installation. Reconcile event counts across pages, detect tampering/gaps, deny an auditor’s write attempt and prove erased subjects no longer disclose personal identifiers.

Existing evidence and limits: src/auth/core.mjs; src/auth/admin.mjs; scripts/installer/transfer.mjs; tests/auth/agents-proposals.test.mjs; tests/integration/browser.test.mjs — Activity and portable history exist; reporting, streams, tamper evidence and anonymization are missing.

**AUTH-REPORTS-001 — Named per-person identity reports (partial).** With 20 people (15 with a passkey or push, 3 with only a password, 2 with no factor), export the MFA-enrollment report and reconcile it row by row with the directory: all 20 rows are present and the 5 non-compliant people are marked. Terminate two people, one while a connector is held down, export the terminated-people report and reconcile each row's local-denial and full-deprovision times with the AUTH-TIMING-001 audit; the held app is named. Grant and revoke a custom administrator role and see the administrators report follow; age a person past 90 days without sign-in and see them on the dormant report. Refuse export to a role without export rights. Each export's row count equals the directory count for its filter at its as-of time.

Existing evidence and limits: src/auth/admin.mjs; src/ui/pages/people.ts; tests/integration/browser.test.mjs — People lists every person with role (owner, admin, member) and status for administrators; per-person factor, termination-time and dormant reports, filters, schedules and export are missing.

**AUTH-COMPLIANCE-001 — Identity-provider connectors for compliance platforms (missing).** In an authorized Vanta test tenant, connect Auth through the private integration: Vanta's accounts page shows every Auth person in scope with the correct status, MFA status and factor types, and a custom MFA test passes. Remove one person's last factor and see the test fail within one sync; offboard another and see them in Vanta's offboarding queue within one sync. Scope by an Auth group and see Vanta's scope follow a membership change. Repeat in a Drata test tenant and see "MFA on Identity Provider" pass and then fail the same way. Configure the Secureframe and Thoropass recipes in authorized test accounts and see each person's MFA status. Revoke the Vanta credential and see the connector unhealthy, with a follow-up raised, within two hours.

Existing evidence and limits: No implementing product path or acceptance test yet.

### Migration, integration and operations

**AUTH-MIGRATION-001 — Switch from Okta, Entra ID or JumpCloud (partial).** For Okta Workforce Identity, Microsoft Entra ID and JumpCloud separately, migrate a populated authorized test tenant with groups, apps, a collision, suspended worker and privileged assignment. Pilot a cohort, re-enroll factors through the AUTH-MIGRATION-003 campaign, compare counts/permissions, roll back and cut over; prove old subjects cannot act as credentials and no app is silently omitted. With Vanta and Drata connected to the incumbent, see both listed with AUTH-COMPLIANCE-001 as their replacement, and cutover held until each replacement's first sync succeeds.

Existing evidence and limits: src/auth/move-in/sources.mjs; src/auth/move-in/routes.mjs; tests/auth/move-in-staging.test.mjs; tests/auth/move-in-admission.test.mjs — user-export staging/admission exists for all three; full configuration/group/app migration and live cutover are missing.

**AUTH-MIGRATION-002 — Custom-directory and progressive move-in (partial).** Import Google and Auth0 records, migrate one eligible legacy worker at first login through the real bridge, and compare downstream subject mapping before/after. Refuse a wrong password, email collision and disabled worker; interrupt migration and prove an idempotent outcome and a cleanly disabled bridge.

Existing evidence and limits: src/auth/move-in/sources.mjs; tests/auth/move-in-staging.test.mjs; tests/auth/move-in-admission.test.mjs — Google/Auth0 staged imports exist; first-login database migration does not.

**AUTH-MIGRATION-003 — Cutover enrollment campaign (partial).** In an authorized Okta test tenant with 20 staged employees, run a campaign: all 20 enroll through Okta-federated proof with no help-desk action while the dashboard counts down. Leave 3 unenrolled and see them named as overdue with manager reminders and in the export. Refuse a person whose email matches but whose Okta subject differs, an unstaged person, proof after the campaign window and campaign proof for an administrator. Bridge one employee's Okta password and sign in with it at RADIUS after cutover. Repeat the enrollment proof with Entra ID and JumpCloud as upstreams.

Existing evidence and limits: src/auth/upstreams.mjs; src/auth/move-in/routes.mjs; tests/auth/upstreams.test.mjs; tests/auth/move-in-admission.test.mjs — Okta, Microsoft and Google OIDC upstream sign-in with configured subject association and staged move-in admission exist; the campaign window, enrollment dashboard, reminders, JumpCloud/SAML upstreams and the Okta password bridge are missing.

**AUTH-DEVELOPER-001 — Working integration SDKs and admin API (partial).** Build and run each framework quickstart against a fresh Auth install; enroll an employee, sign in, verify a protected API, switch an authorized organization, revoke access and observe logout. Follow the docs from an empty app and diagnose a deliberately wrong redirect without hand-editing SDK internals.

Existing evidence and limits: LINKING.md; src/auth/protocol.mjs; tests/auth/linking.test.mjs — RER link documentation and Worker integration exist; named framework SDKs/components/quickstarts are missing.

**AUTH-ADMINAPI-001 — Admin API credentials for automation (missing).** Create a service app with `groups.manage` and `assignments.manage` from an allowed IP, call the API to create a group and assign an app; call a policy endpoint and from another IP and be refused; attempt each excluded action with every scope and be refused. Expire the app, suspend its owner, and replay a stale ETag; each is refused or suspended as stated, and the audit shows every call.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-TERRAFORM-001 — Terraform provider (missing).** Against a fresh install, `terraform plan` and `terraform apply` create a group, an app assignment and a policy; a second plan shows no changes; a change made in the UI appears as drift on the next plan; `terraform import` adopts an existing app. A resource needing a scope outside the credential's grant fails at apply with a refused, audited call and no partial change to that resource.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-MOBILE-001 — Native employee and administrator access (partial).** On real iOS and Android builds plus Expo SDK clients, deploy the app with managed configuration through Intune and Android Enterprise, enroll a passkey, return through a verified link, launch an assigned app, approve an authorized request and revoke the lost device. Refuse a hijacked callback and offline approval; exercise web equivalents at 1440 and 390.

Existing evidence and limits: src/ui/pages/account.ts; tests/integration/browser.test.mjs — responsive account/admin web exists; native apps, mobile SDKs and launcher do not.

**AUTH-EVENTS-001 — Reliable lifecycle events and webhooks (done).** Subscribe a real app endpoint through admin/API, perform a joiner/mover/leaver, rotate signing material and recover after 429, timeout and outage. Replay an event and request a historical cursor; verify ordered/versioned reconstruction without duplicate grants or missing unresolved work.

Existing evidence and limits: src/auth/events/; src/auth/outbound.mjs; tests/auth/events.test.mjs; COMPANY-APPS.md — administrators subscribe HTTPS endpoints (private, IP and internal destinations refused); versioned events with stable IDs and commit-order cursors for people, memberships, assignments, provisioning outcomes, recovery and policy are signed (Standard Webhooks HMAC), retried through 429 with Retry-After, a timeout and an outage without changing their ID, signed with both secrets during a rotation overlap, replayable with the original ID, and readable from a resumable cursor with a per-subscription read key; a delivery acknowledgment closes no access obligation.

**AUTH-FOLLOWUP-001 — Follow-through until access is resolved (partial).** Leave an invitation, access approval and failed deprovision unresolved across a weekend/DST change and process restart; observe due actions/reminders/escalation, complete or cancel each through its normal door, and verify reminders cease while the complete history remains.

Existing evidence and limits: src/auth/recovery.mjs; src/auth/links/logout.mjs; src/auth/agents/approval.mjs — delayed recovery, notices and bounded logout retries exist; a general obligation/reminder engine and collaboration adapters are missing.

**AUTH-DELIVERY-001 — Email and SMS delivery operations (partial).** Configure SES and Twilio in authorized test accounts, enroll/recover a worker and observe accepted, bounced, throttled and unavailable outcomes. Prove tokens/credentials absent from logs/exports and a notification failure leaves the original access obligation unresolved.

Existing evidence and limits: src/auth/email.mjs; src/mail.server.mjs; tests/integration/http.test.mjs; tests/email-link.mjs — Base mail/outbox wiring and send-failure activity exist; SES/Twilio-specific setup and delivery reconciliation are missing.

**AUTH-OPS-001 — Operate a company identity service (partial).** Deploy to the supported production host, perform a rolling/key-certificate upgrade, fail a dependency, restore a backup and measure against each numeric objective: availability from synthetic sign-ins at one-minute intervals across a month, the restore's elapsed time against the 1-hour RTO and its newest recovered write against the 5-minute RPO, p95 authorization/SAML and token/UserInfo latency under a load of 50 sign-ins per second, and leaver processing against AUTH-TIMING-001. Trigger Uptime/Oncall escalation and reconcile the USD usage forecast to actual provider usage without exposing secrets.

Existing evidence and limits: AUTH-COMMANDS.md; scripts/installer/local.mjs; src/auth/keys.mjs; tests/integration/dev.test.mjs — local command/recovery and key operations exist; hosted resilience, SLO measurement, region selection and usage forecasting are missing.

**AUTH-RECOVERY-002 — Emergency continuity and recovery drills (partial).** Drill lost phone/key, unavailable upstream, expired signing certificate and restoration of an owner installation through the public account/CLI doors. Confirm ordinary workers cannot invoke emergency authority, cancellation wins against completion where applicable, all notices persist and used credentials cannot be replayed.

Existing evidence and limits: src/auth/recovery.mjs; tests/auth/security.test.mjs; tests/auth/recovery-cli.test.mjs; tests/integration/browser.test.mjs — delayed/approved/cancelable and local emergency recovery exist; scheduled multi-system continuity drills do not.

**AUTH-RECOVERY-003 — Same-day help-desk recovery for employees (partial).** As help desk scoped to the employee's group, restore a non-admin employee with no recovery code through manager attestation, and another through a Persona check in an authorized test account, each from case opening to a newly enrolled passkey in under 1 hour. Refuse the path for an administrator, for an employee outside scope, without a recorded verification, and on reuse or after an hour of the enrollment link; see the revoked sessions and every notice.

Existing evidence and limits: src/auth/recovery.mjs; tests/auth/security.test.mjs — another administrator can approve any person's pending recovery the same day, after which the person completes it with email proof; the scoped help-desk role, recorded verification step, admin refusal and one-hour enrollment link are missing.

### Privacy, custody and Base replacements

**AUTH-ERASURE-001 — Authorized erasure with retained accountability (missing).** Erase a worker with multiple factors, imports, agent grants and SaaS access through the owner door; query/export all stores, inspect receipt and anonymized audit, and attempt restore of a pre-erasure archive with the later journal. Keep a blocked remote deletion visible, test legal hold and last-owner protection, then reset a local installation.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-RETENTION-001 — Explicit retention and secret custody (partial).** On a default installation, confirm 13-month audit retention; try to set it to 30 days and be refused; open a review over a period and see its events kept past their expiry. Populate every retained class, age it across each configured expiry, restart and inspect the public history/export doors: transient secrets expire, retained history and unresolved obligations remain, held data is preserved and scheduled deletion produces accountable results. Rotate a connector/signing key and verify secrets absent from logs/assets/archive.

Existing evidence and limits: src/auth/maintenance.mjs; src/auth/keys.mjs; scripts/installer/transfer.mjs; tests/auth/userinfo.test.mjs — bounded transient/key cleanup and archive exclusions exist; configurable workforce retention/holds and complete class coverage are missing.

**AUTH-TRANSFER-002 — Complete workforce portability (partial).** Create a populated workforce installation, export/import/export through rer and compare every declared portable record. Refuse corrupt/foreign/unknown schema and nonempty destination; restore with later erasure journal, confirm all jobs/grants are inactive, then reauthorize one connector and verify exactly its approved work resumes.

Existing evidence and limits: scripts/installer/transfer.mjs; src/auth/links/grant-map.mjs; tests/auth/linking.test.mjs — current identity/grant-map portability exists; workforce product records and inactive connector/job restoration are missing.

## Push further: agents serving workforce identity

**AUTH-AGENT-001 — Agent-led SaaS onboarding (partial).** Ask the agent to onboard Slack and a generic SAML/SCIM SaaS, approve a scoped configuration diff, and run a real assigned employee through sign-in/provision/change/revoke. Inject malicious vendor text, stale settings and withheld domain consent; prove no unauthorized change and a blocked readiness state with an actionable next step.

Existing evidence and limits: src/auth/agents/app-kinds.mjs; src/auth/agents/approval.mjs; tests/auth/agents-proposals.test.mjs — exact human-approved RER link proposals exist; SaaS discovery/configuration/testing agents do not.

**AUTH-AGENT-002 — Diagnose and repair broken sign-in (missing).** Break a callback, expire a certificate and fail recovery mail on separate app journeys; ask the agent to diagnose with source citations, approve a repair and verify end-to-end behavior. Deny approval and inject untrusted trace instructions, confirming no configuration or authority changes.

Existing evidence and limits: No implementing product path or acceptance test yet.

**AUTH-AGENT-003 — Find orphaned and excessive access (partial).** Feed real approved connector data containing a departed worker’s remote account, an excessive role and an unused but required emergency grant. Review the cited findings, approve only the first two, and verify downstream state plus the worker’s allowed tasks; stale data or changed employment invalidates the proposal.

Existing evidence and limits: src/auth/agents/preparer.mjs; src/auth/agents/approval.mjs; tests/auth/agents-proposals.test.mjs — allow-listed inventory and human-approved suspension/domain proposals exist; cross-app usage analysis and regression verification do not.

**AUTH-AGENT-004 — Person-bound delegated agent identities (partial).** Authorize an agent to update one approved app assignment until a fixed deadline, invoke its target API/MCP tool and inspect attribution. Deny another person, purpose, resource, target, scope, expired grant and replay/substitution; show and revoke the active grant in My account and prove its next request is refused.

Existing evidence and limits: src/auth/agents/keys.mjs; src/auth/agents/approval.mjs; tests/auth/agents-keys.test.mjs — accountable, expiring, revocable preparation keys exist; delegated external OAuth/MCP identities and task scopes are missing.

**AUTH-AGENT-005 — Verify revocation everywhere (partial).** Revoke a delegated grant and offboard its accountable worker while one SaaS is offline and another offers no session-revocation API. Prove immediate Auth denial, enumerate all derivatives, resume verification after restart/provider recovery and retain the manual exception until a person resolves it; every final claim must match a remote read/probe.

Existing evidence and limits: src/auth/links/logout.mjs; src/auth/agents/keys.mjs; tests/auth/linking.test.mjs; tests/auth/agents-keys.test.mjs — local key revocation and RER fences exist; app-wide delegated-credential inventory and verified remote reconciliation are missing.

85 clauses: **13 done / 39 partial / 33 missing**. A completed request, review, lifecycle plan or agent job must satisfy every affected app’s end state; provider acknowledgment or local queue success alone is insufficient.

## Retained implementation checks and historical outcomes

The independent Auth slice has tests through real D1 and the emitted Worker. `tests/auth/security.test.mjs`, `protocol.test.mjs` and `upstreams.test.mjs` exercise browser-bound proof, passkey policy, recovery, encrypted ES256/RS256 signing-key lifecycle, PKCE/private-key JWT protocol behavior and signed upstream responses. Domain-policy coverage includes required-provider management, owner exemption, excluded email/passkey routes, current policy at code redemption, provider removal/configuration changes, exact-domain enrollment and retained provider evidence through email, passkeys and recovery. `recovery-cli.test.mjs` exercises real local wrangler and private recovery-token storage. These are implementation checks, not OpenID certification.

`tests/integration/http.test.mjs` proves the real runtime/mail/outbox wiring, owner bootstrap versus Auth authority, inherited Base route denial, per-request private authorization, native confirmation, first-run completion and publication of real public signing keys. The retained `tests/email-link.mjs` now proves Auth sessions and browser-bound links instead of inherited Base email-cookie behavior. `tests/runtime.mjs` now expects the root to redirect to sign-in instead of serving a public placeholder.

`tests/integration/browser.test.mjs` exercises actual Auth pages, email confirmation, first setup, native Chromium passkey enrollment/authentication, people invitation/domain/suspension and recovery cancellation. It checks the five private pages at 1440 and 390 in light and dark, with axe serious/critical violations required to be zero. `tests/integration/dev.test.mjs` runs fresh real rer setup/dev, uses RER_OPEN in Chromium, checks the key-gated owner session and key removal, and proves localhost enrollment and private-path refusal. CI installs Chromium before running them. Test success must be read from the run evidence; having these tests alone is not acceptance.

Run `rer check --profile first-party`, `pnpm typecheck`, and the appropriate targeted tests after changes. `rer verify` is the complete seed check. `tests/auth/userinfo.test.mjs` exercises real signed access tokens and scoped GET/POST UserInfo, expiry, issuer/audience/type/subject/client/session refusal, sign-out revocation, account/client/policy changes and RS256 key publication/retirement. The existing ID-token flows still prove nonce, issuer, audience, pairwise subjects and one-time owner claims. The old ID-token-only assertion is replaced by the approved access-token response; no refusal or claim assertions were weakened.

`tests/auth/authorization-policy.test.mjs` adds one HTTP regression for each authorization-policy requirement: sessions ending with the email proof and returning through email re-proof to the app; prompt/max-age active authentication with fresh `auth_time`, silent refusal, continuation binding/expiry/replay and upstream SSO followed by a local email confirmation; and discovery matching explicit request-object refusals with callback validation. No previous test is weakened or removed, and no wider Basic OP or logout profile is introduced.

Run site (run-auth.com, HOMEPAGE-VARIANTS.md): `tests/site/run-site.test.mjs` builds it with `rer build --site` and checks that the homepage's Run Auth action opens `/run`, that it links no installed-instance route, and that every guide `docs/site.json` lists is built. `rer build --site` itself refuses broken links, instance-only routes, other origins and installation data. Its deploy (`.github/workflows/run-site.yml`) stays off until the repository variable `RUN_SITE_DEPLOY` is `true`.

Move-in (MOVE-IN.md): `tests/auth/move-in-staging.test.mjs` stages each source's documented export (Google CSV and JSON, Entra CSV, Auth0 CSV and NDJSON, Okta Users API JSON, JumpCloud CSV and JSON) through the staging route, refuses the hostile set and oversize or unknown files, proves staging leaves people, sessions, grants and mail untouched apart from one Activity entry, and flags every review class. `tests/auth/move-in-admission.test.mjs` proves admission through the admin route (member, email-only, signed-out and stale-proof sessions refused; invited members with no proof, right, session or mail; the owner's address and matching emails change nothing), undo (untouched person removed, signed-in and granted people kept and named), and that an Auth0 former subject is refused by UserInfo and the token endpoint and never becomes the pairwise subject. `tests/integration/move-in-browser.test.mjs` runs the 30-row Google journey at 1440 and 390 in light and dark with axe serious/critical at zero. Fixtures are hand-written from provider documentation (tests/fixtures/move-in/README.md); no provider account or live tenant was used, so live cutover is not accepted. Export carries the former subject map with the signed grant map (below).

Agents (AUTH-ADMIN-001): `tests/auth/agents-keys.test.mjs` proves minting, renewal and revocation through the admin routes (no-session, member, email-link-only and stale-proof sessions refused; expired, revoked and orphaned keys refused on the next request; the key absent from listings, Activity, every stored row and the test process's output) and that a key opens nothing but the preparer API while a session cookie is no key. `tests/auth/agents-proposals.test.mjs` parses the inventory from a populated store against an allow-list of field names, files and approves each proposal kind (filing leaves people, sessions, apps, links, rules and mail unchanged), and proves approval rules: passkey signature by the approver in the session that asked, replay, stale targets with what changed, expiry, rejection, concurrent approvals held at a commit barrier, a revoked key's pending proposals, owner and self-suspension refusals. `tests/integration/agents-browser.test.mjs` runs mint, file, review, passkey approval and Activity at 1440 and 390 in light and dark with axe serious/critical at zero. `remove_app_link` is proven the same way; `approve_app_link` reads the app's own documents when filed and again at approval.

Linking (AUTH-LINK-001, AUTH-LOGOUT-001, AUTH-TRANSFER-001, LINKING.md): `tests/auth/linking.test.mjs` links an app Worker built only from Base's own app side with a one-use link token (a replayed token refused), signs a person in to it through Auth, and proves Sign out everywhere ends that app session. On 13 Oct 2026 a fresh clone of Spool, whose setup declares the optional `oidc-provider@1` dependency, linked a fresh local Auth install through `rer setup --non-interactive` and a person signed in to it through Auth at 1440 and 390 (screenshots and network log kept with the task evidence). The same run proved, through HTTP: a replayed redeem code, a second concurrent redemption, a link token reused or presented for another origin, a key swap without continuity, a version downgrade before owner approval, and loopback or plain-http origins on a production install, each refused; Sign out everywhere and suspension ending Spool sessions (200 before, 401 after); a replayed logout token refused at Spool (409) while a fresh one is accepted; and `rer export` into a fresh install with `rer import`, after which Spool re-linked with the same client, sector and pairwise subject. Hosted acceptance, a public release and certification are not claimed.

OpenID conformance, 13 Oct 2026, Auth `9915adf`: the unchanged release-v5.3.2 suite through `tests/conformance` (listener on 127.0.0.1, browser automation for the authorization and logout pages). **Config OP PASSED**: `oidcc-discovery-endpoint-verification` PASSED. **Back-Channel Logout OP** (code, static client, the plan's own client_secret_basic variant): `oidcc-backchannel-logout-discovery-endpoint-verification` now PASSED (Auth advertises `end_session_endpoint`, `backchannel_logout_supported` and `backchannel_logout_session_supported`); `oidcc-backchannel-rp-initiated-logout` FAILED at `EnsureServerConfigurationSupportsClientSecretBasic`, the kept strict profile (private_key_jwt and mandatory PKCE), as decided. No expectation annotations were added and the profile was not widened.

OpenID conformance, 12 Oct 2026: the unchanged OpenID Foundation release-v5.3.2 suite ran through `tests/conformance` against real local Workerd/D1 Auth with signed access tokens and UserInfo. **Config OP PASSED**: its discovery module PASSED, runner exit 0, no warnings, reviews or skips. **Back-Channel Logout OP FAILED**: with Auth's private_key_jwt variant the suite refuses to create the plan (HTTP 400, the plan fixes client authentication); with the plan's own variant (code, static client, client_secret_basic) both modules FAILED. `oidcc-backchannel-logout-discovery-endpoint-verification` finds no `backchannel_logout_supported`, `backchannel_logout_session_supported` or `end_session_endpoint`; `oidcc-backchannel-rp-initiated-logout` fails `EnsureServerConfigurationSupportsClientSecretBasic` and then sends an authorization request without PKCE, which Auth refuses with HTTP 400. **Basic OP not run**: plan creation HTTP 400 for private_key_jwt. Config's native configuration declares the required `rer_interfaces` extension through upstream's `server.allow_unexpected_metadata_fields`; structural validation and every protocol condition remain active, with no expected-failure or skip annotations.

Back-Channel Logout OP can pass only with client_secret_basic for the test client and authorization without PKCE, which widen the approved private_key_jwt and mandatory-PKCE profile (the same decision that holds Basic OP); the end-session endpoint and signed `logout_token` sender it also needed now exist. An earlier unchanged static Basic diagnostic exported two FAILED results (`EnsureServerConfigurationSupportsClientSecretBasic`) and was stopped after an ordinary Basic authorization request without mandatory PKCE returned Auth HTTP 400; it is incomplete, not certification.
