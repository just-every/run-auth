<!-- Generated from CONTRACT.md by contract-docs. Edit CONTRACT.md, then regenerate. -->

# Accept a Auth installation

The primary journey: Exercise the capabilities and acceptance journeys below.

## Progress

| Tier | Done | Partial | Missing | Total |
| --- | ---: | ---: | ---: | ---: |
| Core | 38 | 37 | 17 | 92 |
| Agent surface | 0 | 0 | 0 | 0 |
| Later | 0 | 0 | 0 | 0 |
| Full target | 38 | 37 | 17 | 92 |

Judged from the code and tests at commit `4565fd3f48b1cfe6b518f27e168a215d9e549ac4` (17 October 2026). Field proof register: 0 rows; 0 passed, 0 failed, 0 not run.

## Core

### Retained identity and RER guarantees

#### AUTH-HOST-001 — Issuer host

Core · published · **done**

**Requirement.** The host owns the issuer and passkeys. Choose it before linking apps. A host change is a provider move requiring the apps' owners to approve re-linking; it does not silently preserve an issuer or passkey origin. Fresh local setup selects localhost; explicit and saved hosts are preserved.

**Acceptance.**
1. Choose localhost on fresh setup; repeat with an explicit/saved issuer; enroll a passkey and link an app.
2. Attempt a host move and require a new app-owner approval rather than preserving issuer authority.

**Evidence.** `tests/integration/dev.test.mjs`; `tests/auth/linking.test.mjs`; `scripts/installer/local.mjs`
**Gap.** None.

#### AUTH-PRIVACY-001 — Shared claims

Core · published · **done**

**Requirement.** Auth shares each person's email and name with the apps they use. Under RER Managed, RER can sign link approvals for the account's Auth install; it receives people's data only as an ordinary linked app, for people who sign in to RER through it.

**Acceptance.**
1. Sign in to two linked apps with different granted identity scopes; inspect UserInfo and tokens for only the permitted claims.
2. Add a RER approval key and confirm it grants no user-data access without an ordinary app sign-in.

**Evidence.** `src/auth/userinfo.mjs`; `tests/auth/userinfo.test.mjs`; `tests/auth/rer-approval.test.mjs`
**Gap.** None.

#### AUTH-RER-TRUST-001 — RER trust

Core · published · **done**

**Requirement.** Auth accepts a RER link approval only when an active trusted key signed it (`typ: rer-link-approval+jwt`, `aud` this issuer, lifetime at most five minutes, unique `jti` consumed once), its origin and link key match the app document Auth pulls itself, and its `claim`, if any, names the Auth owner. Keys come from the `RER_LINK_APPROVAL_KEYS` setting of a RER-provisioned install, or from an owner or administrator on Sign-in methods with passkey and fresh local email proof. Withdrawal, by an administrator there or by RER with an assertion signed by that key when the account leaves Managed, ends the key for good. RER-made links are flagged and notified like token-made links. An install with no trusted key makes no request to RER.

**Acceptance.**
1. Link using a correctly signed RER approval, then refuse wrong issuer/origin/key/claim, stale assertion and jti replay.
2. Withdraw trust through both supported doors and prove the key cannot be restored or used again.

**Evidence.** `src/auth/links/rer-trust.mjs`; `src/auth/links/rer-approval.mjs`; `tests/auth/rer-approval.test.mjs`
**Gap.** None.

#### AUTH-IDENTITY-001 — Owner and sign-in proof

Core · published · **done**

**Requirement.** Base bootstrap claims the owner but conveys no Auth privilege. Email-link proof completes once, only in the requesting browser. First passkey enrollment requires Auth email proof; administration and additional passkey enrollment require hardware passkey proof. Every enrollment, recovery approval or completion and administration write also requires this browser's Auth email confirmation within ten minutes, rechecked with the session's authority in the committing write; an enrollment challenge is valid only in the session that requested it. Recovery of anyone holding an administrator or other privileged role (AUTH-DECISIONS-001) requires another administrator's approval, a cancelable notified 72-hour delay, or the local emergency recovery token, and this rule is never relaxed for them. A non-privileged employee may also take the same-business-day help-desk path of AUTH-RECOVERY-003; today every person follows the administrator rule, which is stricter than the target and satisfies it.

**Acceptance.**
1. Through the real email, WebAuthn and administration routes, prove same-browser one-use confirmation, first/additional enrollment, fresh local email step-up rechecked at commit, wrong-session and revoked-session refusal, and approved/delayed/canceled/emergency recovery.

**Evidence.** `src/auth/local-email.mjs`; `src/auth/recovery.mjs`; `tests/auth/security.test.mjs`; `tests/auth/fresh-proof.test.mjs`; `tests/auth/local-email.test.mjs`; `tests/auth/recovery-cli.test.mjs`
**Gap.** None.

#### AUTH-PROTOCOL-001 — OpenID Connect profile

Core · published · **done**

**Requirement.** Auth implements code/PKCE with state, nonce, RFC 9207 issuer, private_key_jwt clients, pairwise subjects and ID tokens accompanied by signed bearer access tokens. Access tokens are restricted to Auth UserInfo, bound to client, subject, session and granted scopes, and valid for at most five minutes or the remaining session lifetime. UserInfo supports GET and POST, returns only scoped identity claims and rechecks active session, account, client, grant, email proof and domain policy. ID tokens and other bearer credentials cannot authorize UserInfo. No refresh tokens or offline access are offered for the static code-flow profiles. Existing clients retain ES256; clients may select RS256. Both algorithms’ keys are encrypted under AUTH_ENCRYPTION_KEY, published before use and retained through outstanding token expiry. These guarantees are exercised by the edition tests; they are not a certification statement.

**Acceptance.**
1. A registered RER client completes code/PKCE/private_key_jwt, validates nonce/issuer/audience/pairwise subject, and calls scoped GET/POST UserInfo.
2. Refuse code/assertion replay and inactive client/person/session/grant/policy; test encrypted ES256/RS256 publish-before-use and retirement.

**Evidence.** `src/auth/protocol.mjs`; `src/auth/userinfo.mjs`; `src/auth/keys.mjs`; `tests/auth/protocol.test.mjs`; `tests/auth/userinfo.test.mjs`; `tests/auth/authorization-policy.test.mjs`
**Gap.** None.

#### AUTH-BOUNDARY-001 — Private authorization

Core · published · **done**

**Requirement.** Every private document and API enforces its own session and administrative policy. The seed denies inherited Base operator, invitation, provider and domain management paths. Only bootstrap, Base session inspection and local Base sign-out remain exposed; gated dev entry exists exclusively in the development bundle. Removing the gate removes dev-session authority; production refuses dev proof.

**Acceptance.**
1. Request each private page/API signed out, as an email-only member, as a passkey administrator and with revoked authority; deny inherited Base management and production dev tokens.
2. Remove the local dev gate and confirm authority ends.

**Evidence.** `src/server.ts`; `src/auth/index.mjs`; `tests/integration/http.test.mjs`; `tests/integration/dev.test.mjs`
**Gap.** None.

#### AUTH-MOVEIN-001 — Staged move-in

Core · published · **done**

**Requirement.** Directory exports are staged apart from people: a staged row cannot sign in, receives no mail and appears only on the move-in review. Admission creates the same invited member as a People invitation, with no email proof, administrator right, password, factor, app role, group permission or session, and sends mail only when the owner chooses to send invitations. A matching email never rebinds an existing person, passkey or upstream link. Undo removes only people the batch admitted who have never signed in and hold no passkey, app grant or later activity, and records who it removed and kept. An Auth0 former subject is data for app owners: no protocol endpoint accepts it and it never replaces the pairwise subject. Staging, admission, invitation and undo are administration writes under AUTH-IDENTITY-001.

**Acceptance.**
1. Stage Google, Entra, Auth0, Okta and JumpCloud exports through Move-in, inspect collision/disabled rows, admit selected members without proof/roles/mail, explicitly invite, and undo only untouched admissions.
2. Refuse former Auth0 subjects as credentials and concurrent/stale administrative authority.

**Evidence.** `src/auth/move-in/routes.mjs`; `src/auth/move-in/sources.mjs`; `tests/auth/move-in-staging.test.mjs`; `tests/auth/move-in-admission.test.mjs`; `tests/integration/move-in-browser.test.mjs`
**Gap.** None.

#### AUTH-ADMIN-001 — Agent preparation

Core · published · **done**

**Requirement.** An agent prepares administration and a person decides. A preparer key, minted, renewed and revoked by an administrator under AUTH-IDENTITY-001, is shown once, stored as a digest, expires 30 days after minting or renewal, and is accepted only by the preparer API while unrevoked and while its accountable administrator remains the administrator who minted it: it ends for good when that person is demoted, suspended or removed, and promoting or restoring them again does not bring it back (a new key is minted). It reads an allow-listed inventory (no session, passkey, key or token material) and files proposals to suspend or restore a person, invite a person, remove an invitation, or add or remove a domain's required provider; filing stores the affected people and apps and a digest of the target's state, and changes nothing else. A proposal runs only on one exact approval: an administrator's passkey signature over a challenge naming it, with that session's fresh local email proof, rechecked with the approver's authority, the unchanged target state and an unexpired, undecided proposal in the committing write. It runs once; it never suspends the owner or its own approver; its outcome is recorded in Activity with the key and the approver. A preparer key confers no session, page, approval, key management or protocol access and is not an access token.

**Acceptance.**
1. Mint/renew/revoke a preparer key, inspect its allow-listed inventory, file each supported proposal and approve its exact state with a person’s passkey and fresh local email.
2. Prove expiry, stale-state refusal, one winner under concurrent approvals and permanent loss of key authority after administrator removal.

**Evidence.** `src/auth/agents/keys.mjs`; `src/auth/agents/preparer.mjs`; `src/auth/agents/approval.mjs`; `tests/auth/agents-keys.test.mjs`; `tests/auth/agents-proposals.test.mjs`; `tests/integration/agents-browser.test.mjs`
**Gap.** None.

#### CMD-001 — Commands

Core · published · **done**

**Requirement.** Auth retains the shared RER command dispatcher and verbs. Its edition-owned extensions are documented in AUTH-COMMANDS.md. Setup applies real D1 migrations and claims the first owner. Sign-in begins in the browser, never by presenting an unusable CLI-bound proof. Local recovery writes only a token digest to D1 and stores the raw token in a mode-0600 private file.

**Acceptance.**
1. Run real install/setup/dev, start browser sign-in, repeat setup without replacing owner/settings/data, stop the managed process, and generate/redeem local recovery with only a digest in D1 and a mode-0600 raw token file.

**Evidence.** `AUTH-COMMANDS.md`; `scripts/installer/local.mjs`; `tests/integration/dev.test.mjs`; `tests/auth/recovery-cli.test.mjs`
**Gap.** None.

#### HTTP-001 — HTTP surfaces

Core · published · **done**

**Requirement.** Hono serves health/API dispatch and Start serves remaining documents; Auth intercepts identity, protocol and private Auth pages before dispatch. Unknown routes return 404.

**Acceptance.**
1. Call health, Auth APIs and public/private documents through the emitted Worker; confirm identity interception, per-request authorization and an ordinary 404 for unknown routes.

**Evidence.** `src/server.ts`; `tests/integration/http.test.mjs`; `tests/runtime.mjs`
**Gap.** None.

#### AUTH-LINK-001 — App links

Core · published · **done**

**Requirement.** Auth links apps through Base's pull protocol (LINKING.md). It reads only the app's own documents at its exact origin and binds the exact callback set. Codes are one-use, last 60 seconds and are redeemed atomically. It verifies the redeem assertion (audience, at most 60 seconds, unique `jti`). A client keeps its id and sector. A new key needs an administrator who saw the existing link, and a link replaces another app (its sector at another origin, or another sector at its origin) only on an approval that named it. Link tokens cover one origin and callback set, are single use and last at most an hour. Production installs refuse loopback and plain-http origins; dev installs serve only loopback apps. Token- and RER-made links are flagged and announced. Reported interface versions are kept, and a lower one, reported or re-linked, waits for the owner. Removing an app signs out everyone it signed in.

**Acceptance.**
1. Use the pull/link-token flow to link a real Base app Worker, sign in, re-link with continuity, and remove it.
2. Refuse mismatched callbacks/origins, replay/concurrent redemption, unauthorized key swap and unapproved downgrade; observe linked-app sessions end on removal.

**Evidence.** `src/auth/links/handshake.mjs`; `src/auth/links/routes.mjs`; `src/auth/links/versions.mjs`; `tests/auth/linking.test.mjs`; `tests/auth/agents-proposals.test.mjs`
**Gap.** None.

#### AUTH-LOGOUT-001 — Sign-out reach

Core · published · **done**

**Requirement.** Sign out everywhere, suspension (identity fence) and RP-initiated logout send signed `logout+jwt` tokens with a unique `jti` and no `nonce` to each linked app's registered logout path. Each is retried for up to 24 hours. Discovery advertises `end_session_endpoint` and back-channel logout with session support.

**Acceptance.**
1. Sign out everywhere, suspend a person and request RP logout through real Auth/app endpoints; the app rejects the old session and replayed logout tokens.
2. Exercise bounded retries and inspect the persisted delivery outcome; discovery advertises the supported endpoints.

**Evidence.** `src/auth/links/logout.mjs`; `src/auth/links/end-session.mjs`; `tests/auth/linking.test.mjs`; `tests/auth/protocol.test.mjs`
**Gap.** None.

#### AUTH-TRANSFER-001 — Export and import

Core · published · **done**

**Requirement.** Export carries people, emails, passkey public keys, clients, grants, subjects, history and a signed grant map. It omits sessions, private keys, the pairwise key and the RER keys an owner trusted; withdrawn RER keys stay withdrawn. Import refuses app origins the destination cannot serve and active dev personas. A restore at the same host keeps every client, sector and pairwise subject.

**Acceptance.**
1. Export a populated installation, import into an empty installation at the same host, and re-link the app with unchanged client/sector/pairwise subject.
2. Inspect retained records and absent authority; refuse incompatible origins and active dev personas.

**Evidence.** `scripts/installer/transfer.mjs`; `src/auth/links/grant-map.mjs`; `tests/auth/linking.test.mjs`
**Gap.** None.

### The workforce directory and employee experience

#### AUTH-DIRECTORY-001 — One workforce directory

Core · target · **done**

**Requirement.** Employers manage employees, contractors, service identities, managers, departments, locations, employment dates, immutable person/source identifiers, custom attributes and active/invited/suspended/terminated states. Search, filter, bulk preview and admin API edits (made through AUTH-ADMINAPI-001 credentials or an administrator's session) use the same validation and audit. Static and attribute-driven groups have explainable membership, group owners and mapped app roles; source precedence and manual overrides are visible. Rehires and email/name changes preserve reviewed identity continuity rather than merging by email.

**Acceptance.**
1. In People/API, onboard a W-2 employee and a contractor, rename and transfer one, preview a bulk edit, evaluate dynamic groups, suspend and rehire; verify stable identifiers, explicit source conflicts and resulting assignments without duplicate accounts.

**Evidence.** `src/auth/workforce/people/`; `src/auth/admin.mjs`; `tests/auth/directory.test.mjs` ("onboard, rename, transfer, bulk preview, dynamic groups, suspend and rehire keep one stable account per person": onboard a W-2 employee, a contractor and a service identity, rename and transfer, preview then apply a bulk edit, evaluate dynamic groups, suspend, terminate and rehire, with no duplicate account and no merge by email); `tests/auth/directory.test.mjs` ("source precedence, manual overrides and conflicts are visible; a source finds people by its own id, never by email; an email change keeps the same person, sessions end and apps follow": stable identifiers, explicit source conflicts, resulting SCIM assignments); `tests/auth/directory.test.mjs` ("directory doors need a passkey administrator with fresh email proof; attributes are typed; groups explain each member, keep owners and honour exclusions": same validation and audit, search and filter, explainable membership); `tests/integration/directory-browser.test.mjs` ("directory journey: an administrator onboards a worker, edits and bulk-moves people with a preview, sets a group rule, terminates and rehires, at desktop/mobile in both themes": People at 1440 and 390)
**Gap.** None.

#### AUTH-TENANCY-001 — Organizations and delegated administration

Core · target · **done**

**Requirement.** An installation can serve multiple employer organizations, subsidiaries and partner workspaces. Installation authority and organization authority are separate: the installation owner and installation administrators run the installation, and each organization has its own owner. Each organization is either installation-operated, where installation roles also administer it, or isolated, where installation roles have no read, write or export authority over its directory, profiles, audit content, issuer secrets or connector credentials and the installation owner can only host it or erase or reset it as a whole under AUTH-ERASURE-001. People may hold distinct memberships and roles in more than one organization, with an explicit active organization. Owner, identity administrator, security/policy administrator, app administrator, group owner, manager, help desk, auditor and employee permissions are scoped and server-enforced, including exports and API credentials; each built-in role's permissions are listed, and employers compose further roles and scopes under AUTH-ROLES-001 (custom roles, resource sets of groups/apps/people, separate view and edit scope, rank fence on administration). Invitations expire, can be canceled, and never grant more than the inviter can delegate. Employers can delegate setup without exposing another employer's directory or issuer secrets.

**Current scoped administration semantics (ct 21 Oct 22:55Z; public-door conformance proven):** The original installation retains its issuer and tables. New employers have separate physical stores, path issuers, factors, sessions and signing keys; installation roles confer no directory read/write/export authority in an isolated organization. Existing HTTP tests cover proven-session switching, expiring/cancelled invitations, one-app/one-case delegation and cross-employer denials. All current organizations are isolated. Scoped credential custody and the 1440/390 authority journey pass; named HTTP assertions now cover installation-owner/admin read/write/export and issuer/connector credential refusals, including renamed cookies. The current authority journey passes at 1440 and 390. Complete organization-schema restoration remains under AUTH-TRANSFER-002; current archives fail closed without provisioned destination schemas.

**Acceptance.**
1. Invite a contractor into two employers, switch organization, delegate one app to an app administrator and one recovery case to help desk; deny cross-organization reads/writes/exports and unauthorized role escalation, including direct API requests.
2. **Current isolation semantics:** every newly created employer is isolated.
3. Installation roles acquire no employer session, membership or directory authority by hosting it.
4. Installation archive export/import refuses an active isolated employer, including an active employer inside a source archive; anonymous evidence from an erased employer remains portable, with credentials and sealed pending remote work excluded.
5. AUTH-TRANSFER-002 inherits a separate employer-owner-authorized archive/restore door before that capability ships.
6. A future installation-operated mode inherits the published permission/resource/rank and independent-proof boundaries before it ships.

**Evidence.** `tests/auth/security.test.mjs` — "organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions"; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile"; `docs/administrator-roles.md`  `tests/integration/http.test.mjs` — "owner erasure fences a pre-erasure rer archive with its later journal, restores anonymous evidence and resets the local installation" proves active isolated-employer archive refusals and erased anonymous-namespace portability.
**Gap.** None.

#### AUTH-TENANCY-002 — No cross-organization linking or proof transfer

Core · target · **done**

**Requirement.** A person's memberships in different organizations are never linked, merged or matched automatically, whether by email, domain, upstream subject, device, imported metadata or an agent suggestion. Proof, factors, recovery state, sessions, consent, approvals and administrator authority completed in one organization never satisfy another; each organization's sign-in, enrollment and step-up stand alone. A person's own organization switcher requires their proof in each organization and gives no organization visibility of another's records. Records retained after an organization is erased or reset (AUTH-ERASURE-001 anonymous receipts and sealed remote work) are never attached to, shown in, matched against or retried from any other organization, including a new organization later created with the same name, domain or people. The only link between a person's identities is one they create under AUTH-ERASURE-002; it carries no proof, visibility or authority.

**Acceptance.**
1. Give one person memberships in two isolated organizations with the same email and upstream subject; confirm no automatic link or match, that a passkey sign-in, step-up, recovery or approval completed in one does not satisfy the other, and that an administrator of one cannot see or act on the other membership through UI, admin API or export.
2. Reset one organization, create a new organization with the same name, domain and people, and confirm none of the retained receipts or sealed work appears in, links to or can be retried from it.

**Evidence.** `tests/auth/security.test.mjs` — "organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions"; `tests/auth/provisioning.test.mjs` — "app erasure removes connector custody and protected organization reset retains only installation-owner anonymous outcomes and credential-free pending work"
**Gap.** None. The named organization journey additionally registers encrypted employer-local Google clients and proves identical issuer/subject/email produce independent people and no callback, session or root trust transfer. `docs/employer-providers.md` documents the bounded owner-only registration door.

#### AUTH-ROLES-001 — Custom administrator roles and resource sets

Core · target · **done**

**Requirement.** Employers build custom administrator roles from a published permission list (for example: view people, edit profile fields, suspend/restore, reset factors, approve recovery, manage group membership, manage group rules, configure app, assign app, manage policy, manage identity providers, view audit, export audit, manage admin API credentials). A role is granted over a resource set: named groups, attribute-defined groups (such as "non-privileged users in the US group"), apps and individual people, with view scope and edit scope set separately. The built-in AUTH-TENANCY-001 roles are expressible in the same model. Server enforcement applies to UI, admin API and exports alike, in this order: organization boundary, published permission, view or edit resource set, then rank. Built-in administrator ranks are immutable: installation owner and organization owner 100 (each in its own scope), installation administrator 90, identity administrator and security/policy administrator 80, app administrator 50, help desk 20, auditor 10. Group owner, manager, app owner and employee carry administrator rank 0; their decisions follow AUTH-DECISIONS-001. A custom role's rank (1–89) is chosen by the installation owner, an installation administrator for an installation-operated organization, or that organization's owner, always strictly below the chooser's rank. Rank grants nothing by itself. No role can administer (profile, status, factors, recovery approval, roles, sessions or that person's data export) a person whose administrator rank in that scope is equal to or higher than its own, nor anyone outside its edit scope. Viewing follows view scope, not rank. A role holder can never grant a role, rank, resource set or admin API credential wider than their own current authority. Admin API credential custody is the published "manage admin API credentials" permission; until custom roles ship it is held by installation owner and installation administrator. Role and resource-set changes are administrator writes under AUTH-IDENTITY-001, previewed with who gains and loses which actions, and audited. Future machine administration doors inherit AUTH-ADMINAPI-001 credential, scope/resource, excluded-action, live-authority, audit and concurrency checks before shipping.

**Current scoped administration semantics (ct 21 Oct 22:55Z; public-door conformance proven):** Custom and built-in roles, separate view/edit resource sets, membership-sensitive decisions, previewed grants and audited scoped commands are implemented. Existing HTTP assertions cover equal-rank account-administration refusals, higher-owner administration, viewing without a rank fence and refusal of administrator factor reset. The ratified permission/resource/rank order and immutable built-in ranks are published in `docs/administrator-roles.md`. Named HTTP journeys prove scoped admin API credential custody, rank/no-widening, owner-only isolated custom-role design, exact gain/loss previews and hardware/fresh-email gates; the authority journey proves the current controls at 1440 and 390. Future machine doors inherit AUTH-ADMINAPI-001, and ordinary decisions inherit AUTH-DECISIONS-001 before shipping.

**Acceptance.**
1. Create a help-desk role with "reset factors" over group A and view-only over group B.
2. As its holder, reset a factor for a person in A; be refused editing in B (view succeeds), refused on an administrator in A, and refused via direct API and export.
3. Attempt to grant the role over a wider set and be refused; change group A's membership and observe the next decision follow it.

**Evidence.** `tests/auth/directory.test.mjs` — "scoped help desk separates view and edit, refuses privileged and out-of-group people, and follows live membership"; `tests/auth/security.test.mjs` — "recovery waits 72 hours, notifies every session, supports cancellation and distinct admin approval"; `tests/auth/agents-keys.test.mjs` — "machine directory and company-app commands share native lifecycle planning, dynamic membership, safe paginated reads and optimistic updates"; `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation"; `tests/auth/security.test.mjs` — "organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions"; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile"; `docs/administrator-roles.md`  `tests/auth/agents-keys.test.mjs` — "scoped credential custodians own exact automation whose tokens and native decisions track current permissions, dynamic resources and revocation" proves credential custody and no wider automation authority.
**Gap.** None.

#### AUTH-DOMAINS-001 — Verified employer domains

Core · target · **done**

**Requirement.** Administrators prove control of a corporate domain through expiring DNS or equivalent ownership challenges before domain-based enrollment, discovery or federation routing is activated. A domain cannot be silently claimed by another employer. Preview shows who a rule affects, aliases are explicit, and removal/reverification cannot strand emergency owners. Verified domain control never by itself proves an individual’s identity or licenses account linking.

**Acceptance.**
1. Claim a domain through the admin setup door, fail an incorrect or expired challenge and competing claim, then enroll and route an eligible worker.
2. Revoke domain ownership and confirm policy reevaluation and audited recovery access.

**Evidence.** `tests/auth/domains.test.mjs` — "domain setup refuses unproved, incorrect, expired and competing ownership; exact aliases need proof and eligible enrollment still needs individual email proof" proves admin claim, challenge refusals, competing employer, aliases, affected-person preview and enrollment; "revocation reevaluates existing sessions and enrollment while emergency owners retain audited access and can reverify" proves revocation, current policy, audited emergency access and reverification. `tests/auth/upstreams.test.mjs` — "required provider enrollment respects exact allowed domains and never supplies Auth email enrollment proof" proves eligible worker federation routing. `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation" proves committing administrator authority. `tests/integration/security-settings-browser.test.mjs` — "security settings: prove and revoke employer ownership, preview affected workers, and authorize persistent notification preferences at desktop and mobile" proves setup, preview and revocation at 1440 and 390 with tooltips. Live receipt sx-auth-c-i817-dns-live: records before 3, after 3. `docs/verified-domains.md`.
**Gap.** No acceptance gap remains.

#### AUTH-PROFILE-001 — Profiles and safe identity linking

Core · target · **done**

**Requirement.** Employees can read and edit permitted profile fields through account UI/API; administrators manage typed custom metadata with field-level visibility and source ownership. Linking or unlinking Google, Microsoft, Okta, GitHub, Apple or generic upstream identities requires proof of the existing account and the new identity, explicit confirmation and a surviving sign-in/recovery path. An issuer/subject pair has one binding; matching email, imported metadata or an agent suggestion alone cannot take over an account.

**Acceptance.**
1. Edit an employee profile and protected HR field, connect a second proven upstream and then unlink it; refuse an email collision, foreign subject, concurrent binding and last usable sign-in removal.
2. Inspect app claims for only consented fields.

**Evidence.** `src/auth/profiles/`; `src/auth/upstreams.mjs`; `src/auth/userinfo.mjs`; `tests/auth/profile.test.mjs` ("an employee edits only permitted profile fields; fields held by HR or an administrator are protected and say who holds them; hidden fields stay hidden; groups follow": edit a profile and a protected HR field); `tests/auth/upstreams.test.mjs` ("a signed-in person connects a second proven identity after confirming, and disconnects it; an email collision, a foreign subject, a replay and a concurrent binding are refused": connect, unlink, email collision, foreign subject, concurrent binding; "an agent proposal, imported metadata or a matching email never connects an identity, and the last usable sign-in cannot be disconnected": last usable sign-in); `tests/auth/profile.test.mjs` ("apps receive the edited name only under the profile scope, and never a custom or hidden field": app claims for only consented fields); `tests/integration/directory-browser.test.mjs` (same journey: My account profile edit and HR-managed field at 1440 and 390)
**Gap.** None.

#### AUTH-ENROLLMENT-001 — Managed enrollment and password compatibility

Core · target · **partial**

**Requirement.** Invitation, approved-domain self-registration and HR-driven prehire flows share verification, duplicate resolution, terms/consent and recovery controls. Passkeys are the default. HR-sourced future hires activate before their start date through AUTH-ONBOARD-001, and anyone without a usable factor gets a first credential through a temporary access pass (AUTH-TAP-001). Employers migrating password-dependent workforces can explicitly enable hashed password sign-in, governed by AUTH-PASSWORD-001's per-group policy and reset or unlocked under AUTH-PASSWORD-002, and email or SMS one-time verification; these methods cannot confer hardware administration proof or bypass conditional access. Public registration stays closed unless employer policy opens it, and a pending invitation or import is never authenticated authority.

**Acceptance.**
1. Enroll an invited employee and an approved-domain self-registrant, reject an outside address, complete a password reset under AUTH-PASSWORD-002 and a one-use SMS/email challenge, and prove weaker methods cannot administer or bypass required MFA.
2. Cancel enrollment and verify its outstanding links stop.

**Evidence.** `src/auth/email.mjs`; `src/auth/passkeys.mjs`; `tests/auth/security.test.mjs`; `tests/auth/registration.test.mjs`
**Gap.** email/domain enrollment and passkeys exist; passwords and SMS do not.

#### AUTH-PASSWORD-001 — Password policy per group

Core · target · **missing**

**Requirement.** Wherever an employer enables password compatibility (AUTH-ENROLLMENT-001), the Auth password is load-bearing: it carries RADIUS/VPN and Wi-Fi EAP-TTLS (AUTH-LEGACY-001), LDAPS binds, Mac password sync (AUTH-DESKTOP-001), the WS-Trust endpoint (AUTH-M365-001) and AD write-back. It is therefore governed by versioned password policies assigned to groups in an explicit priority order, with a default policy for everyone else; each person's effective policy and why it applies are shown. Each policy sets: minimum length (8–64, default 12) with at least 64 characters always accepted; required character classes (lower case, upper case, digit, symbol, each optional); refusal of any part of the person's username, email local part, first or last name; refusal of Auth's list of at least 100,000 common and dictionary passwords plus employer-added words; breached-password screening by a k-anonymity range query (Have I Been Pwned Pwned Passwords) when a password is set and, by policy, at sign-in; history of the last 0–30 passwords (default 24); minimum age of 0 to 7 days (default 1 hour); maximum age of never or 1–999 days, with an expiry warning a set number of days before (default 14) shown at web sign-in, in the launcher, at the desktop login window and by email, and a forced change at the next sign-in once expired; and lockout after 1–100 consecutive failed attempts (default 10), with automatic unlock after a set period or never, self-service unlock under AUTH-PASSWORD-002 and an optional lockout notice (AUTH-NOTIFY-001). Failed attempts count across every door that accepts the password (web, RADIUS, LDAPS, WS-Trust, desktop). Lockout blocks only the password: passkey sign-in, push, help-desk recovery (AUTH-RECOVERY-003) and a temporary access pass (AUTH-TAP-001) still work, so a remote attacker cannot lock a person out of their account. Policies preview who they affect before publishing, follow group membership on the person's next password set or sign-in, and are administrator writes under AUTH-IDENTITY-001; every policy version is audited and included in the AUTH-REVIEWS-001 evidence export.

**Acceptance.**
1. Assign a policy of length 12, history 24, minimum age 1 hour and lockout at 10 attempts to group A, and a policy of length 16 with symbols required and a 90-day maximum age with a 14-day warning to group B; preview the affected people.
2. Through the web change door and a RADIUS sign-in, refuse for a person in A each of: 11 characters, a password from their history, a second change within the hour, a password containing their last name, a block-list word and a breached password; refuse a password without a symbol for B.
3. Fail 10 attempts for A's person across web and RADIUS and see the password locked while passkey sign-in still succeeds; self-unlock under AUTH-PASSWORD-002.
4. Age B's person's password into the warning window and past expiry, and see the warning at each surface and the forced change.
5. Move the person from A to B and see B's rules at their next change.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-PASSWORD-002 — Self-service password reset, unlock and propagation

Core · target · **missing**

**Requirement.** Employees reset a forgotten password and unlock a locked password themselves at the hosted sign-in, in the launcher, in the Auth mobile app and at the macOS and Windows login window (AUTH-DESKTOP-001). Policy sets, per group, which factors reset and unlock require: by default one strong factor (passkey, Auth push or Auth TOTP), and, only for a person with no strong factor enrolled, email or SMS plus a second check (an SMS code together with an email link); security questions are never offered. Email or SMS alone is never accepted for anyone who has a stronger factor enrolled, nor for an administrator or privileged role (AUTH-DECISIONS-001), who reset only through a strong factor or AUTH-IDENTITY-001's recovery. Reset and unlock responses do not reveal whether an account exists and are throttled under AUTH-ABUSE-001. A reset or change is checked against the person's AUTH-PASSWORD-001 policy, ends their other password-based sessions as policy sets, sends the AUTH-NOTIFY-001 password-changed notice and propagates to every place the password is used: Auth verifies RADIUS, LDAPS binds and WS-Trust itself, so those take the new password at once; the AD connector writes it back to Active Directory (AUTH-LEGACY-001); and the Mac Platform SSO password-sync account takes it at the next online login or unlock. All of this happens within AUTH-TIMING-001's 60-second local bound, after which the old password is refused at every door Auth controls. A target that cannot yet confirm (connector offline, Mac not yet online) is shown per target as pending, never as done, and stays an AUTH-FOLLOWUP-001 obligation. Help desk can force a reset under AUTH-RECOVERY-003 with a temporary password that must be changed at first use.

**Acceptance.**
1. For a person in group A with Auth push enrolled, reset a forgotten password through self-service with push, and be refused when offering email alone; unlock a locked password the same way.
2. Within 60 seconds see the new password accepted and the old one refused at GlobalProtect RADIUS, an LDAPS bind, the WS-Trust endpoint and the Mac login in password-sync mode, and read the written-back password's change time from AD.
3. Take the AD connector offline during a reset and see AD pending until it returns.
4. Request a reset for an unknown address and receive the same response as for a known one; refuse a self-service reset by email alone for an administrator.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-ONBOARD-001 — New-hire activation before the start date

Core · target · **partial**

**Requirement.** For a future hire from an HR source (AUTH-HRIS-001, AUTH-HRIS-002) or created by an administrator, Auth sends an activation invitation to the personal email address on the HR record (or one an administrator enters, marked as an unverified personal contact) at an employer-set lead time before the start date (default 7 days, 0 to 30), with reminders through AUTH-FOLLOWUP-001 and a notice to the hiring manager if it is still unused 2 days before start. The activation link is single use, bound to the person and expires after a set period (default 7 days); reissuing it voids the old one. Opening it proves the personal address; employer policy may add a second check (an SMS code to the HR-recorded mobile number, or an ID-document and selfie check through Persona or CLEAR, whose result and not the document is stored). The hire then enrolls a passkey and the Auth authenticator (AUTH-AUTHENTICATOR-001), and a password where AUTH-ENROLLMENT-001 enables it. Enrollment grants nothing before the authorized start (AUTH-TIMING-001): launcher tiles read "available from" the start time, and every launch, token, SAML, RADIUS and desktop sign-in is refused until then. A hire who has not enrolled by the start uses a temporary access pass (AUTH-TAP-001). An HR start-date change moves the gate; a rescinded offer revokes the enrollment and its factors. The personal address is used only for activation and for recovery notices the employer enables, never as a work sign-in identifier.

CT policy ruling, 27 October 2026: Personal-contact activation is limited to the pre-start window. Auth must not dispatch an initial activation, reissue, retry or reminder to the personal address at or after the current authorized employer-local start time. Recheck the current start time, rescission and sending authority immediately before dispatch. A lead time of zero creates no permitted personal-email activation window and grants no exception. At or after start, only employer-enabled recovery notices may use that address under their existing controls.

Before personal-contact dispatch, record the employer’s authority to use the contact for transactional onboarding and its responsibility for required notice and consent. Importing an address does not prove mailbox ownership or legal consent; opening activation proves only the personal address. The address never becomes a work sign-in identifier or administrator credential.

Preserve day-one onboarding: an unenrolled hire requires the existing temporary-access-pass path, with recorded verification, a manager request where applicable, and issuance by authorized administration or group-scoped help desk. Owner-only handling is interim and cannot satisfy this workforce promise. Existing administrator proof, role scope, enrollment restrictions and start-time access gates remain binding. This ruling removes no original acceptance obligation.

**Acceptance.**
1. From an HR test source, add a hire starting in 10 days with a 7-day lead time; see no invitation until 7 days before start, then the invitation at the HR personal address.
2. Enroll a passkey and push before start; be refused app launch and token issuance until the start time, then launch.
3. Let a second hire's link expire, reissue it and refuse the old link.
4. Move a start date earlier and later and see the gate follow; rescind an offer and see the enrollment revoked.
5. Confirm no message reaches the personal address after start except enabled recovery notices.
6. Assert one initial activation dispatch within a permitted pre-start lead window.
7. For initial activation, explicit reissue, queued retry and reminder, assert zero activation dispatches exactly at start and after start.
8. With lead time zero, assert zero personal activation dispatches and expose the unenrolled hire’s required temporary-pass next step. Move start earlier and later immediately before dispatch and assert the current schedule governs; rescind the offer and assert no dispatch. Refuse personal-contact dispatch without recorded employer authority. Exercise the permitted recovery-notice case separately. Complete the manager-request and scoped-help-desk temporary-pass journey, including refusal outside scope. Preserve the original HR-source, delivered-recipient, enrollment and access-gating journeys; local dispatch assertions alone do not prove them.

**Evidence.** `tests/auth/onboarding.test.mjs` — future hire activates once at the lead boundary, enrolls with personal proof only, and obeys changed start times at protocol doors; expiry, explicit reissue, duplicate addresses and rescission never merge identities or retain enrollment authority; future-hire administration refuses missing, weak, foreign and expired authority and invalid local schedules; `tests/integration/browser.test.mjs`; `docs/onboarding.md`; `tests/auth/onboarding.test.mjs` — activation dispatch uses recorded employer authority and the current schedule at every queued transport boundary; `tests/auth/temporary-passes.test.mjs` — manager verification and scoped issuance give a one-use pass that enrolls after work email proof and ends its restricted session; temporary pass authority follows current group, manager, revocation, expiry and privileged-target protection
**Gap.** Administrator-created hires support unverified personal contacts, employer-local start times, bounded lead time, digest-only single-use activation, passkey enrollment, reissue and rescission. Personal activation is enrollment-only; ordinary work-address proof remains required for application access. Local scheduling and native SAML and OIDC gates are proved. HR-source ingestion and start-date qualification, authorized HR test source and verified delivery recipient, live delivered invitations and reminders, manager escalation with outbound authority, optional SMS and Persona or CLEAR checks, Auth authenticator and password enrollment, temporary-pass fallback, downstream joiner provisioning, RADIUS, desktop and every other device or network acceptance point remain unproved. Uncertain activation delivery needs explicit reissue. Zero-day lead has no pre-start activation window; late enrollment still depends on the unbuilt temporary-pass path. CT policy approval does not complete AUTH-ONBOARD-001. Zero-day and missed-window onboarding still require the unbuilt AUTH-TAP-001 fallback and its scoped issuance and refusal proof. Recorded personal-contact authority, required notice and consent handling, dispatch-boundary proofs for initial activation, reissue, retry and reminder, and live recipient proof remain unestablished. Mail accepted by a provider before start may arrive afterward; the original delivered-message acceptance sentence remains unproved, including that in-flight delivery boundary. The strict cutoff is interim and does not remove day-one onboarding or any existing acceptance obligation. Native contact-authority recording, dispatch-boundary refusals for initial sends and explicit reissues, retries and reminders, and hosted manager-requested scoped temporary-pass enrollment are implemented; the complete AUTH-TAP-001 obligation, live recipient delivery and in-flight provider boundary remain open.

#### AUTH-TAP-001 — Temporary access pass

Core · target · **partial**

**Requirement.** Help desk, within its AUTH-ROLES-001 scope, or an administrator issues a temporary access pass after a recorded verification using AUTH-RECOVERY-003's methods (manager attestation, a remaining factor, or a Persona or CLEAR check); a manager can request one for a direct report. Auth generates the pass (at least 12 random characters), shows it once to the issuer for delivery in person, by phone or through the manager, and stores only its digest. Policy per group sets its lifetime (default 1 hour, minimum 10 minutes, maximum 8 hours, optionally starting at a joiner's start time) and whether it is single use (the default) or reusable within its lifetime for a first day with several devices. The pass is accepted at the hosted web sign-in and at the AUTH-DESKTOP-001 Mac and Windows login windows, including the first login on a zero-touch Mac or PC, where it creates or binds the local account. It authorizes only enrolling a durable factor (passkey, Auth authenticator, or password where enabled): it never satisfies app MFA or step-up, never launches an app, is never accepted by RADIUS, LDAPS, WS-Trust or a token endpoint, and the session it opens ends when enrollment completes. Issuing a pass for an administrator or privileged role is refused; they follow AUTH-IDENTITY-001. Issue, use, expiry and revocation are audited, and the person and their manager are notified (AUTH-NOTIFY-001).

**Acceptance.**
1. As help desk scoped to a new hire's group, record manager attestation and issue a pass.
2. At a fresh Mac's login window (Platform SSO) and at a fresh Windows PC, sign in with it, create the local account and enroll a passkey.
3. Refuse the pass on reuse, after expiry, at an app launch, at app MFA step-up and at GlobalProtect RADIUS.
4. Refuse issuance without a recorded verification, outside the issuer's scope and for an administrator.
5. Inspect the audit trail and the notices.

**Evidence.** `tests/auth/temporary-passes.test.mjs` — manager verification and scoped issuance give a one-use pass that enrolls after work email proof and ends its restricted session; temporary pass authority follows current group, manager, revocation, expiry and privileged-target protection; `tests/integration/browser.test.mjs` — real Auth pages, via temporaryPassJourney in `tests/integration/helpers/temporary-pass-journey.mjs`
**Gap.** Native onboarding-only manager attestation, scoped issuance, digest-only custody, hosted redemption, real work-email confirmation and passkey enrollment are implemented. Group lifetime policy, optional reusable passes, scheduled validity, remaining-factor and identity-provider verification, general recovery targets, desktop login and local account creation, RADIUS refusal, and employee and manager notices remain unproved.

#### AUTH-EXPERIENCE-001 — Hosted and embedded identity journeys

Core · target · **partial**

**Requirement.** Employers configure an accessible branded sign-in, enrollment, account and recovery experience on their chosen verified host. React/Next.js components embed the same server-enforced user, membership and organization controls; a versioned journey editor composes approved verification and step-up steps without arbitrary client-side authorization. Preview, test and rollback preserve anti-enumeration, trusted redirects, emergency access and the strict RER profile.

**Acceptance.**
1. Configure branding and an employee journey, use both hosted and embedded account/membership screens, preview a changed MFA step and roll it back.
2. At 1440 and 390, in light/dark with keyboard and assistive technology, complete sign-in/recovery and expose durable errors without leaking hidden fields.

**Evidence.** `src/ui/pages/signin.ts`; `src/ui/pages/account.ts`; `tests/integration/browser.test.mjs`
**Gap.** hosted responsive pages exist; branding controls, embedded components and journey orchestration are missing.

#### AUTH-LOCALE-001 — End-user display languages

Core · target · **missing**

**Requirement.** Every employee-facing surface is available in at least 30 display languages: the hosted sign-in, activation, enrollment, recovery, account and launcher pages, the browser extension (AUTH-SWA-001), the macOS and Windows login extensions (AUTH-DESKTOP-001), the iOS and Android app including push and number-matching text (AUTH-AUTHENTICATOR-001, AUTH-MOBILE-001), and every notification email and SMS (AUTH-NOTIFY-001, AUTH-ONBOARD-001). The set includes English, Spanish (United States and Latin America), Simplified and Traditional Chinese, Vietnamese, Tagalog, Korean, Arabic, Russian, Haitian Creole, French, Portuguese (Brazil), German, Japanese, Hindi, Polish and Italian, with right-to-left layout for Arabic. A person's language is, in order: their own choice in My account; else the preferred language from their HR source (AUTH-HRIS-001); else the employer's default for their organization or group; else the browser or device language. Anyone can switch language on the sign-in page before signing in. Dates, times and numbers follow the language and the person's own time zone. Employer-customized text (branding copy, journey messages, notification templates, bookmark tile names) is entered per language with the employer default as fallback, and preview flags each untranslated string. Security text (number matching, push context, recovery and lockout warnings) is never shown untranslated in a supported language. The administrator console ships in English and Spanish.

**Acceptance.**
1. Set a person's language to Spanish and complete activation, sign-in, push approval with number matching, password reset, the launcher, an extension fill and the Mac login window entirely in Spanish; receive the new-device and password-changed notices in Spanish.
2. On the sign-in page switch to Arabic and complete sign-in at 390 in right-to-left layout.
3. Leave an employer notification template in English only and see the English fallback used and flagged in preview.
4. A build check fails when any end-user string key is missing from a supported language.

**Evidence.** `src/ui/shell.ts`; `src/ui/pages/signin.ts`
**Gap.** every page renders English only (`lang="en"`); language selection, translations and per-language employer text are missing.

#### AUTH-LAUNCHER-001 — Employee app launcher

Core · target · **partial**

**Requirement.** Every employee gets a searchable dashboard of assigned SaaS, legacy and RER apps—SAML, OIDC, and password-based apps signed in through the Auth browser extension (AUTH-SWA-001)—with favorites, recently used apps and clear access-request actions. Each tile opens the correct employer/role and explains an unprovisioned, denied, expired or connector-blocked assignment. Administrators also add bookmark tiles, a named link with an icon assigned by group, for intranet pages and apps with no SSO; a bookmark carries no credential or assertion. Unassigned apps do not yield working launch assertions or filled credentials; app owners can publish instructions for apps requiring a separate client or VPN.

**Acceptance.**
1. As an employee with Google Workspace, Slack, AWS, a password-only app and a RER app assigned, launch each into its proper account.
2. Request an unassigned app, remove an assignment and expire a temporary grant; the dashboard, the extension and direct launch all enforce the changed access.
3. Assign a bookmark tile to a group and see it only for members.

**Evidence.** `src/auth/launcher/index.mjs`; `tests/auth/saml.test.mjs` (launcher preferences never grant access); `tests/auth/oidc-apps.test.mjs` (wrong, mismatched and rotated-out secrets); `tests/integration/company-apps-browser.test.mjs` (company apps journey); `tests/auth/access-decisions-flow.mjs` (requestDecisionsFlow); `tests/auth/review-reduction-flow.mjs` (reviewReductionFlow)
**Gap.** Native search, per-person durable favorites and recent opens, request links using the existing passkey decision flow, group-only credential-free bookmarks, and denied, expired, unprovisioned and connector-blocked explanations are implemented. Shared native assignment checks refuse removed and expired temporary grants at SAML launch and OIDC authorization and token issuance; saved preferences confer no access. Held: password-app tiles and extension fill and enforcement need the browser-extension release; RER tiles need the Base local link and Spool owner-link path; the complete five-app journey needs authorized Google Workspace, Slack and AWS tenants and a password-app account. Native protocol peers do not establish vendor or extension qualification.

#### AUTH-SWA-001 — Password-based app sign-in

Core · target · **missing**

**Requirement.** Apps whose plan has no SAML or OIDC are first-class launcher apps. An Auth browser extension for Chrome, Edge, Firefox and Safari (macOS and iOS) recognizes the app's sign-in page from its recipe, fills and submits the credential only on the recipe's exact origins, and offers the same on direct visits. Employers can force-install and preconfigure the extension (Auth tenant URL, sign-in required) through Jamf Pro, Kandji, Microsoft Intune and Google Chrome Enterprise policy, so employees cannot remove it on managed devices. App administrators choose per app between admin-set shared credentials (employees never see the password) and user-set individual credentials, and may let Auth generate strong passwords to a recipe's length/character rules and rotate them. Credentials are encrypted per person under keys Auth never sends to model context, logs or exports; shared credentials are released only to currently assigned people, and reveal, copy and change are policy-controlled and audited. Unassigning or offboarding a person removes their access in the extension immediately, and the leaver plan (AUTH-LIFECYCLE-001) rotates every shared credential they could use and records each password-only app as an access obligation until rotated or confirmed removed. AUTH-MIGRATION-001 imports Okta SWA app definitions (URL, field selectors, credential scheme) and leaves credentials to re-entry or a guided admin import. This is app sign-in, not a general personal password manager.

**Acceptance.**
1. Install the extension in each of the four browsers, and force-install it preconfigured through Intune on Windows and Jamf Pro on macOS, assign a shared-credential and an individual-credential app, sign in from the launcher and by direct visit, generate a password and refuse fill on a lookalike origin.
2. Unassign one employee and offboard another; their next fill is refused within 60 seconds, the shared password is rotated, and the audit shows every reveal, fill and rotation without the secret.
3. Import an Okta SWA app definition and launch it.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

### Authentication, SSO and policy

#### AUTH-MFA-001 — Passkey-first multifactor policy

Core · target · **partial**

**Requirement.** Employers require phishing-resistant platform/synced passkeys or hardware security keys, offer TOTP and single-use recovery codes under explicit assurance rules, and control enrollment, replacement and factor loss. SMS/email are policy-limited bootstrap/recovery alternatives with lower assurance, never equivalent to a security key. The Auth mobile authenticator (AUTH-AUTHENTICATOR-001) adds push with number matching and its own TOTP; each factor's assurance (phishing-resistant, push, TOTP, SMS/email) is published and policy chooses which satisfy which app, RADIUS flow (AUTH-LEGACY-001) and OS login (AUTH-DESKTOP-001). Factor inventory, lost-factor revocation, step-up and the named employee security notifications of AUTH-NOTIFY-001 cover web, desktop and native mobile; a lost factor without a recovery code is restored the same business day under AUTH-RECOVERY-003. Existing hardware-passkey and fresh local email gates for interactive Auth administration by the roles AUTH-DECISIONS-001 lists remain mandatory.

**Acceptance.**
1. Enroll a platform passkey, hardware key, Auth push and TOTP, require step-up for a sensitive app, revoke a lost factor and consume a recovery code once.
2. Deny downgraded admin access and prove factor removal/rotation reaches current sessions according to policy.

**Evidence.** `src/auth/passkeys.mjs`; `src/auth/local-email.mjs`; `tests/auth/security.test.mjs`; `tests/auth/local-email.test.mjs`
**Gap.** hardware passkeys and local email step-up exist; configurable factor policy/TOTP/recovery codes do not.

#### AUTH-AUTHENTICATOR-001 — Push authenticator in the Auth mobile app

Core · target · **missing**

**Requirement.** The iOS and Android Auth app (AUTH-MOBILE-001) enrolls as an authenticator bound to a device key held in the Secure Enclave/StrongBox and protected by biometrics or device PIN. It delivers push approvals showing the requesting app, employee, approximate location, IP, device and time, with number matching (the employee types the number shown on the sign-in screen) wherever the requesting flow can display one; it also generates TOTP offline. Push carries no approval in the notification payload itself: approval is a signed response from the enrolled device key, single use and bound to the transaction, expiring after 120 seconds. Denying a push refuses the sign-in and optionally reports it as suspicious, which notifies the security owner and can suspend further pushes to that person (push-fatigue control: rate limit and automatic number matching after repeated denials). Phishing-resistant passkeys remain the default for browser sign-in; push and TOTP are the stated factors for RADIUS/VPN, Wi-Fi and other flows where a passkey cannot cross the protocol, and policy can require a passkey instead wherever one can. Lost-device removal invalidates the device key at once.

**Acceptance.**
1. On real iOS and Android builds, enroll the authenticator, approve a web sign-in with number matching, deny another and see it refused and reported, and complete a sign-in with the app's offline TOTP.
2. Replay an approval, answer after expiry and answer from a second unenrolled device; each is refused.
3. Send repeated pushes and observe the fatigue control; remove the device and prove its next approval is refused.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-POLICY-001 — Conditional access and session policy

Core · target · **partial**

**Requirement.** Versioned policies combine employee/group/app/role, authentication assurance, managed-device posture, IP/network/location, the named behavior signals of AUTH-RISK-001 (new device, new country/state/city, geo-location radius, velocity, IP reputation) and session age; no condition is an unexplained score. Administrators simulate impact before publishing; an explainable decision records the matched rule, each signal's value and evidence freshness. Deny or require step-up when posture is missing/stale, enforce idle/absolute session lifetime and fresh authentication on critical actions, and reevaluate when membership, location, device or policy changes. Emergency accounts are explicitly bounded, monitored and drilled rather than a blanket bypass. Future machine administration doors inherit AUTH-ADMINAPI-001 credential, scope/resource, excluded-action, live-authority, audit and concurrency checks before shipping.

**Acceptance.**
1. Preview and publish a payroll-app rule requiring a managed US device and fresh passkey; attempt allowed, foreign-network, stale-posture and expired-session launches through app and direct protocol routes.
2. Add an AUTH-RISK-001 "step up on new country" condition and see a new-country sign-in stepped up with the signal named in the decision.
3. Change group/policy during sign-in and verify the current decision at token issuance.

**Evidence.** `src/auth/domain-policy.mjs`; `src/auth/authorization-login.mjs`; `tests/auth/authorization-policy.test.mjs`; `tests/auth/upstreams.test.mjs`
**Gap.** current domain, session and prompt/max-age checks exist; general device/location/risk engine is missing.

#### AUTH-ABUSE-001 — Automated attack protection

Core · target · **partial**

**Requirement.** Configurable bot challenges, suspicious-IP/device throttling, credential-stuffing and brute-force detection, breached-password screening, lockout and user/security-team notification protect every enrollment, sign-in, reset and token endpoint. Decisions are tenant-scoped and observable, avoid account enumeration and do not let a remote attacker permanently lock out emergency recovery. Risk-driven step-up uses AUTH-RISK-001's named signals, lockout and self-service unlock follow AUTH-PASSWORD-001 and AUTH-PASSWORD-002, and the user notification is AUTH-NOTIFY-001's; all retain the same account proof and administrator controls.

**Acceptance.**
1. Attack real authentication/reset/token HTTP doors with bot traffic, password spraying, a breached password and distributed source attempts; observe rate limits/lockouts, protected notifications and legitimate recovery.
2. Sign in through a Tor exit and from a location implying impossible travel, and verify step-up or denial with the AUTH-RISK-001 signal named in an explainable log.

**Evidence.** `src/auth/abuse/index.mjs`; `tests/auth/abuse.test.mjs` (attack configuration; native attack doors; email responses; proved emergency recovery); `tests/auth/protocol.test.mjs` (token attack budgets); `tests/integration/security-settings-browser.test.mjs` (attack protection settings)
**Gap.** Tenant-scoped configurable native throttling is proven for email, WebAuthn, recovery and token requests, with durable aggregate and source budgets, bounded cooldowns, explained refusal audit and commit-time administrator hardware and fresh-email protection. Tor-exit and impossible-travel proof awaits AUTH-RISK-001 and licensed MaxMind feeds; password spraying, breached-password screening, lockout and unlock await AUTH-PASSWORD-001 and AUTH-PASSWORD-002; remaining bot-challenge controls and protected notifications under AUTH-NOTIFY-001 remain unproved.

#### AUTH-RISK-001 — Named sign-in behavior signals

Core · target · **missing**

**Requirement.** AUTH-POLICY-001 rules use named, tunable behavior signals, each computed from the person's own sign-in history: new device (a browser or device not seen within the person's last N successful sign-ins, by device cookie or bound device key; N defaults to 20); new country; new US state; new city; new geo-location beyond a set radius (default 20 km) from all of the last N locations; velocity (implied travel speed from the previous successful sign-in above a set threshold, default 805 km/h, about 500 mph); new IP address and new network (ASN); and IP reputation: anonymizing proxy or VPN service, hosting provider and Tor exit node from a named, dated IP-intelligence feed (MaxMind GeoIP2 with Anonymous IP by default), an employer block list and employer-trusted corporate networks. Recent failed attempts and denied pushes are also signals. Each signal is a boolean or a number in the rule language, so "step up on new country, allow new city, deny Tor" is a rule an employer writes directly. Data that is unavailable (for example a failed location lookup) has its own named value, and the rule states what it does then. Signals are evaluated at every sign-in and token issuance through every door: web, OIDC, SAML, WS-Federation, desktop, and RADIUS where the connector reports the client IP. A summary risk level may be displayed, but it is always broken down into the signals that produced it; no rule can depend on an opaque score. Each decision records the signal values and the feed versions it used, and AUTH-POLICY-001 simulation replays the last 30 days of sign-ins against a draft rule.

**Acceptance.**
1. Publish "step up on new country, allow new city, deny Tor" for a group.
2. Sign in from a known location and pass; from a new US city and pass with "new city" logged; from a new country and be stepped up; from a location implying 900 km/h travel since the previous sign-in and be stepped up with velocity logged; through a Tor exit and be denied.
3. Change the radius and look-back and see the next decision follow them.
4. Each decision log names the signal, its value and the feed version.
5. Simulate the draft rule over 30 days of history and see per-signal counts.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-NOTIFY-001 — Employee security notifications and suspicious-activity reports

Core · target · **partial**

**Requirement.** Auth sends each employee named security notifications by email to the work address, and as a push in the Auth app where enrolled, for: sign-in from a new device or browser (AUTH-RISK-001's new-device signal), with app, time, approximate location, IP and device; factor enrolled; factor reset or removed, by them or by help desk; password changed or reset; password locked; recovery started (with its cancel action); temporary access pass issued; and an administrator role granted. Employers can turn off individual types except recovery started, factor reset or removed, and administrator role granted, which always send. Every notification carries a one-click "Report suspicious activity" action that works from the email without signing in (a signed, single-use link valid for 7 days) and from the Auth app. A report records a suspicious-activity event linked to the triggering event, alerts the security owner through AUTH-FOLLOWUP-001 (email, Slack or Teams, and Oncall per policy), and by policy ends all the person's sessions and refresh grants with back-channel logout and in connected SaaS apps (AUTH-LOGOUT-002), requires a password reset and factor review at next sign-in, or suspends the person pending help desk. Reports and their outcomes are audited, appear in AUTH-AUDIT-001 investigations and stream to the configured SIEM. A notification never contains a sign-in link or code that could itself confer authority.

**Acceptance.**
1. Sign in from a new browser and receive the new-device email with its stated context.
2. Enroll a factor, have help desk reset a factor and change a password, and receive each notification.
3. From the new-device email, while signed out, click "Report suspicious activity": see the security owner's escalation in Slack and, under the end-sessions policy, the person's sessions ended and a linked app's back-channel logout delivered.
4. Refuse the report link's reuse and use after expiry.
5. Turn off new-device notices and receive none; try to turn off recovery notices and be refused.

**Evidence.** `tests/auth/notifications.test.mjs` — "security notifications report suspicious activity, escalate once and end sessions and refresh grants with back-channel logout" proves contextual new-device email, bound app context, signed-out one-use report, linked event stream and Activity, Slack escalation, follow-up, Auth session and refresh ending, and native app back-channel delivery. "security notice preferences retain mandatory recovery and factor notices, and report links refuse forgery, cross-employer use and expiry" proves factor enrollment, scoped help-desk reset, recovery cancellation, role notices, optional new-device off, mandatory recovery off refusal, signature, issuer and expiry. `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation" proves policy consent authority. `tests/integration/security-settings-browser.test.mjs` — "security settings: prove and revoke employer ownership, preview affected workers, and authorize persistent notification preferences at desktop and mobile" proves preference and report states at 1440 and 390 with tooltips. Live receipt sx-auth-c-i817-notifications-live: 6 messages accepted and received; received report escalated to the configured fleet Slack destination, ended sessions and refused reuse. `docs/security-notifications.md`.
**Gap.** Push notices depend on AUTH-AUTHENTICATOR-001. Password-changed and password-lockout notices depend on AUTH-PASSWORD-001; temporary access pass notices depend on AUTH-TAP-001. Remaining: all factor-removal and role-grant doors, connected SaaS session revocation under AUTH-LOGOUT-002, additional report responses, Oncall escalation and configured SIEM qualification. Conservative default awaiting ct approval: owner or passkey administrator plus fresh email must explicitly authorize the new email channel and recipients; mandatory types cannot subsequently be disabled, and Slack or destructive report responses require separate audited consent. Existing recovery notices continue before that initial consent.

#### AUTH-LOGOUT-002 — Universal logout from connected SaaS for a compromised account

Core · target · **partial**

**Requirement.** When an account is suspected compromised but the person is not leaving, Auth ends their sessions inside connected SaaS apps as well as in Auth, without deprovisioning them. Triggers are: an administrator's or help desk's "End all sessions" action on a person within their AUTH-ROLES-001 scope; an AUTH-NOTIFY-001 suspicious-activity report under the end-sessions policy; an AUTH-POLICY-001 rule on AUTH-RISK-001 signals (for example a Tor-exit or impossible-travel sign-in after a successful one); and an approved AUTH-AGENT-002 or AUTH-AGENT-005 action. Auth ends every Auth session and refresh grant, sends back-channel logout to linked apps (AUTH-LOGOUT-001), and calls each connected app's session-revocation API: Google Workspace (Admin SDK Directory `users.signOut` and deletion of the user's OAuth tokens), Microsoft 365 (Microsoft Graph `revokeSignInSessions`), Slack (`admin.users.session.reset`, Enterprise Grid), Zoom (revoke the user's SSO token), Salesforce (revoke the user's OAuth tokens and end their sessions) and GitHub Enterprise (remove the user's SAML SSO credential authorizations). Every AUTH-CATALOG-002 recipe states whether it supports session revocation, token revocation or neither. The person stays active; by policy their next sign-in requires a passkey or factor review and a password reset under AUTH-PASSWORD-002. For each app Auth records dispatch, vendor acknowledgment and, where the vendor allows, verification by read-back or a denied-access probe, within AUTH-TIMING-001's downstream bounds (dispatch within 60 seconds, verification within 5 minutes), shown per app as locally denied, acknowledged, verified, unsupported or failed. An unsupported or failed app stays an AUTH-FOLLOWUP-001 obligation showing its residual risk and manual step. The action is audited with its trigger and per-app outcome, and the person is notified (AUTH-NOTIFY-001). This is the job Okta's Universal Logout in Identity Threat Protection does.

**Acceptance.**
1. In authorized Google Workspace, Microsoft 365, Slack Enterprise Grid, Zoom and Salesforce test tenants, sign a person in to each through Auth on the web and in each vendor's desktop or mobile client.
2. From a new-device notice, report suspicious activity under the end-sessions policy: within 60 seconds the person's Auth sessions and a linked app's session end; within 5 minutes each vendor's API shows the sessions or tokens revoked, and each web and client session is refused at its next request, while the person stays active and signs in again with a passkey.
3. Repeat from help desk's End all sessions action and be refused outside the holder's scope.
4. An app with no revocation API is shown as unsupported with its manual step, and a vendor failure stays an open obligation.

**Evidence.** `src/auth/links/logout.mjs`; `src/auth/index.mjs`; `tests/auth/linking.test.mjs`
**Gap.** Sign out everywhere ends the person's own Auth sessions and signs them out of linked RER apps by back-channel logout; ending another person's sessions, report and risk triggers, and vendor-API revocation in SaaS apps are missing.

#### AUTH-SAML-001 — SAML 2.0 workforce identity provider

Core · target · **done**

**Requirement.** Auth supplies SP-initiated and explicitly permitted IdP-initiated SAML SSO for company apps, with per-app metadata import/export, entity IDs, exact ACS allow-lists, NameID/attribute/group/role mappings (AUTH-MAPPING-001) and certificate rollover with overlapping publication. Every release supports at minimum: HTTP-POST and HTTP-Redirect bindings for AuthnRequest and Response; RSA-SHA256 and RSA-SHA512 signatures, chosen per app, on the response, the assertion or both; optional assertion encryption with AES-256-GCM or AES-128-CBC content encryption and RSA-OAEP key transport; SP-initiated and IdP-initiated Single Logout over HTTP-Redirect and HTTP-POST; and the `persistent`, `emailAddress`, `unspecified` and `transient` NameID formats. RSA-SHA1 is accepted only as a named per-app compatibility exception. Auth validates request signatures where configured, destination, audience, request correlation, time windows (at most 5 minutes' clock skew) and replay; setup exposes incompatible profiles rather than claiming universal SAML compatibility.

**Acceptance.**
1. Configure a generic SAML SP through the admin door, launch as an assigned employee over each binding, validate mapped role/NameID in each of the four formats, sign the response, the assertion and both with SHA-256 and SHA-512, decrypt an encrypted assertion with each named algorithm at the SP, and roll certificates with overlap.
2. Complete SP- and IdP-initiated logout over both bindings.
3. Refuse a forged request, altered ACS, wrong audience, SHA-1 without an exception, stale/replayed assertion and unassigned user.

**Evidence.** `src/auth/saml/`; `src/auth/workforce/routes.mjs`; `tests/auth/saml.test.mjs`; `tests/integration/company-apps-browser.test.mjs`
**Gap.** Limits: attributes use fixed directory sources or versioned expressions (AUTH-MAPPING-001); metadata is pasted, not fetched by URL; RequestedAuthnContext is not interpreted.

#### AUTH-OIDC-001 — General SaaS OIDC and OAuth profiles

Core · target · **done**

**Requirement.** Alongside the unchanged AUTH-PROTOCOL-001 RER profile, app administrators register ordinary SaaS/web/native OIDC clients with discovery, exact redirects, the authorization code flow, scopes, claim mappings (AUTH-MAPPING-001) and per-app public or pairwise subjects. Supported client authentication methods are listed in discovery and chosen per client: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, and `none` for public clients, which must use PKCE (S256); confidential clients may also be required to use PKCE. Client secrets are generated by Auth with at least 256 bits, shown once, stored hashed, and rotated with an overlap window. The implicit and hybrid flows are available only as a named per-app opt-in for legacy SaaS that requires them. None of this loosens existing RER registrations, which keep `private_key_jwt` and mandatory PKCE. Generic clients receive documented consent, session, UserInfo, logout (RP-initiated, front-channel and back-channel) and key-rotation semantics; denied grants cannot mint tokens.

**Acceptance.**
1. Register confidential SaaS clients with each of `client_secret_basic`, `client_secret_post` and `private_key_jwt`, and a public native client with `none` plus PKCE, through the catalog/API; complete code flows and logout for each and rotate a secret with overlap.
2. Refuse a wrong or rotated-out secret, a public client without PKCE, redirect substitution, token substitution, code replay and unsupported grants.
3. Re-run the strict RER journey unchanged and inspect each connection’s advertised profile.

**Evidence.** `src/auth/oidc-apps/`; `src/auth/protocol.mjs`; `src/auth/links/end-session.mjs`; `tests/auth/oidc-apps.test.mjs`; `tests/integration/company-apps-browser.test.mjs`; `COMPANY-APPS.md`
**Gap.** Limit: a fresh install signs only with keys published five minutes earlier.

#### AUTH-MAPPING-001 — Attribute and NameID transform language

Core · target · **done**

**Requirement.** Per-app SAML attributes, NameID and OIDC claims, SCIM/API attribute pushes and generated usernames are computed by a documented, versioned expression language over the person's directory, source and group data. It offers string functions (concatenate, lower/upper case, substring, replace, regular-expression replace, trim, pad), conditionals and null handling, date formatting, group-membership tests and list filters, and lookups of the person's manager and source fields—enough to express, for example, a `first.last` username or an app role chosen from group membership. Expressions are typed, side-effect free, cannot read secrets or make network calls, and are bounded in run time. The editor previews each expression's output for chosen people before saving, flags people for whom it yields empty or duplicate values, and every change is versioned and audited.

**Acceptance.**
1. Through the app setup door, map NameID to a computed `first.last` value with a collision suffix, map a role from group membership and push a formatted date over SCIM; preview against three people including one with a missing field, then launch and provision and read the values back at the SP and SCIM service.
2. Refuse an expression that reads a secret, calls out or exceeds the time bound; roll back to the previous version.
3. Exact semantics: language version 1 is typed JSON over an explicit directory/source/manager/group projection, with no credential/runtime access, dynamic code or network operations.
4. Character work, depth, nodes, output size and elapsed time are bounded.
5. Preview allocates collision suffixes against the entire directory; a save requires the exact preview and current version, and rollback publishes a new audited version.
6. Current output doors are SAML, generic OIDC and SCIM.
7. AUTH-CATALOG-002 API provisioning adapters and AUTH-LIFECYCLE-001 future provisioning doors inherit these same computed values before shipping.

**Evidence.** `tests/auth/saml.test.mjs` ("app setup previews typed mappings for three people, launches computed collision-safe NameID and group role, provisions formatted dates, refuses unsafe programs and rolls back an audited version": three-person missing/duplicate preview, independent SP and SCIM read-back, secret/network/type/budget refusals, version rollback and audit); `tests/auth/oidc-apps.test.mjs` ("SaaS clients sign in with client_secret_basic, client_secret_post and private_key_jwt, and a native app with none and PKCE; RP-initiated logout reaches front- and back-channel apps": computed ID-token claim); `tests/integration/company-apps-browser.test.mjs` ("company apps journey: the owner adds a SAML app from its metadata, an OpenID Connect app, a group and assignments; an employee signs in through Auth, and loses both when removed, at desktop/mobile in both themes": editor, preview and save at 1440 and 390); `docs/attribute-mapping.md`
**Gap.** None.

### SaaS, directories and workforce lifecycle

#### AUTH-CATALOG-001 — Production SaaS application catalog

Core · target · **partial**

**Requirement.** A maintained catalog configures Google Workspace, Microsoft 365, Slack, GitHub Enterprise, AWS IAM Identity Center, Salesforce and Zoom for SAML/OIDC SSO and supported lifecycle APIs/SCIM. Each recipe states required vendor edition/permissions, groups/roles, attribute ownership, test-user procedure, secret/certificate rotation and deactivation/session limits. Administrators can clone a recipe into a generic connector, securely enter provider credentials, test, preview changes, approve and roll back. A catalog label alone is not a working integration. These seven are the deep-journey anchors; catalog breadth is AUTH-CATALOG-002 and Microsoft 365 domain federation is AUTH-M365-001.

**Acceptance.**
1. For each of the seven named services, an authorized US test tenant connects from catalog, assigns a test group/role, creates or binds the correct account, launches SSO, changes role and offboards it; read back remote state and document any external-session limit.
2. Inject one provider denial and prove it remains unresolved.

**Evidence.** `src/auth/catalog/recipes.mjs`; `tests/auth/catalog.test.mjs`
**Gap.** Google Workspace, Microsoft 365, Slack, GitHub Enterprise Cloud, AWS IAM Identity Center, Salesforce and Zoom recipes fill a working SAML app and, for the SCIM vendors, a provisioning connector, and state edition, permissions, roles, attributes, test-user procedure, certificate rotation and session limits. Missing: every authorized vendor-tenant journey (needs accounts), the Google Directory API and Microsoft Graph provisioning adapters, and Zoom's client-credentials token refresh.

#### AUTH-CATALOG-002 — Catalog breadth and verification cadence

Core · target · **missing**

**Requirement.** The catalog carries at least 100 tested recipes for the SaaS apps US small and mid-size companies use most, each tagged SAML, OIDC, SWA (AUTH-SWA-001), SCIM or vendor API, with SCIM or API provisioning wherever the vendor offers it on any plan, and the plan it needs named. The minimum set includes, beyond AUTH-CATALOG-001's seven: Atlassian (Jira, Confluence via Atlassian Guard), Zendesk, HubSpot, Dropbox, Box, Notion, Asana, 1Password, DocuSign, Miro, Figma, Linear, monday.com, Smartsheet, Airtable, Calendly, Adobe Creative Cloud, Canva, Intercom, Freshdesk, ServiceNow, Jamf Pro, Kandji, CrowdStrike Falcon, Datadog, PagerDuty, Snowflake, Tableau, Expensify, Ramp, Brex, BILL, QuickBooks Online, NetSuite, Greenhouse, Lever, Gong, Loom, Webex, RingCentral, Dialpad, GitLab, Bitbucket, Sentry, Cloudflare, Google Cloud, Lucid, Coupa, Carta, Vanta, Drata, Secureframe, Thoropass, Lattice, Culture Amp, Rippling, Gusto, BambooHR, Workato, Zapier, Retool and Postman. A public catalog page publishes the recipe count, each recipe's supported features and its last-verified date. Every recipe is re-verified against a vendor sandbox or authorized test tenant at least every 90 days and within 14 days of a vendor-announced breaking change; a recipe past its date is marked stale in the catalog and at activation, never silently served as verified. The Vanta, Drata, Secureframe and Thoropass recipes carry, beyond sign-in to the platform, the AUTH-COMPLIANCE-001 identity-provider connector, and every recipe states whether the app supports AUTH-LOGOUT-002 session or token revocation. Employers can request a recipe, and AUTH-AGENT-001 drafts new ones for human review. Future API/provisioning doors inherit AUTH-MAPPING-001 computed-value validation and preview/version semantics.

**Acceptance.**
1. The catalog door lists at least 100 recipes, every one named above among them, each with protocol tags and a last-verified date within 90 days.
2. A random sample of 10 recipes, drawn by the test run, each passes AUTH-CATALOG-001's connect/assign/launch/role-change/offboard journey with remote state read back.
3. Age one recipe past its date and see it marked stale at the catalog and at activation.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-M365-001 — Microsoft 365 domain federation and licensing

Core · target · **missing**

**Requirement.** Auth federates an employer's Microsoft 365 domain as its identity provider using WS-Federation (passive) for browser and modern-authentication clients, with a WS-Trust 1.3 active endpoint for rich clients that still use it (workers on password compatibility only, whose password follows AUTH-PASSWORD-001 and AUTH-PASSWORD-002; passkey-only workers use modern authentication). Claims map the person's ImmutableID (`onPremisesImmutableId`, or Auth's stable source ID when no on-premises AD exists) as the `persistent` NameID/`ImmutableID` claim and the UPN as `IDPEmail`. The setup door converts a verified domain from managed to federated through Microsoft Graph (`internalDomainFederation`), first with Microsoft's staged-rollout group, and converts back to managed for rollback; it warns that Microsoft can take up to two hours to apply a change, schedules the cutover window and keeps a cloud-only emergency administrator outside federation. A tested client matrix is published and accepted: Outlook on the web, Outlook desktop for Windows and Mac, Teams desktop and mobile, OneDrive sync for Windows and Mac, Outlook mobile for iOS and Android, and Office desktop apps. Group-driven license assignment assigns and removes Microsoft 365 SKUs and service plans through Microsoft Graph, shows unused seats, and reclaims a leaver's licenses after the AUTH-WORKFLOWS-001 mailbox steps complete.

**Acceptance.**
1. In an authorized Microsoft 365 test tenant, federate a verified domain in a staged-rollout group, then fully; sign in with each client in the matrix and inspect the ImmutableID and IDPEmail claims.
2. Roll back to managed and sign in again.
3. Add a person to a licensing group and see the SKU assigned, remove them and offboard another, and see each license reclaimed in Microsoft's admin data; a client that fails is shown as a failed matrix row, never omitted.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-SCIM-001 — Outbound provisioning and deprovisioning

Core · target · **done**

**Requirement.** App/group assignments create, update, suspend/reactivate and deprovision users and groups using SCIM 2.0 or a declared vendor API. Administrators preview attribute/role/group push, collision decisions and destructive effects. Stable external IDs, pagination, PATCH/filter semantics, idempotency, rate limits, credential rotation, remote drift and partial failure are handled without duplicate people or privilege escalation. Disable locally first on a leaver; retain each remote obligation until actual app access and supported sessions/tokens are verified revoked. Changes are pushed on the event, not in a batch, within the AUTH-TIMING-001 bounds: dispatched within 60 seconds and remote state verified within 5 minutes for a healthy connector.

**Acceptance.**
1. Assign a group through admin UI/API to a real SCIM service, provision users/groups, change a role and email, then revoke while the provider returns 429/503 and later recovers.
2. Inspect one account per person, persisted per-app outcomes with dispatch and verification times inside the bounds while healthy, no duplicate side effect and verified deactivation rather than a green queue submission.

**Evidence.** `src/auth/provisioning/`; `src/auth/workforce/`; `tests/auth/provisioning.test.mjs`; `tests/auth/scim-server.mjs`
**Gap.** Limit: an email change travels the same update path (AUTH-DIRECTORY-001 edit door).

#### AUTH-SCIM-002 — Inbound directory synchronization

Core · target · **partial**

**Requirement.** Employers can make an authorized generic SCIM 2.0 provider, Microsoft Entra ID, Okta or Google Workspace directory the source for users, groups and membership. A source connector has a scoped credential, verified organization binding, source-of-truth fields, conflict preview and reconciliation bounded by AUTH-TIMING-001: pushed SCIM requests applied within 60 seconds, polled deltas at least every 15 minutes and a full reconciliation at least every 24 hours. Deleting an upstream record cannot silently delete audit or grant a reused email authority; a full-feed outage never means every employee left. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

**Acceptance.**
1. Connect each named directory and a generic SCIM client through setup, import paginated users/groups, apply a mover and deactivate a leaver.
2. Send a foreign-tenant request, duplicate event and incomplete/full-empty snapshot; verify isolation, stable IDs and a held destructive change pending confirmation.
3. CT policy ruling, 26 October 2026: Incoming observations remain staged until an authorized organization administrator approves one exact delivery, selected changes and preview digest with hardware passkey and fresh local email proof.
4. Receipt and staging grant no sign-in, enrollment, assignment or authority-changing effect.
5. Execution rechecks current approver authority, approved content and target; drift returns to review, and interruption recovery prevents duplicate effects.
6. Recurring pulls and later deliveries never approve themselves.
7. Missing or empty feeds never infer termination, and outbound reminders require separate audited consent.
8. For this interim approved-delivery profile, execution timing starts at exact approval or the approved future effective time. Record receipt, approval, effective and application times separately. Approval delay remains visible and cannot be excluded when assessing the complete receipt-to-application source promise. The original 60-second pushed application, 15-minute polling and 24-hour full-reconciliation targets remain unchanged; staging alone does not satisfy them or timely deprovisioning. An approved leaver event retains every AUTH-TIMING-001 local-denial and downstream obligation. AUTH-HRIS-002 exact-approval and interruption-recovery protections, AUTH-DIRECTORY-001 identity and planner protections, AUTH-HOOKS-001 import protections and AUTH-FOLLOWUP-003 consent and follow-through obligations remain inherited before their receiving doors ship. Every original acceptance point remains required.

**Evidence.** `tests/auth/directory.test.mjs` — "inbound directories and scoped SCIM stage immutable users and groups, require exact approval, retain incomplete feeds and fence reviewed leavers" (all four source adapters at their network edges, paginated users and groups, stable IDs, reviewed mover and leaver effects, foreign credentials, duplicates, incomplete and empty holds); `tests/integration/move-in-browser.test.mjs` — "move-in journey: stage a 30-person Google export, review, admit, invite and undo at desktop and mobile in both themes" (source setup, held preview, application and disable at 1440 and 390); `journeys/directory-sandboxes.mjs` (held-key qualification journey; live result remains pending); `docs/directory-sources.md`
**Gap.** Partial remains unchanged. Native connectors stage observations and apply only exact human-approved changes. Remaining Gaps are complete live provider mover and leaver qualification, Google Workspace directory delegation, measured pushed and polling bounds, full-reconciliation timing, receipt-to-application timeliness while human approval is pending, directory stale-source follow-up, and nested or external membership support. Timely provisioning and deprovisioning remain complete category requirements. CT approves approval-origin timing only for the interim approved-delivery execution profile; it does not redefine receipt-origin source performance, authorize recurring approval, infer termination from absence or grant outbound consent.

#### AUTH-HRIS-001 — HR-driven identity sources

Core · target · **missing**

**Requirement.** Willow, Rippling, Gusto, BambooHR, Workday, ADP Workforce Now, UKG Pro, Paylocity, Namely and SAP SuccessFactors supply employment/source IDs, manager, department, location, worker type and effective dates through authorized connectors. Each connector states whether it receives vendor events or polls; events are applied within 60 seconds and polls run at least every 15 minutes (AUTH-TIMING-001), and a source with no successful read for 2 polling intervals is flagged stale. HR systems without a connector use AUTH-HRIS-002's scheduled file feed. Employers select field precedence and approved joiner/mover/leaver policies, including contractors and rehires. Preview shows exact access effects before activation, separates future hires from active workers, detects stale/missing feeds and rejects untrusted payload instructions. Auth owns identity/access; payroll, benefits, time off and employee files stay in the HR/payroll products. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

**Acceptance.**
1. Connect each of the ten named HR sources in an authorized tenant; synchronize a future hire, US employment start, department/manager move, scheduled termination and rehire, and measure each change's arrival against its event or polling bound.
2. Exercise DST/timezone effective times, conflicting sources, duplicate/out-of-order events and a stale feed; verify resulting access and unresolved source errors.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-HRIS-002 — Scheduled HR file feeds

Core · target · **done**

**Requirement.** For any HR or payroll system without a named connector, employers deliver a scheduled CSV feed by SFTP (Auth-hosted, key-authenticated per employer) or upload, with a saved column mapping and the same preview, field precedence, effective-date, joiner/mover/leaver policy and stale-feed rules as AUTH-HRIS-001. The schedule is hourly or daily as the employer chooses; a feed missing past its schedule plus one interval is stale and raises a follow-up (AUTH-FOLLOWUP-001), and a feed that would terminate more than a set share of workers (default 5%) or arrives empty is held for confirmation rather than applied. Files are retained per AUTH-RETENTION-001 and never treated as instructions. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

Current execution follows CT's 24 October ruling: a human approves an exact
file, selected rows and their preview digest with hardware and fresh local
email proof. Only those changes may execute when due, after rechecking the
approver's current authority, approved content and target. Drift returns to
review. Recurring pulls cannot approve themselves; outbound consent remains
separate. AUTH-HRIS-001 and AUTH-SCIM-002 inherit these exact-approval and
interruption-recovery obligations before adding automation.

**Acceptance.**
1. Configure an SFTP feed with a mapping, deliver a file with a hire, a move and a termination and see the preview and resulting access; deliver a malformed file, an empty file and one terminating 20% of workers and see each held; skip a delivery and see the stale flag and follow-up.
2. Refuse a wrong SFTP key and a file for another employer.

**Evidence.** `tests/auth/directory.test.mjs` — "saved HR file mappings hold destructive, empty and malformed deliveries, preview current and future rows, and retain one stale-feed follow-up across restart"; "a real SFTP listener verifies the employer key, applies reviewed hires, moves and leavers, refuses traversal and shells, and ends ingress after disabling"; "an explicitly approved HR file applies current and dated hires, moves and leavers once, resolves managers and resumes interruptions while preserving enrollment and authority refusals"; `tests/integration/directory-browser.test.mjs` — "directory journey: an administrator onboards a worker, edits and bulk-moves people with a preview, sets a group rule, terminates and rehires, at desktop/mobile in both themes": stale-source Activity, guide link and tooltips at 1440/390; `docs/hr-file-feeds.md`; `tests/auth/directory.test.mjs` — the same approved-file journey proves exact dated execution once under concurrent maintenance, manager source resolution, content and target drift refusal, demoted or removed approver refusal, unapproved-delivery refusal and interrupted multi-row restart with one approver and digest receipt per row; `tests/auth/provisioning.test.mjs` — "request, review and stale HR obligations retain decider reminders and resolution history across DST and restart": separately consented stale-source reminders; `tests/integration/browser.test.mjs` — "docs pages support keyboard code scrolling and remain readable at desktop and mobile": published guide at 1440 and 390;
**Gap.** None for the approved per-file profile. Unapproved recurring changes never apply. Remote provisioning and outbound consent remain separate obligations.

#### AUTH-LIFECYCLE-001 — Complete joiner, mover and leaver execution

Core · target · **partial**

**Requirement.** An approved HR or administrative event creates a durable, per-person plan of directory changes, group/app/role assignments, credential/session actions, owners and deadlines. Routine actions may run only within a human-published policy and scoped connector authority; exceptional or privileged/destructive changes need explicit approval. Joiners are ready at their authorized start, movers lose obsolete access, and leavers lose Auth access with every downstream revocation tracked, each within the numeric bounds of AUTH-TIMING-001. Reconciliation survives restart, handles uncertainty without blind duplicate writes, and never marks a person fully offboarded while an app still has unresolved access. Employer-built steps, such as transferring a leaver's files to their manager, run as AUTH-WORKFLOWS-001 automations recorded in the same plan. Future API/provisioning doors inherit AUTH-MAPPING-001 computed-value validation and preview/version semantics.

**Acceptance.**
1. From HR/admin doors, onboard a sales hire across Workspace, Slack and Salesforce, move them to engineering/GitHub, then terminate while one provider is unavailable.
2. Restart the worker, inspect deadlines and approvals, restore the provider and confirm each remote outcome with its timestamps; local access must remain denied throughout.

**Evidence.** `src/auth/admin.mjs`; `src/auth/links/logout.mjs`; `tests/auth/linking.test.mjs`
**Gap.** manual invitations, suspension and RER fences exist; multi-app HR-driven execution is missing.

#### AUTH-TIMING-001 — Measured lifecycle time bounds

Core · target · **partial**

**Requirement.** Every lifecycle change carries numeric bounds that a test or auditor can check. Leaver: within 60 seconds of the leaver event committing, Auth refuses every session, refresh grant, UserInfo and introspection call, launcher tile, extension fill and RADIUS/LDAP bind for the person, and has sent back-channel logout to every linked app; self-contained access tokens already issued expire within their at most 5-minute lifetime. Downstream: each healthy SCIM/API connector has the change dispatched within 60 seconds and remote state verified within 5 minutes; past 15 minutes an unverified change is escalated as unresolved (AUTH-FOLLOWUP-001). Joiner: the AUTH-ONBOARD-001 activation invitation goes out at its lead time, accounts are provisioned and verified by 06:00 employer-local time on the start date (or at an HR-set start time), and sign-in is permitted from the authorized start. Mover: obsolete access is removed under the same downstream bounds. Sources: HR events applied within 60 seconds, HR polls at least every 15 minutes, file feeds per their schedule, and a full reconciliation of every source and connector at least every 24 hours. Each obligation records event time, local-denial time, dispatch time and remote-verified time per app; a timeliness report shows the share of leavers fully deprovisioned within 1 hour and within 24 hours for any period, with unverified apps listed by name.

**Acceptance.**
1. With healthy connectors to three SaaS test tenants, terminate a person and measure: local refusal on every door and logout delivery within 60 seconds, dispatch within 60 seconds and remote verification within 5 minutes per app.
2. Hold one connector down past 15 minutes and see the escalation; add a future hire and see verified accounts before 06:00 local on the start date.
3. Export the timeliness report for the period and reconcile each row's four timestamps with the audit trail.

**Evidence.** `src/auth/admin.mjs`; `src/auth/links/logout.mjs`; `src/auth/provisioning/obligations.mjs`; `tests/auth/security.test.mjs`; `tests/auth/linking.test.mjs`; `tests/auth/provisioning.test.mjs`
**Gap.** suspension denies Auth sessions at once and starts signed RER back-channel logout with bounded retries; each SCIM obligation records event, dispatch and remote-verified times and is flagged unverified past 15 minutes. Missing: source and joiner bounds, the 24-hour reconciliation of every source, and the timeliness report.

#### AUTH-WORKFLOWS-001 — Employer-built identity automations

Core · target · **partial**

**Requirement.** Administrators with the automation permission build versioned automations in a no-code editor: a trigger on an identity event (hire, start date, move, attribute change, leave, group membership change, access request decision, a schedule or a webhook), conditions over directory and source data (AUTH-MAPPING-001 expressions), and steps that call connector actions, make a signed HTTP request to any HTTPS REST endpoint with stored connection authentication (API key, basic, bearer or OAuth 2.0 client credentials) and use its parsed response in later steps, wait for a date or an approval, branch, or notify. HTTP step destinations are validated against SSRF as AUTH-EVENTS-001 validates webhooks, and their credentials stay in connector custody. Steps run only under the scoped connector authority the employer granted to that automation; destructive or privileged steps require a named approver per run unless the published policy pre-approves them. Every automation has a dry run against a chosen person that shows each step's intended effect without performing it, and every run is recorded against that person's AUTH-LIFECYCLE-001 plan with inputs, step outcomes, remote verification and retries, so a failed step stays an open obligation. Auth ships tested templates: Google Drive file ownership transfer to the manager (Data Transfer API), Google Calendar transfer, Gmail delegation to the manager and a leaver auto-reply, Microsoft 365 mailbox conversion to a shared mailbox with manager access, OneDrive access grant to the manager, and license reclaim for Google Workspace, Microsoft 365, Slack, Zoom and Salesforce. Templates are copied and edited, never run blind.

**Acceptance.**
1. In authorized Google Workspace and Microsoft 365 test tenants, enable the leaver templates and terminate a person through HR: read back Drive files owned by the manager, the transferred calendar, the Gmail auto-reply and delegate, the shared mailbox with manager access and every reclaimed license.
2. Dry-run an edited automation and see no remote change; fail one step and see it held as an unresolved obligation in the person's plan; refuse a step outside the automation's granted scope.
3. Call a generic REST endpoint with stored OAuth client credentials and use its response in a later step; refuse an HTTP step aimed at a private address.

**Evidence.** `tests/auth/automations.test.mjs` ("automation public doors dry run without calls, acquire OAuth and chain two signed steps, retain history and exclude credentials from projections and archives"; "automation refuses lost permission, foreign scope and stale configuration, and holds failed or interrupted effects as person obligations without replay"; "automation hosted destinations refuse private addresses and DNS, redirects and unbounded response mapping without credential diagnostics"); `tests/auth/events.test.mjs` (retained native event delivery); `tests/integration/automations-browser.test.mjs` (editor, person dry run and failure history at 1440 and 390 in both themes); `docs/automations.md`
**Gap.** The bounded native slice implements one group-membership trigger, two signed HTTP steps, encrypted OAuth client-credentials custody, scoped authority, exact named approval for every run, person-specific zero-outbound dry runs and durable failure obligations. Held: authorized Google Workspace and Microsoft 365 tenants with Drive, Calendar, Gmail and Graph mailbox and license consent. All live HR-triggered leaver-template journeys, Drive and Calendar transfer, Gmail delegation and auto-reply, shared mailbox and OneDrive manager access, and Google, Microsoft 365, Slack, Zoom and Salesforce license reclaim remain unproved. Other trigger families, full mapping conditions, connector-action steps, waits, branches, notification steps, remaining authentication modes, template copying and editing, full remote verification and retry journeys, and complete lifecycle-plan integration remain unbuilt. Native peers qualify no vendor template.

#### AUTH-FEDERATION-001 — Generic upstream federation

Core · target · **partial**

**Requirement.** Employers configure generic OIDC and SAML 2.0 upstream IdPs as well as Google Workspace, Microsoft Entra ID and Okta for coexistence, mergers or partner employees. A delegated setup portal verifies domains, issuer/metadata and keys, tests a representative user, previews mappings and activates only after authorized approval. Validate issuer, signature, audience, correlation, clock/replay and trusted subject/email evidence; prevent federation loops, unsolicited account merging and stale configuration admission. Upstream proof never substitutes for the local email/hardware requirements of existing Auth administration. Future machine administration doors inherit AUTH-ADMINAPI-001 credential, scope/resource, excluded-action, live-authority, audit and concurrency checks before shipping.

**Acceptance.**
1. Through delegated setup, connect generic SAML/OIDC plus the three named providers, sign in to an assigned downstream app and rotate upstream keys.
2. Refuse an email-only collision, replay, changed issuer/configuration, malicious metadata URL and foreign organization setup; simulate upstream outage and use approved recovery.
3. CT policy ruling, 26 October 2026: The interim activation profile is owner-only and limited to exact reviewed ordinary subjects and their immutable mappings.
4. The affected organization’s owner approves with hardware passkey and fresh local email proof; current authority, organization binding, trust configuration and mapping are rechecked at commit, and drift returns to review.
5. Installation authority grants no administration of an isolated organization.
6. A representative test validates upstream proof and previews mappings only: it creates no employee session, authenticated membership, downstream grant or administrator authority.
7. Activation does not itself sign in the employee or bypass assignments, policy or AUTH-PROFILE-001 existing-account and new-identity proof.
8. Record only necessary trust configuration, reviewed bindings, approval facts and redacted validation outcomes; disclosure remains governed by existing claims and scope rules. Upstream proof never replaces local administrator proof. Machine administration remains limited to enabling or disabling approved trust; future machine doors inherit all AUTH-ADMINAPI-001 protections. Every original federation acceptance point remains required.

**Evidence.** `tests/auth/upstreams.test.mjs` — "delegated federation tests a representative without granting a session, previews exact immutable mappings, activates with owner consent and refuses drift and collisions" (generic OIDC and SAML setup, representative isolation, exact mapping approval, assigned downstream sign-in, signing-key refresh, correlation, replay, collision, private metadata and stale-authority refusal); `tests/auth/security.test.mjs` — "organizations isolate every existing HTTP family, admit expiring memberships and switch only between proven sessions" (foreign employer setup); `tests/integration/move-in-browser.test.mjs` — "move-in journey: stage a 30-person Google export, review, admit, invite and undo at desktop and mobile in both themes" (delegated setup, tested mapping, activation and provider screens at 1440 and 390); `docs/upstream-campaigns.md`
**Gap.** Partial remains unchanged. The owner-only delegated RS256 OIDC and plaintext SAML profile is implemented according to the cited repository evidence. Remaining Gaps are live Google callback and consenting test-user proof, an authorized Okta web registration, live Entra employee callback, full live downstream qualification, SAML upstream certificate-rotation and outage-recovery qualification, and broader federation-loop qualification. Every original generic and named-provider acceptance journey remains required. CT approves exact owner activation with isolated representative testing and the stated riders; this ruling certifies neither provider interoperability nor implementation completion.

#### AUTH-SOCIAL-001 — Controlled external identity sign-in

Core · target · **partial**

**Requirement.** Google, GitHub and Sign in with Apple adapters support employees/contractors only when their employer explicitly permits them. Verified stable issuer/subject, consent, minimum scopes and explicit existing-account proof govern binding; hiding an email or changing an upstream address does not merge accounts. Social proof has its actual assurance and must satisfy employer MFA and recovery policy.

**Acceptance.**
1. Configure each adapter with a real provider app, sign in an invited contractor, exercise private/changed email and unlink/relink, then withdraw employer permission.
2. Refuse a same-email unproven identity and observe immediate policy denial on further token issuance.

**Evidence.** `src/auth/upstreams.mjs`; `tests/auth/upstreams.test.mjs`
**Gap.** Google OIDC is exercised; GitHub and Apple adapters are missing.

#### AUTH-LEGACY-001 — LDAP, Active Directory and RADIUS access

Core · target · **missing**

**Requirement.** Auth provides documented LDAP/LDAPS and RADIUS integration for legacy apps, VPNs and Wi-Fi, plus scoped Active Directory coexistence/synchronization where employers retain AD. A separately deployed authenticated connector handles private-network access, certificate/secret rotation, group restrictions, health and revocation acknowledgments. Each recipe publishes its factor matrix rather than "MFA-compatible": RADIUS PAP recipes for Palo Alto GlobalProtect and Cisco Secure Client support password plus Auth push (AUTH-AUTHENTICATOR-001) and password plus TOTP (entered as a challenge response or appended code), number matching is not available over RADIUS and is replaced by push context, and passkeys are not available over RADIUS; Meraki and other 802.1X Wi-Fi recipes support EAP-TLS with an Auth-issued device certificate (AUTH-DEVICE-001) and EAP-TTLS/PAP with password plus push; LDAPS binds support password plus push for apps that tolerate the wait, and otherwise password only behind network policy. Active Directory coexistence states each direction: AD as a source of people and groups (supported), delegated authentication of Auth sign-in to AD (supported), password write-back to AD for workers on password compatibility (supported), and group push from Auth to AD (supported), each through the connector with its scope and conflict rules shown. Every password accepted here follows AUTH-PASSWORD-001's policy and lockout, and a change made anywhere propagates under AUTH-PASSWORD-002. Protocol limitations and unavailable posture fail closed under policy. The connector is engineering scope, not a reason to omit legacy access.

**Acceptance.**
1. Install the real private connector.
2. Sign in to GlobalProtect through RADIUS with password plus push and with password plus TOTP; deny the push and let one time out, and each sign-in is refused.
3. Join Meraki Wi-Fi with EAP-TLS and with EAP-TTLS plus push, bind an LDAPS app, and exercise each AD direction (source import, delegated authentication, password write-back, group push).
4. Disable the employee, rotate trust and disconnect the connector; prove new access stops within AUTH-TIMING-001's leaver bound and unresolved external sessions remain visible.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-DEVICE-001 — Device identity and trust

Core · target · **missing**

**Requirement.** Windows, macOS and Linux directory/device connectors and Intune, Jamf Pro, Kandji and JumpCloud posture integrations bind device identity to a person and report encryption, screen lock, OS/compliance and last contact for conditional access. iOS, iPadOS and Android devices report posture through the Auth mobile app and those MDMs: OS version and patch level, jailbreak or root detection, screen lock and biometrics, disk encryption and managed or personal status, each usable in AUTH-POLICY-001 like desktop posture. Employees enroll and remove devices with ownership proof; administrators can revoke device trust and certificate-based Wi-Fi/VPN access. Native/device software, packaging, updates and OS permissions are deliverables. Auth owns identity and trust decisions; broad endpoint patching, EDR and software deployment remain with those endpoint products.

**Acceptance.**
1. Enroll one device per supported desktop OS and an iPhone and an Android phone, and read posture from each named management service; launch from a jailbroken or rooted phone and from one below the required OS version and be denied.
2. Launch an app, stale the posture, mark a device noncompliant and revoke it; verify policy denial, trust removal and an auditable employee/help-desk recovery path.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-DESKTOP-001 — Sign in to the computer with company identity

Core · target · **missing**

**Requirement.** Employees sign in to their Mac and Windows PC with their Auth identity. On macOS, an Auth Platform SSO extension, deployed by Jamf Pro, Kandji, Intune or JumpCloud, supports both Platform SSO modes: password sync (the local account password follows the Auth password) and passwordless sign-in with a Secure Enclave key, and creates or binds the local account at first login, where a person with no factor yet signs in with a temporary access pass (AUTH-TAP-001) and enrolls one. In password-sync mode the password follows AUTH-PASSWORD-001's policy, shows its expiry warning and offers self-service reset and unlock at the login window under AUTH-PASSWORD-002. On Windows 10/11, an Auth credential provider does the same at the sign-in and unlock screens. MFA at the OS login screen uses push or TOTP from the Auth authenticator (AUTH-AUTHENTICATOR-001) or a security key, as policy requires. Offline sign-in uses a cached credential valid for an employer-set period (default 7 days, maximum 30) after which the device must reach Auth again. A locked-out employee gets a time-limited, single-use recovery PIN from help desk under AUTH-RECOVERY-003, valid for at most 1 hour. When a person is suspended or leaves, the device refuses their next online login and unlock, and refuses offline login once its next online check or the offline period ends; a device the employer marks lost refuses their offline login at its next contact. On domain-joined Windows PCs, Kerberos desktop SSO (SPNEGO through the private connector) signs a domain-signed-in employee in to Auth's web sign-in without re-entering credentials, as one factor, with policy deciding whether further MFA is required.

**Acceptance.**
1. On a managed Mac and Windows PC, sign in at the OS login with company identity using push, TOTP and a security key; on the Mac exercise both password-sync and Secure Enclave modes.
2. Sign in offline within and beyond the cached period.
3. Lock an employee out and restore them with a help-desk recovery PIN, then refuse the PIN's reuse and its use after an hour.
4. Offboard the employee and see the next online login and unlock refused.
5. On a domain-joined Windows PC, open the launcher and be signed in by Kerberos, then be stepped up where policy requires.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-GATEWAY-001 — On-premises web apps through an access gateway

Core · target · **missing**

**Requirement.** An Auth access gateway, deployed beside the private connector (AUTH-LEGACY-001) as a container or VM image, fronts on-premises and private web apps that use header-based authentication, Kerberos constrained delegation (IIS and other Windows-integrated apps) or no sign-in of their own. It signs the employee in through Auth, applies AUTH-POLICY-001 per app and per path, and passes identity to the app as mapped headers (AUTH-MAPPING-001) or a Kerberos ticket, always stripping identity headers supplied by the client. Apps are published to the launcher through an outbound-only tunnel with no inbound port opened on the private network; session lifetime, logout and leaver denial within AUTH-TIMING-001 apply. This is the job Okta Access Gateway and the Microsoft Entra application proxy do.

**Acceptance.**
1. Deploy the gateway on a private network with no inbound port and publish a header-based test app and an IIS app using Kerberos constrained delegation.
2. Launch both as an assigned employee and read the identity headers and Kerberos identity at each app.
3. Send a forged identity header and see it stripped; deny an unassigned employee and a path-level rule; offboard the employee and see the next request refused within 60 seconds.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

#### AUTH-PRIVILEGED-001 — Server and SSH access without standing keys

Core · target · **missing**

**Requirement.** Engineers reach Linux servers over SSH with short-lived SSH certificates (default 10 minutes, at most 12 hours) that Auth issues after sign-in and AUTH-POLICY-001, for server groups mapped from Auth groups; and reach Windows servers over RDP through the access gateway (AUTH-GATEWAY-001) after Auth sign-in. A server agent creates and removes local accounts and grants sudo or local administrator rights from group membership; servers without the agent trust Auth's SSH certificate authority through OpenSSH's `TrustedUserCAKeys`. Elevation to sudo or administrator is requested and time-bound through AUTH-REQUESTS-001. No static SSH keys are issued. Every session's person, server, time, elevation and, where the agent captures them, commands go to AUTH-AUDIT-001. On a leaver, no new certificate is issued within AUTH-TIMING-001's local bound and the agent removes the account. This is the job Okta Privileged Access does.

**Acceptance.**
1. Enroll two Linux servers (one with the agent, one with only the CA key) and one Windows server.
2. As an engineer in a server group, sign in with a passkey, obtain a certificate and SSH in; RDP to the Windows server through the gateway.
3. Be refused sudo until a time-bound request is approved, then gain it and see it expire.
4. Refuse a server outside the person's groups, an expired certificate and an unassigned engineer.
5. Offboard the engineer and see the next connection refused and the local account removed; the audit shows each session.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

### Access governance and application authorization

#### AUTH-GRANTS-001 — App roles, APIs and service identities

Core · target · **done**

**Requirement.** Group and role assignments govern app launch, provisioned app roles and registered API permissions. App owners define scopes, role/attribute/resource relationships and fine-grained permission checks through a documented authorization API, with default deny and current tenant/person context. Service accounts use scoped, expiring OAuth client-credentials tokens with distinct accountable owners, targets and audit; they cannot impersonate a person or obtain interactive administrator proof. Administering Auth itself by machine is only through AUTH-ADMINAPI-001's admin scopes. External app authorization remains enforced in the app using verified claims or Auth decisions.

**Acceptance.**
1. Register an API, map a group to read/write and resource-level permissions, and call it as an employee and a service identity.
2. Deny an unassigned role, cross-employer resource, wrong audience, excessive scope and revoked service credential; role removal must change the next authorization decision.

**Evidence.** `tests/auth/oidc-apps.test.mjs` — "resource APIs use live app roles and tenant resources for employees and distinct accountable OAuth services"; `tests/auth/provisioning.test.mjs` — "a group assignment provisions its members and the group over SCIM; role changes update the one account; unassignment and suspension deactivate, verified by read-back"; `docs/authorization-api.md`; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile" proves API registration, group-role mapping, service issuance and next-call revocation at 1440/390.
**Gap.** None.

#### AUTH-TOKENS-001 — Refresh and delegated session lifecycle

Core · target · **done**

**Requirement.** Explicitly registered non-RER profiles may grant offline access with least-privilege consent, refresh-token rotation, reuse detection, family revocation, idle/absolute expiry and sender/client binding appropriate to the profile. Web/native SDKs rotate safely across concurrent requests without concealing replay. Employees and administrators see active app/device grants and can revoke them; disabling a person, app or grant prevents refresh and triggers supported app/session revocation. AUTH-PROTOCOL-001 continues to offer no refresh/offline access.

**Acceptance.**
1. Use a native SDK to obtain an approved refresh grant, rotate it, replay an old token and revoke the family through My account.
2. Run concurrent refresh, expiry, suspension and app removal, confirming the resource API refuses invalid authority and strict RER clients receive no refresh token.
3. **Current profile:** An administrator explicitly binds a general OIDC client to its own app's resource API, published scopes and chosen idle/absolute lifetimes; there are no implicit offline grants.
4. Each person consents to the exact app/device, audience, scopes and lifetimes.
5. S256 PKCE, registered client authentication and ES256 DPoP bind the grant.
6. Refresh digests rotate with one winner; authenticated consumed-token reuse ends the family without a grace interval or cached successor.
7. The SDK coalesces concurrent calls and commits storage before publishing a successor; failures require deliberate new consent.
8. Resource decisions recheck the family, current account/app/assignment, policy and API/profile revisions and preserve the app's subject policy. Browser expiry alone does not end an offline grant; explicit source-session revocation, account/app/profile endings and either grant expiry do. My account and scoped administrator doors retain the existing permission, view/edit resource, hardware/fresh-email and account-rank fences. Supported OIDC logout is queued without claiming remote deletion. Credentials and family authority are nonportable, and the shared registry covers erasure/retention. AUTH-DEVELOPER-001 and AUTH-MOBILE-001 inherit these SDK storage, binding, concurrency and failure semantics before adding framework/native packages; AUTH-AGENT-006 remains a separate task profile.

**Evidence.** `tests/auth/oidc-apps.test.mjs` — "native offline consent and SDK rotation preserve device binding, detect reuse and concurrency, and end resource authority on expiry, revocation, suspension and app removal": native SDK consent and rotation, device/client/tenant binding, least scopes and pairwise subjects, SDK single-flight and storage failure, consumed-token reuse and simultaneous raw refresh, restart and browser-expiry continuity, idle/absolute expiry, scoped/ranked/fresh-email administrator controls, employee revocation, suspension/app removal, live resource denial, supported logout and store cleanup; `tests/integration/refresh-browser.test.mjs` — "offline app journey: publish a profile, consent to a native device, inspect and revoke it through My account at 1440 and 390": profile publication/disablement, exact consent, employee/admin inventory and My account family revocation, readable end states and every icon-only control's delayed-hover/immediate-focus tooltip at 1440/390; `tests/auth/protocol.test.mjs` — "code flow preserves ES256 ID token claims and adds a userinfo access token": strict RER has no refresh token and refuses offline authorization/refresh; `docs/offline-sessions.md`; `packages/session-sdk/index.mjs`
**Gap.** None.

#### AUTH-HOOKS-001 — Inline hooks for custom sign-in logic

Core · target · **done**

**Requirement.** Employers register signed HTTPS inline hooks that Auth calls synchronously at named points: before token issuance (add or change claims within an allow-listed set), before a SAML assertion (add attributes), at self-registration (allow, deny or change profile fields), at password import (verify a migrating password under AUTH-MIGRATION-002) and at user import (match or create). Each hook receives a documented minimal payload, is signed by Auth and must answer within its timeout (default 3 seconds, maximum 10). The employer chooses fail-open or fail-closed per hook; security-relevant points default to fail-closed. A hook can never grant an administrator role, remove required MFA, change the subject or override AUTH-POLICY-001. Destinations are validated against SSRF as AUTH-EVENTS-001 validates webhooks, and every call is audited with latency and outcome. This is the job Okta's token, SAML, registration, password-import and user-import inline hooks do.

**Acceptance.**
1. Register a token hook that adds a cost-center claim and see it in the ID token; a registration hook that denies an outside domain; and a hook that tries to add an administrator role and change the subject, and see both changes refused.
2. Let a fail-closed hook time out and see the sign-in refused with a clear error, then a fail-open hook time out and see sign-in continue with the event logged.
3. Refuse a hook URL that resolves to a private address.
4. Exact current-door semantics: signed hooks run for strict RER and general OIDC ID tokens, SAML assertions, self-registration, staged move-in admission and source-id-matched directory imports.
5. Token/SAML outputs are restricted to explicit custom fields; registration/import may alter only the currently exposed name field, and neither may change an identity binding or authority.
6. Every remote call is bounded, audited and followed by a fresh issuance/commit authority check.
7. Under current-capability inheritance, AUTH-MIGRATION-002 must supply the password-verification/first-login hook before that bridge ships, and new match/create doors in AUTH-HRIS-001, AUTH-HRIS-002 and AUTH-SCIM-002 inherit all hook protections before shipping.
8. Unavailable password-hook registration refuses; no password verifier is simulated.

**Evidence.** `tests/auth/oidc-apps.test.mjs` ("inline hooks add only approved token and SAML fields, deny registration and imports, enforce signed minimal payloads and timeout choices, and refuse private DNS and protected identity changes": cost-center ID token and independent SP assertion, registration/import denial, subject/admin-role/MFA/policy refusal, real fail-closed/fail-open timeouts with public error and audit, private DNS at registration and invocation, revocation during the call); `tests/auth/protocol.test.mjs` ("code flow preserves ES256 ID token claims and adds a userinfo access token": strict RER hook and unchanged proof claims); `tests/auth/move-in-admission.test.mjs` ("admission is the ordinary invitation: administrators only, no proof, right, session or mail, and existing people never rebound": signed import denial and creation); `tests/integration/company-apps-browser.test.mjs` ("company apps journey: the owner adds a SAML app from its metadata, an OpenID Connect app, a group and assignments; an employee signs in through Auth, and loses both when removed, at desktop/mobile in both themes": register/refuse/stop hook and Activity latency/outcome at 1440/390); `docs/inline-hooks.md`
**Gap.** None.

#### AUTH-REQUESTS-001 — Access requests and time-bound grants

Core · target · **partial**

**Requirement.** Employees request apps/roles with purpose and duration; policies route to manager, app owner or security approvers, handle separation of duties and forbid self-approval. Approvers see current employment, existing access, risk and license consequence, and decide with the proof AUTH-DECISIONS-001 sets, on the web or in Slack or Teams (AUTH-CHAT-001). Exact approved scopes provision only after a fresh authorization check, expire automatically and verify removal in connected apps. Denial, cancellation, approver absence, extensions and emergency elevation leave attributable history.

**Acceptance.**
1. Request Salesforce access and temporary AWS elevation from the launcher, have the required independent people approve, provision only those roles, and let the grant expire while a connector fails.
2. Reject self/stale/concurrent approvals and verify revocation/escalation before closing the request.
3. The current native foundation supports an explicitly administrator-selected independent decider, a maximum thirty-day duration, exact approval/denial and restart-safe expiry that stays pending until remote removal is verified.
4. Default ADOPTED pending ct: owner/admin policy writes under hardware/fresh-email proof; a temporary approval cannot overwrite a standing direct assignment.
5. Authorized Salesforce and AWS live qualification, multi-stage routing and chat remain outstanding.

**Evidence.** `tests/auth/directory.test.mjs` — independent request decisions bind the current approver and temporary access expires without claiming remote removal; `src/auth/requests/index.mjs`; `docs/access-decisions.md`
**Gap.** Native single-decider temporary requests and exact decision/expiry foundation built for DECISIONS-001. Authorized Salesforce/AWS role/elevation tenants, multi-stage routing, extensions/emergency rules, chat and live remote expiry qualification remain. Default ADOPTED pending ct: explicit administrator-selected decider and maximum 30-day duration; no standing direct assignment overwritten.

#### AUTH-REVIEWS-001 — Periodic access certification

Core · target · **partial**

**Requirement.** Administrators schedule recurring manager/app-owner reviews with a fixed snapshot of identities, groups, role grants, source, last observed use and data freshness. Reviewers certify, reduce or revoke with reasons; delegation, reminders, absence and overdue escalation are explicit. Completed reviews retain decisions and verified remediation results, including unresolved connector failures, and export a reproducible SOC 2 evidence package without claiming certification.

**Acceptance.**
1. Start a quarterly review of employee, contractor and service-account access, delegate one reviewer, certify one role and revoke another.
2. Change membership mid-review, miss a deadline and fail a provider removal; inspect immutable snapshot, new drift and an export whose completion cannot conceal unfinished remediation.
3. Current native reviews retain immutable access snapshots and separate current drift, certify/revoke decisions and read-back remediation, including failures.
4. Recurring snapshots and overdue records are durable.
5. Explicit app-role reduction, consented decider reminders, absence escalation, scoped published review permissions and optional native administrator-grant inventory are built.
6. Native role revocation uses the existing rank/scope evaluator and refuses owner removal.
7. Generic obligations remain FOLLOWUP-003.
8. Future POLICY/PASSWORD clauses inherit immutable policy-version evidence before shipping. Default ADOPTED pending ct: scheduling, delegation and export require their published scoped permission, hardware and fresh email.

**Evidence.** `tests/auth/directory.test.mjs` — quarterly access snapshots retain delegation, drift, overdue escalation and verified remediation; `tests/auth/access-decisions-flow.mjs`; `src/auth/reviews/routes.mjs`; `docs/access-decisions.md`  `tests/auth/directory.test.mjs` — review reductions follow a published app order and cap live access through provider readback; review reminders follow current reviewer consent and business calendars across restart with absence escalation; native administration reviews preserve scoped grant evidence and enforce the existing revocation door; scoped review coordinators schedule only editable resources and cannot hide excluded evidence in exports; `tests/auth/native-review-flow.mjs`; `tests/auth/review-scope-flow.mjs`; `tests/auth/review-reduction-flow.mjs`; `tests/auth/review-reminders-flow.mjs`; `tests/integration/directory-browser.test.mjs` — access decision and review journey;
**Gap.** Employee/contractor/service snapshots, recurring quarterly runs, delegation, certify/reduce/revoke, new drift, calendar/DST reviewer reminders, absence/overdue escalation, provider-failure closure and immutable export built. Scoped published review permissions and optional native Auth administrator-grant snapshots are built; native revocation reuses live role/rank fences, terminates sessions and refuses owner removal. Generic obligations are FOLLOWUP-003; future POLICY/PASSWORD clauses inherit immutable policy-version evidence before shipping. Default ADOPTED pending ct: scoped hardware-plus-email management/delegation/export, explicit app hierarchy with persistent caps and fail-closed republication.

#### AUTH-DECISIONS-001 — Proof levels for administration and everyday decisions

Core · target · **partial**

**Requirement.** The contract lists who carries the administrator gate. Bound by AUTH-IDENTITY-001's hardware passkey and fresh local email proof for every write: owner, identity administrator, security/policy administrator, app administrator (app configuration, credentials, connector authority), help desk (factor reset, recovery, suspension), auditor when exporting, and every custom role from AUTH-ROLES-001 holding any administrator permission; also any decision that grants an administrator or other privileged role, changes recovery, signing keys, identity providers or admin API credentials, or approves recovery of an administrator. Not bound: a manager, app owner or group owner approving or denying an access request for a non-privileged role, a group owner editing membership of a group that grants no privileged role, a reviewer certifying or revoking access, and an employee requesting access. Those decisions take an ordinary employee passkey sign-in plus the step-up their policy requires (by default a user-verified passkey assertion within the last 15 minutes, bound to the decision). The server checks the decider's current authority, the request's unchanged state and separation of duties at commit, whichever door the decision came through. Privileged roles are marked as such on each app and group, and that marking is itself an administrator write.

**Acceptance.**
1. As a manager with an employee passkey and no local email confirmation, approve a Salesforce request, edit a non-privileged group as its owner, and certify access in a review; each commits after step-up.
2. Attempt to approve a request for an administrator role, edit a privileged group and approve an administrator's recovery with the same proof; each is refused until the administrator gate is satisfied.
3. Approve a stale request and one the decider lost authority over between view and commit; both are refused.
4. Current native doors use one single-use, session/decision-bound UV passkey assertion (15-minute expiry), atomic live authority/state fences and the existing administrator gate.
5. Apps default privileged until an explicit audited owner/admin classification, inherited by their groups; an exact app-role classification overrides that app default and propagates to groups granting the role.
6. Scheduling, delegation and exports require published scoped review permissions with hardware and fresh email.
7. Privilege classification remains owner/admin-only.
8. These adopted conservative policy choices await ct; future REQUESTS-001, CHAT-001 and other decision carriers inherit this gate before shipping.

**Evidence.** `tests/auth/directory.test.mjs` — group owners confirm exact ordinary decisions without email and lose stale or privileged authority; independent request decisions bind the current approver and temporary access expires without claiming remote removal; quarterly access snapshots retain delegation, drift, overdue escalation and verified remediation; `tests/auth/access-decisions-flow.mjs`; `src/auth/decisions/routes.mjs`; `docs/access-decisions.md`  `tests/integration/directory-browser.test.mjs` — access decision and review journey;
**Gap.** Native group/request submission/approval/review certify-reduce-revoke doors, exact UV proof, stale/lost/concurrent refusal built. Authorized Salesforce/AWS live request qualification remains under REQUESTS-001; configurable step-up policy inherits POLICY-001. Request submission now uses the same exact UV proof. Default ADOPTED pending ct: apps and their unclassified roles privileged until audited administrator classification; exact app-role overrides propagate to group decisions; management/delegation/export published scoped permission with hardware plus fresh email; explicit role-order caps fail closed on republication.

#### AUTH-CHAT-001 — Approve, deny and certify from Slack and Microsoft Teams

Core · target · **missing**

**Requirement.** Auth's Slack app and Teams app deliver access requests, review items and reminders to the deciding person with the request context AUTH-REQUESTS-001 shows on the web, and let them approve, deny, ask for more information or certify in the message. A chat account is bound to an Auth person once, by signing in to Auth from the chat app's link (SSO into Slack or Teams through Auth also confirms the binding), and each action re-checks that the chat user, workspace or tenant and Auth person still match. Actions whose policy requires step-up open an Auth step-up page and commit only after it; grants of privileged roles show the request read-only with an "open in Auth" link and are decided only on the web under the administrator gate. Every chat decision is audited with the chat user, workspace, message and Auth person.

**Acceptance.**
1. In authorized Slack and Teams test workspaces, bind a manager, approve one request and deny another from each, certify a review item, and see the outcomes provisioned and audited.
2. Refuse an action from an unbound chat account, one bound to a different person, a stale or already-decided request and a removed binding; a privileged-role request offers only the web link.

**Evidence.** None.
**Gap.** Slack interactivity requires main to choose and configure the shared app request URL or router; Teams requires Entra administrator consent. Native chat bindings and actions and the full authorized workspace journey remain unbuilt.

#### AUTH-AUDIT-001 — Identity investigation and reporting

Core · target · **partial**

**Requirement.** Employees see their sign-in/device/grant history; authorized investigators search and correlate sign-ins, policy decisions, enrollment/recovery, app provisioning, approvals, agent actions and downstream confirmations. Reports show active workers, app/role/license assignments and orphaned access, and the named per-person reports of AUTH-REPORTS-001 (MFA enrollment, terminated people, administrators and privileged roles, dormant accounts, joiner/leaver timeliness, connector health), with unknown freshness explicit. Tenant-filtered export and streams to Datadog, Splunk, Microsoft Sentinel and the Evidence sibling carry stable event IDs, actor/delegate, target, time, policy revision and outcome; no secrets or raw tokens enter logs. Compliance platforms that test the identity provider through a live connection (Vanta, Drata, Secureframe, Thoropass) receive per-person state through AUTH-COMPLIANCE-001, not a log export. Durable tamper-evident audit survives subject erasure with anonymized references. Out of the box, sign-in, administration and decision events are searchable and exportable through the UI and a paginated log API for 13 months (AUTH-RETENTION-001's default).

**Acceptance.**
1. Investigate an employee’s failed sign-in through its policy decision and provisioning history, export a review period to each named sink/Evidence, and reconcile the AUTH-REPORTS-001 MFA-enrollment export for one employer row by row with its directory, with every person who has no factor present and marked non-compliant.
2. Query an event 12 months old through the log API on a default installation.
3. Reconcile event counts across pages, detect tampering/gaps, deny an auditor’s write attempt and prove erased subjects no longer disclose personal identifiers.

**Evidence.** `tests/auth/audit.test.mjs` — "interactive audit finds twelve-month sign-ins and reconciles a frozen authorized set beyond the old cap across restart and concurrent appends"; "interactive audit rechecks employer, person scope and revoked auditor authority without conferring directory or export writes"; "interactive audit preserves stable event IDs and opaque projections after real subject erasure". The scope probe checks related people and groups before counts and pagination; the erasure probe includes an invitation, two email changes, persistent restart and an independent new holder of the old address. `tests/auth/agents-keys.test.mjs` — "admin service apps use private-key OAuth for scoped group and assignment writes; resource, IP, expiry, owner and ETag fences refuse automation while every scope excludes identity and credential custody" includes related-target machine log refusals. `tests/integration/directory-browser.test.mjs` — "organization and authority journey" includes Activity pagination, authority loss between pages and erased-subject readback at 1440 and 390 in both themes. `docs/activity.md`.
**Gap.** Native interactive Activity and role audit queries now have stable employer-bound event IDs, bounded time, person and event filters, as-of pagination and current authority checks. Twelve-month sign-in readback, reconciliation beyond the old cap despite concurrent appends, auditor write and related-target scope refusals before counts and pagination, recoverable Activity filter and cursor errors, and opaque erased-subject projections are implemented. Held: authorized Datadog, Splunk, Microsoft Sentinel and Evidence destinations, sink export and streaming, complete failed-sign-in, policy and provisioning correlation, full employee device and grant history, MFA and other report reconciliation including password, push and policy dependencies, and general durable tamper and gap evidence remain unproved. AUTH-RETENTION-001 and AUTH-ERASURE-002 policy holds are unchanged.

#### AUTH-REPORTS-001 — Named per-person identity reports

Core · target · **partial**

**Requirement.** Auth ships named reports, each with a defined column set, filters by employer, group, worker type and department, a CSV and admin API export, and a stated as-of time at which its row count reconciles to the directory. (1) **MFA enrollment:** one row per person in scope with Auth person ID, email, name, worker type, status, MFA compliant (yes or no against the employer's MFA policy), each enrolled factor type with its enrollment date and last use, and a password-only flag; a person with no factor appears as non-compliant and is never omitted. (2) **Terminated people:** person ID, email, termination effective time, leaver event time, local-denial time and full-deprovision time from AUTH-TIMING-001, and each app still unresolved, by name. (3) **Administrators and privileged roles:** each holder of a built-in or custom administrator role (AUTH-ROLES-001) or an app or group role marked privileged (AUTH-DECISIONS-001), with its resource set, who granted it and when, and last use. (4) **Dormant accounts:** active people with no successful sign-in in an employer-set number of days (default 90), with last sign-in time and door, and the apps they hold. (5) **Joiner and leaver timeliness** (AUTH-TIMING-001). (6) **Connector health:** each connector's last successful sync and open failures. Reports can be scheduled to email recipients and delivered to AUTH-COMPLIANCE-001 connectors and the Evidence sibling. Unknown or stale data is shown as unknown, never counted as compliant. Roles with the view-audit permission read reports; only roles with export rights export them, and each export is audited.

**Acceptance.**
1. With 20 people (15 with a passkey or push, 3 with only a password, 2 with no factor), export the MFA-enrollment report and reconcile it row by row with the directory: all 20 rows are present and the 5 non-compliant people are marked.
2. Terminate two people, one while a connector is held down, export the terminated-people report and reconcile each row's local-denial and full-deprovision times with the AUTH-TIMING-001 audit; the held app is named.
3. Grant and revoke a custom administrator role and see the administrators report follow; age a person past 90 days without sign-in and see them on the dormant report.
4. Refuse export to a role without export rights.
5. Each export's row count equals the directory count for its filter at its as-of time.

**Evidence.** `tests/auth/directory.test.mjs` — "native MFA reports reconcile every scoped directory row and keep no-factor workers noncompliant while separate export rights and audit gates apply"; "the administrators report follows a live published custom role grant and its revocation"; "the dormant report distinguishes an aged successful sign-in from recent activity and explicit unknown history"; "terminated reports retain held app names and verified remote outcomes while connector failures and unmeasured timing stay explicit"; `docs/identity-reports.md`
**Gap.** Native scoped JSON/CSV views, filters, stable columns, as-of roster counts, separate audited export, grants, dormancy and unresolved SCIM names are built. Password/push and employer MFA-policy qualification, full local/all-downstream timing reconciliation, every connector, schedules, machine exports and compliance/Evidence delivery remain unproved; missing facts stay unknown.

#### AUTH-COMPLIANCE-001 — Identity-provider connectors for compliance platforms

Core · target · **missing**

**Requirement.** Auth is the identity-provider connection of the employer's SOC 2 compliance-automation platform, so the platform's continuous tests keep their source through cutover and afterwards. Auth maintains a connector for each of Vanta, Drata, Secureframe and Thoropass, set up from that platform's catalog recipe (AUTH-CATALOG-002). **Vanta:** a private integration through Vanta's Build Integrations API that pushes the full state of `UserAccount` resources with `status`, `mfaEnabled`, `mfaMethods`, `authMethod` and `permissionLevel`, so Vanta reads Auth as the source of employment status and opens its offboarding checklist when Auth deactivates a person. **Drata:** a Drata identity-provider connection of Drata's CSV connection type, beside any others the account holds, kept current by Auth through Drata's public API so that "MFA on Identity Provider" is checked against Auth for every person sourced from it; any Drata partner listing needed for an automated connection is part of this clause's engineering. **Secureframe and Thoropass:** the vendor's documented custom identity integration, with the recipe stating whether the vendor's tests read a live connection or a delivered file. Each connector sends, for every person in scope: Auth person ID, work email and name; status active, suspended or terminated, with the termination time; MFA enrolled, true only when the person holds a factor that satisfies the employer's MFA policy; each enrolled factor type, mapped through a published per-vendor table to the vendor's values (passkey and security key, push, TOTP, SMS, email), with nothing unmapped silently dropped; group memberships, including AUTH-DIRECTORY-001 dynamic groups, so the platform scopes people and access reviews by Auth group; and administrator or privileged role (AUTH-DECISIONS-001). It pushes the full state at least hourly, and each lifecycle, factor or administrator-role change within AUTH-TIMING-001's 60-second dispatch bound. Each sync records the vendor's acknowledgment and, where the vendor's API allows, a read-back of what it stored. A failed or unacknowledged sync, or a last success older than two hours, shows on the connector's health and in AUTH-REPORTS-001 and raises an AUTH-FOLLOWUP-001 obligation; it is never shown green. Which people and groups are sent is an administrator write previewed with who is added and removed. Connector credentials stay in connector custody (AUTH-RETENTION-001), and every sync is audited. The same per-person state feeds the Evidence sibling. Auth supplies identity facts; the platform, Evidence and the auditor judge the controls.

**Acceptance.**
1. In an authorized Vanta test tenant, connect Auth through the private integration: Vanta's accounts page shows every Auth person in scope with the correct status, MFA status and factor types, and a custom MFA test passes.
2. Remove one person's last factor and see the test fail within one sync; offboard another and see them in Vanta's offboarding queue within one sync.
3. Scope by an Auth group and see Vanta's scope follow a membership change.
4. Repeat in a Drata test tenant and see "MFA on Identity Provider" pass and then fail the same way.
5. Configure the Secureframe and Thoropass recipes in authorized test accounts and see each person's MFA status.
6. Revoke the Vanta credential and see the connector unhealthy, with a follow-up raised, within two hours.

**Evidence.** None.
**Gap.** No implementing product path in audited src/ and tests/; acceptance journey remains to be built.

### Migration, integration and operations

#### AUTH-MIGRATION-001 — Switch from Okta, Entra ID or JumpCloud

Core · target · **partial**

**Requirement.** Guided migration from each named incumbent inventories users, immutable source subjects, groups, app/role assignments, SAML/OIDC settings, password-based (Okta SWA) app definitions, provisioning rules, factors, devices, admin roles with their resource sets, and policies through authorized APIs/exports, and lists each Okta Workflows flow with the AUTH-WORKFLOWS-001 template or step that replaces it (an API Connector card maps to the HTTP request step), and each Okta inline hook to its AUTH-HOOKS-001 equivalent. Preview maps what can transfer and names every unsupported/credential-bound item with an actionable reenrollment or partner step; never import working sessions, private keys or fake MFA proof. Factor and password re-enrollment runs as AUTH-MIGRATION-003's enrollment campaign. Staged cohorts, old-to-new subject maps, app-owner-approved subject binding, dual-provider coexistence, reconciliation and rollback preserve employee access without enabling imported authority. The inventory also lists the incumbent's identity-reading integrations: compliance platforms (Vanta, Drata, Secureframe, Thoropass) and any other service holding an incumbent API token or reading its system log. For each it names the Auth replacement (AUTH-COMPLIANCE-001 for compliance platforms, AUTH-EVENTS-001 or the AUTH-AUDIT-001 streams for log readers) or states that none exists. The cutover plan connects every replacement and holds cutover until each one's first successful sync, so no compliance test loses its source during an audit observation window. Final cutover verifies SSO and leaver revocation in every affected app.

**Acceptance.**
1. For Okta Workforce Identity, Microsoft Entra ID and JumpCloud separately, migrate a populated authorized test tenant with groups, apps, a collision, suspended worker and privileged assignment.
2. Pilot a cohort, re-enroll factors through the AUTH-MIGRATION-003 campaign, compare counts/permissions, roll back and cut over; prove old subjects cannot act as credentials and no app is silently omitted.
3. With Vanta and Drata connected to the incumbent, see both listed with AUTH-COMPLIANCE-001 as their replacement, and cutover held until each replacement's first sync succeeds.

**Evidence.** `src/auth/move-in/sources.mjs`; `src/auth/move-in/routes.mjs`; `tests/auth/move-in-staging.test.mjs`; `tests/auth/move-in-admission.test.mjs`
**Gap.** Export staging and admission exist for all three; full configuration, group and app migration and live cutover are missing. JumpCloud, Vanta and Drata accounts are not held.

#### AUTH-MIGRATION-002 — Custom-directory and progressive move-in

Core · target · **done**

**Requirement.** Existing Google Workspace/Auth0 exports and authorized custom-directory/database migrations preserve reviewed identifiers and profile history. A constrained migration bridge may verify an eligible worker’s old password at their first successful sign-in, then enroll them into Auth under employer policy and retire that bridge after cutover. Secrets never enter agent context or logs, failed old authentication grants nothing, and unsupported password hashes/factors are explicitly reset or reenrolled rather than fabricated. This is workforce migration compatibility, not a separate consumer identity product. Its future password-verification or match/create import doors inherit every AUTH-HOOKS-001 signature, minimal-payload, timeout/fail-policy, protected-identity, destination and audited-call obligation before shipping.

**Acceptance.**
1. Import Google and Auth0 records, migrate one eligible legacy worker at first login through the real bridge, and compare downstream subject mapping before/after.
2. Refuse a wrong password, email collision and disabled worker; interrupt migration and prove an idempotent outcome and a cleanly disabled bridge.

**Evidence.** `tests/auth/move-in-staging.test.mjs` — "Google Workspace JSON export stages through the route" and "Auth0 CSV and NDJSON exports stage through the route"; `tests/auth/move-in-admission.test.mjs` — "reviewed custom-directory workers migrate at first legacy login with protected history, exact subject mapping, inherited hooks and permanent bridge shutdown": reviewed history and subjects, wrong-password/collision/disabled refusals, real Auth email/passkey enrollment and linked-app sign-in, delivery interruption/restart, permanent and in-flight shutdown; `tests/integration/move-in-browser.test.mjs` — "move-in journey: stage a 30-person Google export, review, admit, invite and undo at desktop and mobile in both themes": first-login migration and enrollment at 1440/390; `docs/progressive-migration.md`
**Gap.** None for the documented constrained verifier profile. Standalone exact-candidate bound receipt: `sx-auth-c12-final-targets`. Unsupported hashes/factors require reset/reenrollment; old-password verification never supplies Auth proof or administrator authority.

#### AUTH-MIGRATION-003 — Cutover enrollment campaign

Core · target · **partial**

**Requirement.** Incumbent passwords and factor enrollments cannot be exported, so switching from Okta, Entra ID or JumpCloud includes an enrollment campaign that gets every employee enrolled in Auth before cutover without help desk. The administrator federates the incumbent as an upstream for the campaign (AUTH-FEDERATION-001: Okta, Entra ID or JumpCloud over OIDC or SAML) and sets a cohort, an enrollment deadline and a cutover date. Each employee is notified at their work address and in Slack or Teams (AUTH-FOLLOWUP-001), signs in to Auth with their current incumbent sign-in, including its MFA, as proof of identity, and enrolls a passkey and the Auth authenticator, plus a password where AUTH-ENROLLMENT-001 enables it. Auth binds the incumbent's immutable subject to the person AUTH-MIGRATION-001 staged, never by email match alone. Where the incumbent's API allows verifying a password (Okta's Authentication API), an optional bridge checks the employee's current password at their campaign sign-in and keeps it as their Auth password under AUTH-PASSWORD-001, so VPN users keep working at cutover. A campaign dashboard shows each person as enrolled, pending, overdue or exempt, with factor types, per-cohort counts and the number left before cutover. Reminders escalate to the manager 3 days before the deadline and to the administrator at the deadline, and the straggler list exports. Federated campaign proof is accepted only during the campaign window and only for staged people. After cutover the federation is removed, and anyone not enrolled uses a temporary access pass (AUTH-TAP-001). Campaign proof never confers administrator authority; administrators enroll under AUTH-IDENTITY-001.

**Acceptance.**
1. In an authorized Okta test tenant with 20 staged employees, run a campaign: all 20 enroll through Okta-federated proof with no help-desk action while the dashboard counts down.
2. Leave 3 unenrolled and see them named as overdue with manager reminders and in the export.
3. Refuse a person whose email matches but whose Okta subject differs, an unstaged person, proof after the campaign window and campaign proof for an administrator.
4. Bridge one employee's Okta password and sign in with it at RADIUS after cutover.
5. Repeat the enrollment proof with Entra ID and JumpCloud as upstreams.
6. CT policy ruling, 26 October 2026: The owner may explicitly select a cohort manager.
7. Sending that manager enrollment reminders requires separate audited outbound consent in a policy write by the organization owner or a role holding the published manage-follow-up permission, with hardware passkey and fresh local email proof rechecked at commit.
8. Campaign creation, a directory manager field and existing reminder consent do not grant this consent. Each manager notice contains only the affected employee’s name, work address and enrollment deadline. Dispatch rechecks the selected manager’s current organization membership, state and cohort duty; a failed recheck follows the existing approved escalation rule. The notice grants no enrollment, recovery, approval or administrator authority and contains no credential or proof-bypassing link. Consent, dispatch outcomes and stopping history remain subject to AUTH-FOLLOWUP-001, AUTH-FOLLOWUP-002, AUTH-RETENTION-001 and AUTH-ERASURE-001. Completion, cancellation or expired campaign authority stops reminders. This policy does not replace any enrollment, channel, escalation, export, cutover or provider acceptance requirement.

**Evidence.** `tests/auth/move-in-admission.test.mjs` — "an immutable-subject campaign enrolls twenty staged workers, counts down, reminds managers once and refuses MFA, window and administrator bypasses" (twenty local passkey-ready workers, countdown, three overdue names, CSV, durable consent-bound reminders, exact subject, MFA, administrator and cutover refusal); `tests/integration/move-in-browser.test.mjs` — "move-in journey: stage a 30-person Google export, review, admit, invite and undo at desktop and mobile in both themes" (campaign setup, pending, overdue and closed screens at 1440 and 390); `docs/upstream-campaigns.md`
**Gap.** Partial remains unchanged. Native campaign passkey readiness is distinct from complete enrollment. Remaining Gaps are the live twenty-worker Okta callback with an authorized web registration, live Entra employee proof and JumpCloud qualification, native Auth authenticator enrollment, optional eligible Okta password preservation and RADIUS cutover, Slack or Teams delivery, and temporary access passes after cutover. Every original campaign acceptance point remains required. CT approves the separately consented minimal cohort-manager reminder policy with the stated riders; this ruling supplies no implementation or live-provider proof.

#### AUTH-DEVELOPER-001 — Working integration SDKs and admin API

Core · target · **partial**

**Requirement.** Versioned quickstarts and SDKs for Next.js/React, Node.js, Python and Hono cover real web/server sign-in, callback validation, sessions, logout, claims/API permission checks and scoped administration through AUTH-ADMINAPI-001 credentials. Embeddable user/organization components call the same authorized APIs. Examples declare exact supported profiles, errors, key-cache/rotation behavior and deployment steps; sandbox/test organizations use isolated real protocol flows and cannot mint production authority. App owners can extend the catalog without depending on RER.

**Acceptance.**
1. Build and run each framework quickstart against a fresh Auth install; enroll an employee, sign in, verify a protected API, switch an authorized organization, revoke access and observe logout.
2. Follow the docs from an empty app and diagnose a deliberately wrong redirect without hand-editing SDK internals.

**Evidence.** `tests/auth/agents-keys.test.mjs` — "a packed Node SDK installs in an empty app and enforces scoped private-key administration, pagination, ETags and live revocation over HTTP"; `packages/session-sdk/README.md`; `packages/session-sdk/admin.mjs`; `tests/auth/agents-keys.test.mjs` — "a built Python wheel installs in an empty app and enforces scoped administration, ETags, pagination and cached-token revocation over HTTP"; "an installed Hono quickstart checks genuine employee consent, callback binding, rotation and live revocation against fresh Auth"; `packages/admin-python/README.md`; `packages/hono-sdk/README.md`
**Gap.** Versioned Node and Python administration SDKs and unchanged installed quickstarts prove scoped private-key OAuth, pagination, exact ETags, path confinement and cached-token revocation. The installed Hono quickstart proves employee enrollment, real consent, callback validation, protected API checks, rotation and next-request revocation. Next.js and React, embedded components, full Python employee sessions, authorized organization switching and complete fresh-install browser sign-in and logout journeys remain unproved.

#### AUTH-ADMINAPI-001 — Admin API credentials for automation

Core · target · **done**

**Requirement.** An administrator under the AUTH-IDENTITY-001 gate creates an admin service app: an OAuth 2.0 client-credentials client authenticating with `private_key_jwt` (a client secret is not offered for admin scopes), granted least-privilege admin scopes (for example `people.read`, `people.manage`, `groups.manage`, `apps.manage`, `assignments.manage`, `policies.manage`, `idps.manage`, `domains.read`, `logs.read`), optionally narrowed to an AUTH-ROLES-001 resource set. Each has a named accountable human owner, an expiry of at most 12 months, an optional source-IP allow-list and a published purpose; access tokens last at most 15 minutes. Exclusions are stated per scope and enforced: no admin scope can assign or change administrator roles or resource sets, change any person's factors or recovery, approve recovery, manage signing keys, create or change admin service apps, change emergency accounts, or widen its own policy. Every call is audited with the service app, owner, scope and result; the owner's demotion, suspension or departure suspends the app until a new owner is assigned. The full admin API is a documented, versioned REST API with OpenAPI description, pagination, ETags for optimistic concurrency and rate-limit headers. Preparer keys (AUTH-ADMIN-001) stay propose-only and are distinct from these credentials.

**Current v1 semantics:** Exposes native people/profile/lifecycle, groups/rules/membership, SAML/OIDC company apps and assignments, exact-domain provider requirements, configured-provider availability, domains and safe audit reads. Resource sets are explicit people/group/app IDs; creation requires unrestricted access to the new resource kind, and compound effects must remain within the grant. Provider identity and credentials remain owner configuration; `idps.manage` enables or disables that configuration and cannot replace its issuer, client or bindings. Tokens are issuer-local, at most five minutes, with live owner/revision/IP checks; mutations use guarded native commands and atomic shared-revision ETags. AUTH-ROLES-001, AUTH-POLICY-001 and AUTH-FEDERATION-001 inherit the same scoped, excluded-action, audit and concurrency obligations for their future machine doors before shipping.

**Acceptance.**
1. Create a service app with `groups.manage` and `assignments.manage` from an allowed IP, call the API to create a group and assign an app; call a policy endpoint and from another IP and be refused; attempt each excluded action with every scope and be refused.
2. Expire the app, suspend its owner, and replay a stale ETag; each is refused or suspended as stated, and the audit shows every call.

**Evidence.** `tests/auth/agents-keys.test.mjs` ("admin service apps use private-key OAuth for scoped group and assignment writes; resource, IP, expiry, owner and ETag fences refuse automation while every scope excludes identity and credential custody": allowed group/assignment, wrong scope/IP/resource, every exclusion under every advertised scope, app/token expiry, persistent suspension/demotion/departure, reassignment, stale ETag, complete call audit and no stored assertions/tokens/private keys; "machine directory and company-app commands share native lifecycle planning, dynamic membership, safe paginated reads and optimistic updates": native people/rule/app/policy composition, pagination, safe reads and optimistic updates); `tests/auth/fresh-proof.test.mjs` ("every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation": service create/reassign/revoke); `tests/integration/agents-browser.test.mjs` ("agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes": register, use and revoke a real service app and inspect attributed Activity at 1440/390); `docs/admin-api.md`
**Gap.** None.

#### AUTH-TERRAFORM-001 — Terraform provider

Core · target · **partial**

**Requirement.** A Terraform provider published on the public Terraform Registry (and usable with OpenTofu) manages Auth's people, groups, group rules, apps (SAML, OIDC, password-based) and their assignments, attribute mappings, policies, identity providers, domains and automations, authenticating with AUTH-ADMINAPI-001 credentials. It supports `plan`, `apply`, `import` of existing objects and drift detection, with idempotent applies and documented resource schemas; it can never do what its credential's scopes exclude, so administrator roles, resource sets and their holders, factors, recovery and signing keys stay with interactive administrators.

**Acceptance.**
1. Against a fresh install, `terraform plan` and `terraform apply` create a group, an app assignment and a policy; a second plan shows no changes; a change made in the UI appears as drift on the next plan; `terraform import` adopts an existing app.
2. A resource needing a scope outside the credential's grant fails at apply with a refused, audited call and no partial change to that resource.

**Evidence.** `packages/terraform-provider/README.md`; `tests/auth/terraform-provider.test.mjs` ("terraform installs the Auth provider and reconciles native resources with drift, import and audited scope and stale-plan refusals" and the matching OpenTofu journey: fresh native install, group, SAML app and assignment, unchanged plan, app update drift, existing-app import, exact ETag refusal without retry or proposed-state adoption, audited scope and resource refusals without partial mutation, RSA and P-256 OAuth, no private keys or tokens in state or diagnostics); `tests/integration/company-apps-browser.test.mjs` (company apps journey, extended by `tests/integration/helpers/terraform-journey.mjs`: actual Terraform apply, unchanged plan, Apps UI removal detected as drift, 1440 and 390 in both themes); `packages/terraform-provider/internal/provider/provider_test.go` ("TestRefusalNeverRetriesOrLeaksResponse")
**Gap.** Local installation and the three native resource types are implemented. Public Terraform Registry publication and signing remain gr-held. People, group rules, OIDC and password apps, attribute mappings, policies, identity providers, domains and automations remain unimplemented provider families. The required conditional-access policy remains AUTH-POLICY-001 device-held and automations remain AUTH-WORKFLOWS-001 account-blocked; the exact-domain provider rule does not replace that policy. Full policy and automation acceptance and public release remain unproved.

#### AUTH-MOBILE-001 — Native employee and administrator access

Core · target · **partial**

**Requirement.** Auth delivers iOS and Android employee app-launcher/account experiences and Expo/native iOS/Android SDKs using system-browser authorization, PKCE, universal/app links and OS-protected credential storage. Employees sign in with passkeys, use the app as their push and TOTP authenticator (AUTH-AUTHENTICATOR-001), launch company apps, view/revoke devices/grants and recover access; managers and app owners decide requests under AUTH-DECISIONS-001; authorized administrators can review urgent access/recovery requests with the same hardware and local email gates. Responsive web covers the same essential flows. Employers deploy the app through Microsoft Intune, Jamf Pro, Kandji or Android Enterprise with managed app configuration (AppConfig: Auth tenant URL, enrollment and policy), so a managed phone opens already pointed at the employer. Lost phones, offline state and push notifications never imply approved access.

**Acceptance.**
1. On real iOS and Android builds plus Expo SDK clients, deploy the app with managed configuration through Intune and Android Enterprise, enroll a passkey, return through a verified link, launch an assigned app, approve an authorized request and revoke the lost device.
2. Refuse a hijacked callback and offline approval; exercise web equivalents at 1440 and 390.

**Evidence.** `src/ui/pages/account.ts`; `tests/integration/browser.test.mjs`
**Gap.** responsive account/admin web exists; native apps, mobile SDKs and launcher do not.

#### AUTH-EVENTS-001 — Reliable lifecycle events and webhooks

Core · target · **done**

**Requirement.** Authorized subscribers receive versioned signed events for people, memberships, assignments, policy, recovery and provisioning outcomes. Delivery uses stable IDs, bounded retries/backoff, secret rotation, replay protection and per-subscriber outcomes; consumers can resume from a cursor and reconcile missed events through the API. Destinations are validated against SSRF/private-network abuse. A delivery acknowledgment proves receipt only, and uncertain writes/events do not falsely close downstream access obligations.

**Acceptance.**
1. Subscribe a real app endpoint through admin/API, perform a joiner/mover/leaver, rotate signing material and recover after 429, timeout and outage.
2. Replay an event and request a historical cursor; verify ordered/versioned reconstruction without duplicate grants or missing unresolved work.

**Evidence.** `src/auth/events/`; `src/auth/outbound.mjs`; `tests/auth/events.test.mjs`; `COMPANY-APPS.md`
**Gap.** None.

#### AUTH-FOLLOWUP-001 — Follow-through until access is resolved

Core · target · **done**

**Requirement.** Enrollment, recovery, app setup, provisioning and revocation each keep an owner, next due action, employer timezone and business calendar, deadline, and stop/escalation rule. Email reminders go to approved recipients. Connector denial, missing approval and uncertain remote effect stay visible across restart, with actionable redacted errors. Satisfied, cancelled or expired authority stops reminders. A sent alert or a successful tool call alone never means the employee can sign in or has lost access. Every saved policy, including one saved before the escalation-recipient write check, escalates a failed recipient recheck to an approved owner or administrator. AUTH-TIMING-001's 15-minute unverified-downstream escalation is raised here. The reminder policy below governs AUTH-FOLLOWUP-001 to -004.

**Reminder policy (ct 22 Oct):** Reminder policy (channels, schedules, escalation, recipient rules) is an organization administrator write under AUTH-DECISIONS-001, by the owner or a role holding the published 'manage follow-up' permission; installation roles have none in an isolated organization. Until that write, obligations stay visible in Activity and no reminder is sent. Recipients are roles, never addresses: the person whose action is due (the employee for their own enrollment or recovery, the decider AUTH-DECISIONS-001 names for a request or review, the help desk holding the case), with escalation to an owner or administrator the policy names. Each recipient is rechecked at dispatch against current membership, state and authority; a failed recheck escalates instead. No recipient outside the organization, no free-text address, and no reminder carries a credential or a link that acts without its door's own proof. A reminder never performs a destructive or authority-changing action, and transport acknowledgment never counts as access success. Anyone currently holding an obligation may send its due reminder early, only to recipients the policy already allows. Source completion, cancellation or expired authority stops reminders at the next dispatch; history is kept under AUTH-RETENTION-001 and erased under AUTH-ERASURE-001.

**Acceptance.**
1. Leave an invitation, a recovery awaiting a distinct administrator's approval, and a failed deprovision unresolved across a weekend/DST change and a process restart.
2. Observe due actions, reminders and escalation, including for a legacy policy with no escalation recipient.
3. Complete or cancel each through its normal door, and verify reminders cease while the complete history remains.

**Evidence.** `tests/auth/provisioning.test.mjs` — "durable follow-up dispatches on the employer business calendar across DST and restart, escalates unresolved revocation and stops on source completion, cancellation and expiry": invitation, recovery awaiting distinct-admin approval and failed deprovision across weekend/DST/restart; due actions and reminders; legacy policy recipient-recheck escalation (including a stopped pre-0047 deadline); exact 15-minute downstream escalation outside business hours, concurrent/restart deduplication; normal-door completion/cancellation/expiry stops with retained history; policy refusals and credential-free mail. `tests/integration/agents-browser.test.mjs` — "agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes": Activity policy/scheduling, pending recovery restart and cancellation, enrollment completion and retained history at 1440/390 in both themes. `docs/follow-up.md`
**Gap.** None.

#### AUTH-FOLLOWUP-002 — Role-derived recipients, manage-follow-up authority and early send

Core · target · **done**

**Requirement.** The policy write is open to the owner or a role holding the published 'manage follow-up' permission. Installation roles have none in an isolated organization. Recipients are roles, never addresses: the employee for their own enrollment or recovery, and the help desk holding the case, with escalation to a named owner or administrator. Each recipient is rechecked at dispatch. Anyone currently holding an obligation may send its due reminder early, only to recipients the policy allows.

**Acceptance.**
1. A custom role with 'manage follow-up' saves the policy.
2. An installation role is refused.
3. The employee receives their own enrollment and recovery reminders, and the holding help desk receives its case reminders.
4. A help-desk holder who loses the role escalates.
5. A holder's early send reaches only allowed recipients, and a non-holder is refused.
6. All of this runs at 1440 and 390.

**Evidence.** `tests/auth/provisioning.test.mjs` — "follow-up duties resolve employees and scoped case holders, restrict early send and escalate lost case authority": a custom role holding the published manage follow-up permission (followup.manage) saves the policy and loses that write when revoked; an installation session has no employer session (401) and the same installation-role holder, signed in as a passkey member of the isolated employer, is refused with role_permission_required; scheduled reminders reach the invited and active employee for enrollment, the employee for their own recovery and the help desk holding the exact case, never administrators or policy managers; a holder who loses exact case authority fails the dispatch recheck and escalates to the named owner; holder early send ignores injected recipients, non-holders are refused with followup_holder_required and an early occurrence is not resent after restart or when due; cancellation stops reminders; a pre-0048 employer upgrades and case-binding erasure keeps anonymous history. `tests/integration/agents-browser.test.mjs` — "agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes", through `tests/integration/helpers/followup-roles-journey.mjs` followupRolesJourney at 1440 and 390 with light/dark captures: custom-role save in the settings form; installation owner, administrator and coordinator sessions refused at the isolated employer and the coordinator refused as its passkey member; employee enrollment, own-recovery and holding help-desk case reminders delivered through the gated outbox; injected-recipient and non-holder refusal; lost case role escalation with its visible recheck failure. `docs/follow-up.md`
**Gap.** None.

#### AUTH-FOLLOWUP-003 — Access-request, review and stale-source obligations

Core · target · **done**

**Requirement.** Access requests (AUTH-REQUESTS-001), review items (AUTH-REVIEWS-001) and stale directory or HR sources (AUTH-SCIM-002, AUTH-HRIS-001/002) become obligations under the AUTH-FOLLOWUP-001 engine. Reminders go to the decider AUTH-DECISIONS-001 names. Missing approval and stale source stay visible across restart.

Current source doors are native pending access requests, open native review items and registered HR file feeds. Requests and review items resolve the current decider at dispatch; follow-up ownership never grants decision authority. Stale HR delivery reminders require the separately selected source-owner duty in an explicit audited policy write; registering a feed and existing reviewer consent grant no additional outbound consent. The source owner must retain current administrator authority and the registered version. Source completion, cancellation or expired request authority stops reminders without deciding access. Future source doors in AUTH-SCIM-002 and AUTH-HRIS-001, and additional request or review doors in AUTH-REQUESTS-001 and AUTH-REVIEWS-001, inherit the same adapter, current-authority, consent, stop and retained-history obligations before shipping.

**Acceptance.**
1. Leave an access approval, an overdue review item and a stale source unresolved across a weekend/DST change and a restart.
2. Observe that decider reminders and escalation happen.
3. Decide, cancel or refresh each through its normal door, and verify reminders cease while the history remains.

**Evidence.** `tests/auth/provisioning.test.mjs` — "request, review and stale HR obligations retain decider reminders and resolution history across DST and restart" (implementation: `tests/auth/followup-decisions-flow.mjs`): (1) pending native requests, an overdue review item and a stale HR file feed remain recorded across the weekend, DST and a Worker restart; (2) current-decider reminders and approved-administrator escalation, explicit HR source-owner consent, concurrent and restart deduplication, changed request-policy expiry and refusal after source-owner demotion; (3) normal request denial, requester cancellation, review certification and valid HR refresh stop the old obligations while history remains. `tests/auth/directory.test.mjs` — "review reminders follow current reviewer consent and business calendars across restart with absence escalation": live delegation, absence and uncertain transport. `tests/integration/directory-browser.test.mjs` — "access decision and review journey: ordinary manager proof, request approval, immutable certification and unfinished removal, and retention controls at 1440 and 390" (implementation: `tests/integration/helpers/access-review-journey.mjs`): real Activity source records, normal source links, explicit consent saved through the settings form, responsive layout, accessibility and icon tooltips at 1440 and 390. `docs/follow-up.md`.
**Gap.** None for existing source doors. Future source doors inherit the obligations stated above.

#### AUTH-FOLLOWUP-004 — Slack, Teams and Oncall follow-up channels

Core · target · **missing**

**Requirement.** Reminders the policy allows are also delivered through Slack and Microsoft Teams, where recipients decide under AUTH-CHAT-001. Oncall can receive security escalation. Chat or Oncall acknowledgment never counts as access success.

**Acceptance.**
1. Through authorized Slack, Teams and Oncall test workspaces, deliver a reminder, decide a request from Slack and from Teams, and raise a security escalation to Oncall.
2. A recipient whose binding or authority has lapsed receives nothing and the reminder escalates.
3. Reminders contain no credentials and no links that act without their door's own proof.

**Evidence.** None.
**Gap.** Email only; no chat or Oncall adapters (depends on CHAT-001).

#### AUTH-DELIVERY-001 — Email and SMS delivery operations

Core · target · **partial**

**Requirement.** Employers use configured Base mail adapters or Amazon SES with verified sending identities for invitations, verification, recovery and security notices; Twilio supplies optional SMS verification. Private credentials, scoped templates, bounce/suppression handling, rate limits and durable delivery/uncertainty outcomes protect these messages. Admin diagnostics distinguish queued, provider-accepted and delivered/bounced evidence without exposing a usable link/token; local outbox remains private and sends no external mail. Provider failure does not grant identity proof.

**Acceptance.**
1. Configure SES and Twilio in authorized test accounts, enroll/recover a worker and observe accepted, bounced, throttled and unavailable outcomes.
2. Prove tokens/credentials absent from logs/exports and a notification failure leaves the original access obligation unresolved.

**Evidence.** `tests/auth/notifications.test.mjs` — mail delivery reconciles signed recipient-bound events, survives restart, suppresses bounced recipients and keeps diagnostic exports private; mail failures and throttling retain unresolved employee enrollment without replaying uncertain sends. `tests/integration/security-settings-browser.test.mjs` — mail delivery diagnostics distinguish private outbox and signed provider outcomes at desktop and mobile, via `tests/integration/helpers/delivery-journey.mjs`, proves private local, accepted, throttled, uncertain, bounced and suppressed diagnostics at 1440 and 390. `docs/mail-delivery.md`
**Gap.** SendGrid native reconciliation, suppression and delivery diagnostics are implemented. Authorized SES and Twilio setup and live enrollment and recovery outcomes remain unproved; live SendGrid delivery and bounce through the shared event relay remain pending account-operator forwarding registration. Conservative default adopted pending ct: recipient suppression is private, excluded from archives and has no automatic expiry or self-service bypass. Full live credential-free archive qualification remains pending.

#### AUTH-OPS-001 — Operate a company identity service

Core · target · **partial**

**Requirement.** Self-operation is the delivery model this contract measures: the employer's owner deploys, upgrades, monitors, backs up and recovers the installation. An install RER Managed provisions holds RER link-approval trust (AUTH-RER-TRUST-001), and that provisioning belongs to RER Managed, not to this seed (`seed.json` non-goals); the operations page names who operates each installation, and the objectives below bind whichever operator runs it. Owners can deploy, upgrade, monitor, back up and recover a US-first identity installation with explicit issuer/key custody, US data-region choices, maintenance/incident runbooks, capacity and recoverable connector state. The published objectives for the supported production deployment (Cloudflare Workers with D1, as `deploy.json` defines it) are: 99.99% monthly availability of sign-in, token, SAML, WS-Federation, RADIUS and launcher endpoints and 99.9% of the admin console; recovery time objective 1 hour and recovery point objective 5 minutes for a regional failure or a restore from backup; p95 server-side latency at a US edge of at most 300 ms for an authorization or SAML response and at most 200 ms for a token or UserInfo response, excluding the person's own interaction and upstream/push wait; and RADIUS responses within 2 seconds plus the person's push response. Measurements over each month are published on the operations page with the method used. Uptime monitors sign-in/provisioning health and Oncall receives actionable incidents. Administrators see active-worker, app, SMS/email and connector usage with USD price/cost rules and exportable forecasts before enabling billable providers; estimates distinguish measured usage and provider charges. No certification, service level or hosted capacity is claimed without measurement.

**Acceptance.**
1. Deploy to the supported production host, perform a rolling/key-certificate upgrade, fail a dependency, restore a backup and measure against each numeric objective: availability from synthetic sign-ins at one-minute intervals across a month, the restore's elapsed time against the 1-hour RTO and its newest recovered write against the 5-minute RPO, p95 authorization/SAML and token/UserInfo latency under a load of 50 sign-ins per second, and leaver processing against AUTH-TIMING-001.
2. Trigger Uptime/Oncall escalation and reconcile the USD usage forecast to actual provider usage without exposing secrets.

**Evidence.** `AUTH-COMMANDS.md`; `scripts/installer/local.mjs`; `src/auth/keys.mjs`; `tests/integration/dev.test.mjs`
**Gap.** local command/recovery and key operations exist; hosted resilience, SLO measurement, region selection and usage forecasting are missing.

#### AUTH-RECOVERY-002 — Emergency continuity and recovery drills

Core · target · **done**

**Requirement.** Employers maintain separately protected emergency administrators, redundant factors/keys and documented issuer, upstream-outage, lost-factor and connector recovery paths. Scheduled drills prove those paths with scoped test identities, without bypassing the existing local email/hardware gates or turning an offline archive into active authority. High-risk recovery changes require independent approval, notify the affected employee/security owner and are cancelable where a delay applies; rotation after use is explicit. A drill reports failed and unmeasured steps.

**Acceptance.**
1. Drill lost phone/key, unavailable upstream, expired signing certificate and restoration of an owner installation through the public account/CLI doors.
2. Confirm ordinary workers cannot invoke emergency authority, cancellation wins against completion where applicable, all notices persist and used credentials cannot be replayed.

**Evidence.** `tests/auth/security.test.mjs` — scheduled continuity drill exercises protected lost-factor recovery, upstream outage and expired signing-certificate replacement: separate backup administrator with redundant hardware, distinct higher-rank approval, durable employee notices and mail, signed security-owner delivery across outage and restart, cancellation and replay, upstream refusal and recovery and strict X.509 date refusal and replacement; `tests/integration/http.test.mjs` — scheduled installation continuity drill restores an owner through real archive and local recovery commands without replaying authority: real CLI archive, reset and import, separate private configuration, dead archived sessions and tokens, owner-only local recovery and replacement factors; `tests/auth/provisioning.test.mjs` — a provider answering 429 and 503, or losing a response, is retried until it recovers with no duplicate account; `tests/integration/browser.test.mjs` — real Auth pages: browser email, first setup, hardware passkey, people and account at desktop/mobile in both themes: pending and cancelled recovery at 1440/390; `docs/continuity-drills.md`; `.github/workflows/continuity.yml`
**Gap.** None.

#### AUTH-RECOVERY-003 — Same-day help-desk recovery for employees

Core · target · **partial**

**Requirement.** A non-privileged employee who has lost every factor and holds no recovery code is restored the same business day through help desk. A help-desk holder whose AUTH-ROLES-001 scope covers the employee opens a recovery case and records a verification step the employer's policy accepts: attestation by the employee's manager from the manager's own signed-in session, a remaining enrolled factor (push or TOTP), or an ID-document and selfie check through Persona or CLEAR, whose result (not the document) is stored. On a passed check, help desk resets the employee's factors and issues a single-use enrollment link, a temporary access pass (AUTH-TAP-001) or a desktop recovery PIN (AUTH-DESKTOP-001), valid for at most 1 hour and bound to the case; all the employee's sessions and devices are revoked, and the employee and their manager are notified on every enrolled channel and by email. There is no 72-hour wait for these employees. The path is refused for anyone holding an administrator or privileged role (AUTH-DECISIONS-001), who stay on AUTH-IDENTITY-001's approval, delay or emergency rules, and for anyone outside the help-desk holder's scope. Help desk's own action is under the administrator gate, and every case records who verified what, how and when.

**Acceptance.**
1. As help desk scoped to the employee's group, restore a non-admin employee with no recovery code through manager attestation, and another through a Persona check in an authorized test account, each from case opening to a newly enrolled passkey in under 1 hour.
2. Refuse the path for an administrator, for an employee outside scope, without a recorded verification, and on reuse or after an hour of the enrollment link; see the revoked sessions and every notice.

**Evidence.** `tests/auth/security.test.mjs` ("recovery waits 72 hours, notifies every session, supports cancellation and distinct admin approval", including `tests/auth/recovery-cases-flow.mjs`: manager-bound attestation, active-case link enforcement, cancellation and later administrator-reset enrollment, replay and expiry refusal, replacement passkey authentication); `tests/integration/directory-browser.test.mjs` ("organization and authority journey")
**Gap.** Manager-session attestation, scoped reset, native session and passkey revocation, digest-only case-bound single-use enrollment, employee and manager email notices, and the native passkey journey are implemented. Closing a case or a later administrator factor reset voids incomplete enrollment requirements; active and expired case links retain their existing gates. Persona or CLEAR qualification requires an authorized test account and consenting subject; remaining push or TOTP verification, temporary access pass and desktop PIN alternatives, real-device revocation, every enrolled-channel notification and live delivery remain unproved.

### Privacy, custody and Base replacements

#### AUTH-ERASURE-001 — Authorized erasure with retained accountability

Core · target · **done**

**Requirement.** Owners erase under explicit retention/legal-hold policy, after an exact preview tied to the current revision and counts and a confirmation rechecked at commit, with hardware passkey and fresh local email proof (AUTH-IDENTITY-001); erasure is never scheduled and no erase permission is delegable. An organization owner erases people, app connections and memberships in their organization; the installation owner erases or resets organizations and the installation, and erases a person's installation identity under AUTH-ERASURE-002. Erasure removes profiles, factor keys, invitations, grants, staged/import copies, connector credentials and dependent personal data across one shared store registry used by preview, erasure, export and restore, which refuses any store it does not know. It cuts off access at once (sessions, tokens, back-channel logout, connector deactivation) without further consent; deleting data held by a downstream app needs the owner's consent per destination, and no remote deletion is automatic. Unfinished remote work is reported separately and keeps only the minimum destination identifier it needs, sealed, until it completes or is explicitly abandoned. A legal hold naming the subject refuses the whole erasure (target: erase the unheld remainder and keep the held part restricted behind audited access, erased later only on a fresh preview and reconfirmation). Durable audit/decision evidence uses anonymized references whose tamper evidence still verifies, with a per-store completion receipt and portability fence; restore cannot resurrect erased records when given the later erasure journal (AUTH-TRANSFER-002). AUTH-RETENTION-001 expiry is not erasure and is unaffected. Already delivered messages, exported archives, external audit sinks and independently held provider data have named limits, owners and partner deletion instructions and are never reported as erased. Suspension alone is not erasure; the last owner requires a protected reset/transfer path. A protected organization reset, which removes the organization's issuer and its last owner and sessions, leaves only anonymous receipts and outcomes (no name, email, profile, directory, destination identifier, signing key or credential) and sealed remote work pending at reset, sealed to the installation and never shown or exported in clear; both pass to installation owner custody alone. No other caller authority from the organization survives: its owners, administrators, members, sessions, service apps, preparer keys and invitations end, and the erased issuer answers not found at every door. The installation owner sees each item's app, operation, state and outcome, never the person or destination identifier, and may retry or abandon it under AUTH-IDENTITY-001 proof. A retry performs only work already authorized: revocation as recorded, and deletion only where the organization's owner consented per destination before the reset. Because the organization's connector credential is destroyed, a retry needs a new connection the installation owner explicitly authorizes for that destination, verified to reach the same remote tenant, limited to that work and destroyed with it; without one the item stays blocked with partner deletion instructions. Completion or abandonment destroys the sealed identifier and keeps an anonymous outcome. Every view, retry, connection and abandonment is recorded in the installation audit.

**Current erasure semantics (ct 21 Oct 22:55Z; custody conformance proven):** Owner proof, explicit policy, exact preview/confirmation, whole-hold refusal, per-store erasure, separate remote outcomes, the shared fail-closed registry and signed anonymous audit are implemented. The ratified reset policy separates anonymous receipts/outcomes from sealed pending identifiers, destroys employer connector credentials and limits installation-owner custody to previously authorized work through a fresh tenant-bound connection. HTTP journeys prove those custody requirements, erased-issuer doors, root audit and cleanup. Named HTTP assertions also cover owner hardware/fresh-email gates, installation-admin refusal, unknown-registry refusal, stale person previews, employer-owner erasure, live credential termination, successful revocation retry without deletion consent and external-copy limitations. CT 22 Oct 00:20Z assigns voluntary membership links and opaque release obligations to AUTH-ERASURE-002. Installation-identity erasure does not search, match, enumerate or wait on separate employer identities. The Base journal currently refuses the whole earlier archive; restore that applies the journal and restores inactive remains AUTH-TRANSFER-002. Whole-hold refusal is the conservative interim, and AUTH-RETENTION-001 expiry remains separate.

**Acceptance.**
1. Erase a worker with multiple factors, imports, agent grants and SaaS access through the owner door; query/export all stores, inspect receipt and anonymized audit, and attempt restore of a pre-erasure archive with the later journal.
2. Keep a blocked remote deletion visible, test legal hold and last-owner protection, then reset a local installation.

**Evidence.** `tests/auth/provisioning.test.mjs` — "owner erasure previews every store, honors legal holds, anonymizes decisions and keeps refused remote deletion visible"; "app erasure removes connector custody and protected organization reset retains only installation-owner anonymous outcomes and credential-free pending work"; `tests/integration/http.test.mjs` — "owner erasure fences a pre-erasure rer archive with its later journal, restores anonymous evidence and resets the local installation"; `tests/auth/fresh-proof.test.mjs` — "every sensitive action refuses a stale local email proof without change and succeeds after a fresh confirmation"; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile"; `docs/erasure.md`
**Gap.** None.

#### AUTH-ERASURE-002 — Per-person erasure across separate organization identities

Core · target · **partial**

**Requirement.** A person's installation identity and each membership are separate identities (AUTH-TENANCY-002), each erased by its own owner. A person may link a membership only while holding independently proved live sessions in both, confirming with a passkey in each. The link is a random per-pair handle, visible only to that person and in their own export, and the person may remove it. Installation-identity erasure erases installation-held data and never waits on, enumerates or matches memberships. Each linked membership receives an opaque release notice (handle and erasure reference only). The notice becomes an AUTH-FOLLOWUP-001 obligation for that employer's owner to erase the membership under AUTH-ERASURE-001 or record the hold preventing it. The installation owner learns neither which employers were notified nor how many. Unlinked or unproved memberships are never searched, seen, erased or reported erased. Every organization's sign-in names how to ask its owner for erasure. The person's receipt lists each notice's state and says: "Auth erased your installation identity. Memberships you did not link are held separately by those employers; Auth did not see or erase them. Ask each employer to erase them." Organization erasure destroys its handles.

**Receipt access (ct 23 Oct 10:25Z, approved with riders):** A person explicitly requests their own key from their own passkey session. It is shown once, stored only as a digest and body-posted, never placed in a URL or log. It reads only that person's receipt and cannot sign in, erase an identity or list memberships. It expires after thirteen months; the person may explicitly surrender it, including after sign-in ends. Expiry and revocation retain anonymous facts and clear the receipt payload. Each notice in the receipt carries only its random handle, erasure reference and state, with no employer, organization or count. CT requires this clause to remain partial.

**Acceptance.**
1. Give one person isolated memberships A, B and C.
2. Link A from proved sessions, refuse a link to B from a root session alone, and leave C unlinked.
3. No administrator sees the link in UI, admin API or export.
4. Installation-identity erasure commits without a membership check; only A gets a handle-only obligation; the root preview and receipt name no employer or count; the person's receipt shows A's notice and the unlinked sentence.
5. Erasing an organization's creator leaves the organization.

**Evidence.** `tests/auth/security.test.mjs` — "voluntary independent identity pairs keep employer release notices private through installation erasure, holds, membership erasure and creator removal": independent A, B and C sessions, two passkey confirmations, root-only, foreign and replay refusals, private own export and unlink, owner preview and receipt privacy, only A notice, durable owner follow-up, hold, reopen and erase, opaque personal receipt, explicit own-passkey issuance, digest storage, authority isolation, body-only transport, post-erasure revocation, thirteen-month expiry with retained facts, organization handle destruction and creator erasure; `tests/integration/directory-browser.test.mjs` — "identity release journey: two independent passkeys, private administration, opaque employer follow-up and erasure contact at 1440 and 390"; `docs/erasure.md`
**Gap.** CT 23 Oct requires PARTIAL. Default ADOPTED: possession of the body-posted key plus explicit confirmation can surrender only that key after sign-in ends. CT approval of this post-erasure revocation proof is pending. Pre-rider receipt payloads with already-destroyed notices cannot reconstruct opaque handles and fail closed.

#### AUTH-ERASURE-003 — Erasure revokes everything

Core · target · **partial**

**Requirement.** Erasing an account revokes at once every session, API key, passkey, OAuth client token and refresh token, and delegation the account holds or issued. The audit row keeps only an opaque id and the revocation counts by credential kind, never a name, email or other personal data. Exports and backups never restore an erased account's credentials: a restore drops them and writes the same opaque-id audit row. A failed revocation step aborts the erasure with nothing half-done. The receipt rules of AUTH-ERASURE-002 (digest-only, no employer or count) are unchanged.

**Evidence.** `tests/auth/provisioning.test.mjs` — "owner erasure previews every store, honors legal holds, anonymizes decisions and keeps refused remote deletion visible": live sessions, preparer keys, passkeys and client OAuth authority, atomic failure and anonymous kind counts; `tests/auth/oidc-apps.test.mjs` — "native offline consent and SDK rotation preserve device binding, detect reuse and concurrency, and end resource authority on expiry, revocation, suspension and app removal": independently live access and refresh credentials, next-request erasure refusal, rollback and nonzero refresh counts; `tests/auth/agents-proposals.test.mjs` — "a person-consented agent changes exactly one employer assignment after independent employer approval; substitutions, replay and every local ending deny its next request": matched one-use resource successes beside issuer and holder erasure refusals, removed grants, resource authority after rollback and nonzero delegation counts; `tests/integration/http.test.mjs` — "owner erasure fences a pre-erasure rer archive with its later journal, restores anonymous evidence and resets the local installation": portable opaque audit and refused erased passkey after restore; `tests/integration/directory-browser.test.mjs` — "organization and authority journey: switch employers, delegate a scoped reset, authorize a service and erase a worker at desktop/mobile"; `docs/erasure.md`
**Gap.** AUTH-TRANSFER-002 receives the unproved assertion that restoring a pre-erasure product export or backup never revives the erased account or any credential, drops erased records and replays the same opaque audit. Product restore currently refuses the whole older archive with a later journal; the required Base staged journal hook is not in released rer 0.2.80. Counts enumerate removed durable credential authorities, not every signed stateless token string. Backups held by the platform operator outside the product are not covered.

#### AUTH-RETENTION-001 — Explicit retention and secret custody

Core · target · **partial**

**Requirement.** The product publishes employer-controlled retention for profiles, source snapshots, authentication/decision history, provisioning obligations, audit, model traces and erasure receipts, including retention holds and US storage/processor choices. Out of the box, sign-in, administration and decision audit is kept for 13 months, configurable up to 7 years; the employer can never set it below 90 days, and no event is deleted while an open access review, access request, investigation or legal hold refers to its period. Before any scheduled deletion, the employer can export what will be deleted. Expiry of short-lived challenge/rate-limit/token state cannot delete the only evidence of an unfinished obligation or improve a completion report. Encryption, scoped access and rotation protect signing/connector secrets at rest and in transit; raw credentials and authentication links never enter model context, ordinary logs, public assets or portable archives.

**Acceptance.**
1. On a default installation, confirm 13-month audit retention; try to set it to 30 days and be refused; open a review over a period and see its events kept past their expiry.
2. Populate every retained class, age it across each configured expiry, restart and inspect the public history/export doors: transient secrets expire, retained history and unresolved obligations remain, held data is preserved and scheduled deletion produces accountable results.
3. Rotate a connector/signing key and verify secrets absent from logs/assets/archive.
4. Current expiry uses eight configurable classes with a 13-calendar-month default, a 90-day floor and seven-calendar-year maximum.
5. Default ADOPTED pending ct: scheduled expiry waits for an explicit audited policy confirmation; non-audit classes inherit that default; terminated profile expiry anonymizes name/email and expired fields while retaining identity/state; erasure holds protect the whole employer and unfinished work protects its evidence period.
6. Each exact deletion set has a seven-day export window and at most 200 rows, with live hold/state rechecks and authenticated anonymous expiry commitments preserving erasure audit verification.
7. Storage/processor selection is disclosed as employer deployment configuration, without claiming verified residency.

**Evidence.** `tests/auth/directory.test.mjs` — retention previews export before expiry and preserve held classes and unfinished work across restart; `tests/auth/provisioning.test.mjs` — scheduled retention expiry preserves erasure audit verification while altered expiry commitments fail; `tests/auth/retention-flow.mjs`; `tests/auth/retention-integrity-flow.mjs`; `docs/retention.md`; `src/auth/retention/index.mjs`  `tests/integration/http.test.mjs` — owner erasure fences a pre-erasure rer archive with its later journal, restores anonymous evidence and resets the local installation; `tests/integration/erasure-portability.mjs`; `tests/integration/directory-browser.test.mjs` — access decision and review journey;
**Gap.** Eight-class retention, calendar default/bounds, review/request/investigation/legal holds, pre-delete export, restart/concurrent cleanup and authenticated expiry built. Default ADOPTED pending ct: scheduled expiry waits for an explicit audited policy confirmation; non-audit classes inherit 13 months; terminated profiles anonymize while identity/state remain; whole-employer erasure holds and unfinished-period holds; seven-day export window and 200-row batches. Deployment region/processors disclosed, not independently verified.

#### AUTH-TRANSFER-002 — Complete workforce portability

Core · target · **partial**

**Requirement.** Beyond AUTH-TRANSFER-001’s current identity archive, versioned export includes organizations, workforce attributes, groups, source/subject maps, app recipes/assignments, policies, access requests/reviews, lifecycle obligations/outcomes, delegated-grant definitions, audit and erasure journals. Import previews validation/conflicts and restores inactive into an empty authorized destination; no app send, provisioning write, trusted agent or session starts until the receiving owner reauthorizes. Installation-local signing/wrapping keys, connector credentials, refresh/bearer tokens and passkey private material never travel. Same-host public passkey/subject continuity and cross-host reenrollment/re-link limits are explicit.

**Acceptance.**
1. Create a populated workforce installation, export/import/export through rer and compare every declared portable record.
2. Refuse corrupt/foreign/unknown schema and nonempty destination; restore with later erasure journal, confirm all jobs/grants are inactive, then reauthorize one connector and verify exactly its approved work resumes.

**Evidence.** `scripts/installer/transfer.mjs`; `src/auth/stores.mjs`; `src/auth/links/grant-map.mjs`; `tests/auth/linking.test.mjs` — "an app links with a one-use token, signs a person in through Auth, and Sign out everywhere ends that app session"; `tests/integration/http.test.mjs` — "owner erasure fences a pre-erasure rer archive with its later journal, restores anonymous evidence and resets the local installation"
**Gap.** Shared portable inventory, credential/session/sealed-work exclusions and the Base whole-older-archive fence are implemented; the actual CLI archive journey passes at `64d257be` in Verify Auth `39703632411`. Complete inactive workforce/grant/job restoration, validation/conflict preview, destination organization schemas and receiving-owner reauthorization remain obligations. Whole-archive refusal is interim and cannot complete AUTH-TRANSFER-002.

### Push further: agents serving workforce identity

#### AUTH-AGENT-001 — Agent-led SaaS onboarding

Core · push-further · **partial**

**Requirement.** With an app owner’s scoped consent, an agent reads vendor metadata, current catalog recipes and employer group/role policy, prepares SAML/OIDC and SCIM settings, proposes mappings and configures approved changes through actual vendor APIs or guided setup. Credentials stay in connector custody, never model text. Domain trust, new scopes, role elevation, destructive changes and activation need exact human approval over the proposed diff; observed test-user sign-in, role change and revocation determine readiness. The agent chases missing decisions and preserves rollback plus failed/unverified steps.

**Acceptance.**
1. Ask the agent to onboard Slack and a generic SAML/SCIM SaaS, approve a scoped configuration diff, and run a real assigned employee through sign-in/provision/change/revoke.
2. Inject malicious vendor text, stale settings and withheld domain consent; prove no unauthorized change and a blocked readiness state with an actionable next step.

**Evidence.** `src/auth/agents/app-kinds.mjs`; `src/auth/agents/approval.mjs`; `tests/auth/agents-proposals.test.mjs`
**Gap.** Exact human-approved RER link proposals exist; native SaaS onboarding remains unbuilt. Model access and the held Slack app are available. BLOCKED: the required generic SAML and SCIM SaaS acceptance journey needs an authorized tenant and assigned employee that this run does not hold. Scoped vendor setup, real employee sign-in, provisioning, change and revocation, plus malicious metadata, stale settings and withheld domain-consent readiness proof remain unproved.

#### AUTH-AGENT-002 — Diagnose and repair broken sign-in

Core · push-further · **done**

**Requirement.** An agent correlates approved redacted protocol traces, metadata/key/certificate state, policy decisions, mail outcomes and deployment/configuration changes to explain why a named worker cannot use an app. It proposes the smallest justified repair, tests it with a scoped test identity and verifies sign-in plus logout. Changes to issuer, redirects, scopes, certificates, factors or policy require the responsible owner’s exact approval; it cannot turn off security controls, infer proof from logs or read raw secrets. Uncertain diagnosis stays uncertain with a next diagnostic action.

**Acceptance.**
1. Break a callback, expire a certificate and fail recovery mail on separate app journeys; ask the agent to diagnose with source citations, approve a repair and verify end-to-end behavior.
2. Deny approval and inject untrusted trace instructions, confirming no configuration or authority changes.

**Evidence.** `tests/auth/agents-proposals.test.mjs` — "sign-in diagnosis cites approved facts and exact repairs restore callback, expired certificate and recovery mail journeys through sign-in and logout": separate real protocol journeys, cited diagnoses, exact owner passkey approval, successful repair, scoped OIDC and signed SAML sign-in and logout, refused next requests, observed mail resend and retained recovery protection; "diagnostic consent, denied approval, untrusted instructions, unknown citations, uncertainty and stale targets cannot change configuration or authority": denied consent and approval, untrusted trace fields and model instructions, unknown citations, unavailable provider, uncertainty, stale state and state movement during diagnosis leave configuration and authority unchanged. `tests/integration/agents-browser.test.mjs` — "sign-in repair journey: owner snapshot consent, cited exact diff, passkey approval, employee callback and uncertainty at 1440 and 390": owner consent, cited diff, approved and uncertain end states, employee callback and sign-out, accessibility and icon tooltips at both widths. `docs/agent-diagnostics.md`; `scripts/diagnostic-probe.mjs`
**Gap.** No acceptance gap remains. Unsupported repair or probe profiles remain explicitly unverified; uncertain diagnoses have a next diagnostic action and cannot be approved.

#### AUTH-AGENT-003 — Find orphaned and excessive access

Core · push-further · **partial**

**Requirement.** An agent joins HR employment/source state, directory groups, app-side assignments, observed usage and review history to identify orphaned accounts, role drift, dormant privileges and risky recovery changes. Findings show provenance, freshness, exact people/apps affected and counterevidence; missing use data never proves no need. Policy owners approve least-privilege changes against a current-state diff; the agent verifies actual removal and that affected workers can still do their approved jobs, with an explicit rollback/exception route.

**Acceptance.**
1. Feed real approved connector data containing a departed worker’s remote account, an excessive role and an unused but required emergency grant.
2. Review the cited findings, approve only the first two, and verify downstream state plus the worker’s allowed tasks; stale data or changed employment invalidates the proposal.

**Evidence.** `src/auth/agents/preparer.mjs`; `src/auth/agents/approval.mjs`; `tests/auth/agents-proposals.test.mjs`
**Gap.** allow-listed inventory and human-approved suspension/domain proposals exist; cross-app usage analysis and regression verification do not.

#### AUTH-AGENT-004 — Person-bound delegated agent identities

Core · push-further · **done**

**Requirement.** People can consent to an OAuth/MCP or external-API task identity bound to accountable person, employer, agent, purpose, target resource/API, exact scopes, duration and expiry. A visible consent screen explains the concrete effects, required independent approvals and revocation reach; tokens are short-lived, target-bound and separately attributable, never reusable human sessions or preparer keys. New scopes/purpose/targets and privilege escalation require new explicit consent; employer/person/agent suspension, task completion or expiry ends authority. Untrusted app/document text cannot enlarge it.

**Acceptance.**
1. Authorize an agent to update one approved app assignment until a fixed deadline, invoke its target API/MCP tool and inspect attribution.
2. Deny another person, purpose, resource, target, scope, expired grant and replay/substitution; show and revoke the active grant in My account and prove its next request is refused.
3. **Current delegated-task profile (ct 22 Oct 00:20Z; conformance endorsed 22 Oct 04:52Z):** The native assignment profile requires owner registration of public keys and exact employee/app limits, fresh employee passkey consent, and a different legacy owner/admin's hardware/fresh-email passkey approval.
4. The employee, agent custodian and approver are distinct.
5. Immutable purpose, employer, person, agent, target API, resource, scope and deadline bind a single existing direct employee assignment change.
6. At most five-minute target-bound tokens also require one-use signed execution proof; live authority is rechecked at each door.
7. No arbitrary target, new assignment, administrator target, group change or document instruction is accepted.
8. My account revocation ends the next local request; completed changes are not undone and downstream sessions are not claimed revoked. Future task profiles inherit these consent, approval, audience, resource, proof and live-revocation obligations before shipping. **Native profile (ct 22 Oct 00:20Z):** The first native profile changes one existing direct app assignment through a DPoP-bound (RFC 9449), audience-restricted, one-use token valid for at most five minutes. The token names the person, the agent (RFC 8693 `act`) and the exact change (RFC 9396). It is issued only after the employee's passkey consent and approval by someone who holds that authority and is not the agent's custodian. Revoking in My account stops future use, says it does not undo a completed change, and offers a request to reverse it. The native profile remains restricted to its assignment target. AUTH-AGENT-006 ships a separate registered MCP/external-API POST profile, which inherits every obligation of this clause and its native profile: sender constraint, audience restriction, the five-minute one-use token, the `act` and exact `authorization_details`, passkey consent bound to the digest, a distinct employee, custodian and approver, a recheck at execution, attributed audit of every step and refusal, live endings, and My account revocation.

**Evidence.** `tests/auth/agents-proposals.test.mjs` — "a person-consented agent changes exactly one employer assignment after independent employer approval; substitutions, replay and every local ending deny its next request": real private-key OAuth and DPoP, one existing assignment and fixed deadline; concrete consent and independent passkey approval; agent/person/approver execution and refusal attribution through Activity; person/purpose/resource/target/scope/deadline substitutions, expiry and replay; human-cookie and publicly minted preparer-key refusal at token and execution doors with no token or assignment change; forged client/grant claims retain attempted identifiers without verified attribution; refused scope/resource requests exhaust a bounded per-agent proof budget, return 429 without verified attribution and recover after its window; My account inventory, revoke/next-request denial and reversal request; `tests/integration/agents-browser.test.mjs` — "agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes": consent, approval, My account and Activity at 1440/390; `docs/delegated-agents.md`
**Gap.** External and MCP profiles are separately registered under AUTH-AGENT-006; native assignment credentials retain their original target restrictions.

#### AUTH-AGENT-005 — Verify revocation everywhere

Core · push-further · **partial**

**Requirement.** On any human or agent grant ending, an agent inventories every issued derivative credential, session and provisioned role across the affected apps, sends only approved revocation operations and checks remote state or a safe denied-access probe. The UI distinguishes locally denied, provider-acknowledged, verified revoked, unsupported and unknown. Expiry/offboarding cannot be reported fully complete until every in-scope effect is verified or a named accountable owner accepts a documented exception under policy; unsupported vendor APIs produce an actionable manual/partner step, never fabricated success.

**Acceptance.**
1. Revoke a delegated grant and offboard its accountable worker while one SaaS is offline and another offers no session-revocation API.
2. Prove immediate Auth denial, enumerate all derivatives, resume verification after restart/provider recovery and retain the manual exception until a person resolves it; every final claim must match a remote read/probe.

**Evidence.** `src/auth/links/logout.mjs`; `src/auth/agents/keys.mjs`; `tests/auth/linking.test.mjs`; `tests/auth/agents-keys.test.mjs`
**Gap.** local key revocation and RER fences exist; app-wide delegated-credential inventory and verified remote reconciliation are missing.

#### AUTH-AGENT-006 — External and MCP delegated task identities

Core · push-further · **done**

**Requirement.** Remote MCP servers and external APIs are registered with Auth as resources, each with an audience, published scopes and `authorization_details` types. An agent calls one for a person only with a task identity issued for that resource under AUTH-AGENT-004. A resource that is not registered receives no token.

**Current profile:** Owner-registered HTTPS resources publish scopes, operations and an authorization-details type. One POST task binds an exact person, object and JSON arguments. The resource authenticates its own key and redeems the original agent DPoP proof at Auth before an effect; the live guarded transaction consumes the task once. No automatic outbound call or general MCP OAuth discovery is claimed. A release receipt records authorization with remote outcome unknown; My account revocation refuses the next call. Future resource profiles inherit these live-check, sender-binding, exact-task, independent-proof and no-false-completion obligations before shipping.

**Acceptance.**
1. Register a test MCP server and an external API.
2. Authorize one tool and one operation for one person.
3. At each resource, deny an unregistered audience, another tool or operation, scope, person, replay and an expired grant.
4. Revoke in My account and prove the next call is refused.

**Evidence.** `tests/auth/agents-proposals.test.mjs` — "registered MCP and external API resources execute one person-consented task; operation, person, scope, audience, replay, expiry and live revocation are enforced at each resource": both resource registrations, exact one-tool/operation/person consent and independent approval, audience/scope/person/operation/argument refusals, real HTTP resource handlers with one concurrent winner, replay/expiry, My account revoke/next-call denial, disabling and person erasure; `tests/integration/agents-browser.test.mjs` — "agents journey: mint a key, an agent files a suspension, a person approves with a passkey, the session ends and Activity records it, at desktop/mobile in both themes": MCP/API task review, approval, inventory, revocation and tooltips at 1440/390; `docs/delegated-agents.md`; `packages/delegated-resource/index.mjs`
**Gap.** None for the bounded registered POST profile. A resource must perform authenticated live one-use redemption before its exact effect; a release receipt leaves the remote outcome unknown.

## Agent surface

None.

## Later

None.

## Field proof register

No field proof is recorded yet.
