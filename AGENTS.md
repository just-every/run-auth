# Work on Auth

Auth is an owner-run MIT identity provider, declaring `oidc-provider@1` and never depending on that interface itself. Its host owns the issuer and passkeys: choose it before linking. Changing that host is a provider move requiring the apps' owners to approve re-linking, not an automatic identity migration.

Privacy: Auth shares each person's email and name with the apps they use. Under RER Managed, RER can sign link approvals for the account's Auth install; it receives people's data only as an ordinary linked app (README.md, RER trust).

The foundation is Base main `4336124fe52f0d11a9d27093bcf852ae36fd3a90`, including its operator authentication, the local-listener protections and the dependency link protocol (refreshed 13 Oct 2026; Base schema added since the original composition is migrations 0018 to 0023, and 0001_owner.sql stays as applied). Preserve copied source ownership in composition.lock.json: src/modules, src/base and scripts/base-cli/base-onboarding are maintained Base copies. The lock records the original composition, including the family authoring commit at editions/auth. Subsequent edition changes belong to this runnable repository; that original lock does not attest their current bytes. Edition-owned protocol is src/auth, UI is src/ui and public/auth-assets, and the runtime/CLI adapters connect them. The copied Base command documents describe generic behavior; AUTH-COMMANDS.md records Auth's exceptions.

Keep secrets server-only. Every private HTTP handler must authorize its own request. Base bootstrap/session cookies confer no Auth administration or enrollment privilege. The seed wrapper denies Base operator management paths; do not reopen them. First enrollment needs Auth email proof and additional enrollment/administration needs passkey proof; every enrollment, recovery approval/completion and administration write also needs the session's local email confirmation within ten minutes, rechecked inside the write (src/auth/local-email.mjs `authority`). The local-only src/server.dev.ts bridge turns Base's actual gated dev identity into an Auth dev session; production must never load it or admit dev tokens.

Use `rer install`, `setup --owner-email EMAIL`, then `dev`. Fresh setup chooses localhost for browser passkeys and preserves explicit or saved issuer choices. Start ordinary sign-in at `/signin`, request the email link there, and confirm it in that browser through the key-gated local outbox. Setup does not present a CLI-bound email link. The outbox sends no external mail. A saved IP issuer must be explicitly moved before passkey enrollment.

Private settings live in mode-0600 `.dev.vars`; durable local data lives in `.wrangler/state`. AUTH_ENCRYPTION_KEY is generated locally and must never be printed or committed. Optional AUTH_UPSTREAM_PROVIDERS is private JSON configuration for Google/Microsoft/Okta only. `pnpm recovery --local` writes a digest through wrangler and a mode-0600 raw token file, printing only its path.

Auth is a link provider (LINKING.md, src/auth/links): provider documents, initiate/redeem/deregister/report, Apps page approval and removal, link tokens, versions, sign-out everywhere, fences and end-session. `rer export`/`import` use Base portability with Auth's policy (scripts/installer/transfer.mjs) and a signed grant map. Never weaken continuity (a new key alone never keeps a client), the exact origin and callback binding, or the one-winner code consumption. Preserve existing migrations.

Stop dev/preview before building or verifying. `pnpm typecheck` uses `.cache/typecheck.tsbuildinfo`; `rer build` builds the real Worker and refuses the dev layer in its output. `rer verify` runs the build, typecheck, emitted runtime/email proof, protocol/security/upstream/recovery tests and Chromium integration journeys. Browser tests use real D1/outbox and native WebAuthn with CDP hardware emulation; upstream and external mail may be faked only at their network edges. Read ACCEPTANCE.md before making acceptance claims; no OpenID certification or hosted acceptance is established here.

Keep actual scheduled handlers and named Worker exports in src/server.ts. Preserve the private-listener controls, Vite allow/deny lists and the setup production-runtime target. Never serve .rer, .seed, export archives or Local Explorer from public listeners. Keep RER_SERVER_JOURNEY=1 on test journeys that start managed servers and stop every process started by tests.

## Prepare administration with a preparer key

An agent may prepare Auth administration; a person decides. An administrator mints a **preparer key** on Agents (`/app/agents`) with passkey proof and a fresh email confirmation. The key is shown once, stored only as a digest, expires 30 days after minting or renewal, and stops at once when revoked and ends for good when its accountable administrator is demoted, suspended or removed; promoting or restoring them again does not bring it back, so mint a new key. Proposals an ended key filed stay on Agents for a person to approve or reject. Never print, log or commit it; pass it to your process through the environment.

1. **Inventory.** `GET /api/auth/preparer` with `Authorization: Preparer <key>` returns people (state, last sign-in, passkey present, suspended), invitations, allowed domains, required-provider rules, configured provider ids, apps, and this key's own proposals with their status.
2. **File.** `POST /api/auth/preparer` with JSON `{"kind","target","reason"}` (`name` for an invitation, `providerId` for a rule). Kinds: `suspend_person`, `restore_person`, `invite_person`, `remove_invitation`, `add_domain_rule`, `remove_domain_rule`. The reason is one line. Auth stores who and which apps are affected and a digest of the target's state, and returns that effect; nothing else changes. `approve_app_link` (target: the app's origin; Auth reads the app when filing and again after approval) and `remove_app_link` (target: the client id or origin) are proposal kinds too.
3. **Wait for a person.** Tell your human what you filed and why. A person approves on Agents with their passkey, or rejects it. Poll the inventory for the proposal's `status` (`pending`, `done`, `rejected`, `failed` or `expired`; `outcome.reason` says why). Proposals expire after 24 hours; filing is rate limited per key.

`scripts/preparer-example.mjs` is this sequence as a script. A preparer key cannot approve, mint, renew or revoke keys, read sessions, passkeys, keys or tokens, open any page, sign in, change settings, or reach the OIDC endpoints; it is not an access token and nothing else accepts it. A person's session cookie is not a preparer key. Approval re-checks the approver's authority and the target's state when it runs, runs once, and records the key, the approver and the result in Activity. Whether Auth should ever issue delegated tokens to agents is a separate protocol decision (AUTH-PROTOCOL-001 stays as it is).


## Lander-Regenerate

CONTRACT.md is the only source for acceptance, status and homepage claims. After any contract edit, regenerate all outputs, run the shared check, then relock and check sources. The legacy scripts/contract-docs.mjs entry point delegates to the same shared generator.

Lander-Regenerate: node src/base/contract-docs.mjs write
Lander-Regenerate: node scripts/edition-authoring/cli.mjs lock

Run `node src/base/contract-docs.mjs check` and `pnpm check:sources` before publishing.
