# Foundation operations

Run all first-party operations from the composed, runnable edition checkout
with the shared RER command path. The detailed flags and effects are in
`RUN-LOCALLY.md` and `SEED-COMMAND-CONTRACT.md`.

```sh
node scripts/rer.mjs install
node scripts/rer.mjs setup --owner-email you@example.com
node scripts/rer.mjs dev
```

Use the setup prompt instead of the owner-email flag when entering the real
mailbox. Follow the newest ordinary sign-in message in the printed local
outbox; no external email is sent. Stop `dev` with
`node scripts/rer.mjs dev --stop` or Ctrl-C, and stop `preview` with
`node scripts/rer.mjs preview --stop` before build or verification.

```sh
node scripts/rer.mjs verify
node scripts/rer.mjs reset --yes
node scripts/rer.mjs export --output exports/installation.rer
node scripts/rer.mjs import --input exports/installation.rer --yes
node scripts/rer.mjs deploy
node scripts/rer.mjs describe
```

Use `node scripts/rer.mjs describe` to inspect the checkout's actual
capabilities. `node scripts/rer.mjs check --profile first-party` validates the
declared command contract; it does not run application journeys or contact a
provider.

## Local data and recovery

Setup and development use explicit owner identity and real local migrations.
Dev and preview use the same owner and canonical `.wrangler/state`; the local
development outbox is available only on loopback. Any process with access to
the machine can read that outbox and sign in as the owner. Private settings are
kept in `.dev.vars` with mode 0600 and are not copied into build output.

Local export creates a private archive with an integrity receipt and explicit
exclusions. The foundation has no product-domain tables or background jobs; an
edition's archive contains the supported domain tables and resources that its
adapter declares. Owner/auth, outbox, bookkeeping, private settings and
transient runtime state are excluded. Import validates and restores atomically
into an empty destination; confirmed reset preserves export archives. Run setup
after restore to establish a fresh owner. Each first-party seed verifies local
export/import/export equivalence across its supported resources. Remote transfer
is available only when the adapter declares complete resource coverage.

Preserve ambiguous state and applied migration history. Never place a remote
credential, owner secret or local resource ID in source. A schema change needs
a forward migration and verified transition/recovery.

## Deployment

`node scripts/rer.mjs deploy --dry-run` validates the real owner-account
deployment declaration and builds locally without provider requests. Real
deployment requires privately supplied `CLOUDFLARE_ACCOUNT_ID` and
`CLOUDFLARE_API_TOKEN`, the declared owner/session/setup secrets, and a real
verified mail sender in `deploy.json`. Follow the owner-account deploy-kit
instructions under `scripts/base-cli/modules/deploy-kit`; account scope,
resource ownership, migrations, receipt and health checks are defined there.
Local validation does not prove hosted acceptance, provider delivery or remote
health.

## Owning an Auth install

What the owner of an Auth install carries, stated as it is today. Auth has no
hosted acceptance, OpenID certification or safe transfer yet (see
ACCEPTANCE.md); this note does not change that.

### Who patches

The owner does, usually through the owner's agent, by merging upstream into the
install's own checkout and redeploying. Nobody else patches a self-run install.

```sh
git remote add upstream https://github.com/just-every/run-auth.git  # once
git fetch upstream
git merge upstream/main          # resolve conflicts; never edit applied migrations
node scripts/rer.mjs install
node scripts/rer.mjs check --profile first-party
node scripts/rer.mjs verify
node scripts/rer.mjs deploy --dry-run
node scripts/rer.mjs deploy      # applies new D1 migrations, then the Worker
```

Read the merged CONTRACT.md and ACCEPTANCE.md changes before deploying, and
keep the previous commit to redeploy if the new one misbehaves (migrations are
forward-only, so a rollback keeps the newer schema).

### Where the keys and secrets live

- `AUTH_ENCRYPTION_KEY`: locally in mode-0600 `.dev.vars`; hosted, a Worker
  secret declared in `deploy.json`. Keep a copy in the owner's password manager:
  without it the signing keys cannot be used.
- Signing keys: D1 table `auth_signing_keys`. The public JWK is published; the
  private half is AES-GCM encrypted under `AUTH_ENCRYPTION_KEY`.
- Upstream provider secrets: only in `AUTH_UPSTREAM_PROVIDERS` (private
  settings), never in D1.
- Pairwise subject key: D1 `auth_settings` (`pairwise_key`), stored plainly.
- Preparer keys and the local recovery token: only SHA-256 digests in D1
  (`auth_agent_keys`, `auth_recovery_tokens`). The raw recovery token is in
  mode-0600 `.rer/local/recovery-token`.

### Backups and what they exclude

`rer export` writes a portable archive of a stopped local install (LINKING.md:
it carries a signed grant map and omits sessions, keys and the pairwise key), and
`rer import` restores it into an empty checkout. Hosted installs have no
export route yet. Cloudflare D1 Time Travel restores
the live database in place within the account and holds everything, including
session digests and encrypted keys. Any copy taken out of the account must
leave out sessions, private keys and secrets: export only the directory and
history tables, for example

```sh
npx wrangler d1 export DB --remote --output auth-directory.sql \
  --table oa_operators --table oa_invitation_cancellations --table oa_domain_rules \
  --table auth_domains --table oa_identity_providers --table oa_external_identities \
  --table auth_emails --table auth_passkeys --table auth_clients --table auth_grants \
  --table auth_subjects --table auth_activity --table auth_activity_details \
  --table auth_import_batches --table auth_import_rows --table auth_former_subjects
```

That leaves out sessions and one-time state (`auth_sessions`, `oa_sessions`,
`auth_challenges`, `auth_codes`, `auth_assertions`, `auth_notices`,
`auth_recoveries`, `auth_upstream_proofs`, `oa_tokens`,
`oa_step_up_challenges`, `oa_oidc_transactions`, limits), private keys and key
digests (`auth_signing_keys`, `auth_settings`, `auth_recovery_tokens`,
`auth_agent_keys`, with the proposals that reference them, `oa_dev_credentials`),
the development outbox, which holds sign-in links, and Base's portability
bookkeeping; Activity keeps each proposal's outcome. Passkey public keys are
kept so people keep their passkeys. This copy is a record for safekeeping; a
restore from it has not been rehearsed and is not a supported path.

### Recovery rehearsal

Run it on a local checkout (`node scripts/rer.mjs setup --owner-email ...`,
then `node scripts/rer.mjs dev`), never on the live install.

1. Sign in at `/signin` through the local outbox and register a passkey on
   Sign-in methods. It shows "Passkey 1", and People opens.
2. Lose the passkey: open a private window and sign in by email again. My
   account shows "Administrator access is paused"; People answers 403.
3. Run `node scripts/rer.mjs recovery --local`. It prints only the path of
   `.rer/local/recovery-token` (mode 0600), never the token.
4. In the private window, choose Confirm my email on Sign-in methods and open
   the link, then in its developer console run
   `fetch('/api/auth/recovery/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:'<token>'})})`.
   It answers `{"ok":true}`; Activity shows Emergency Recovery; the old passkey
   is gone and the first window's session has ended.
5. Register a new passkey there. People opens again.
6. With a second administrator, rehearse the ordinary route: request passkey
   recovery on My account; the other administrator approves it (or it becomes
   available after 72 hours), and the requester completes it on My account.

### Key rotation

- Signing keys (owner, passkey session with an email confirmation in the last
  ten minutes, from the signed-in browser's console):
  `POST /api/auth/keys/stage` with `{"alg":"ES256"}` (or `RS256`) publishes a
  new key that signs after five minutes, the JWKS cache lifetime. Then
  `POST /api/auth/keys/retire` with the old `{"kid":"..."}`; it stays published
  for the five-minute token lifetime and is then removed. Retiring the only
  active key of an algorithm is refused.
- `AUTH_ENCRYPTION_KEY`: Auth has no command to re-wrap the signing keys, so do
  not change it on a live install; signing stops if it changes. Rotating it
  needs a re-wrap step that does not exist yet.
- Preparer keys: renew or revoke on Agents. Each expires 30 days after minting
  or renewal, and revocation applies to the agent's next request. A key also ends for
  good when its owner is demoted, suspended or removed (any change of the owner's
  role or status, including a recovery completion, counts); promoting or restoring
  the owner does not revive it, Agents lists it as Ended with the reason, and a
  person still decides the proposals it filed. Mint a new key instead.

### Reuse comparison

From the projects' public repository and licence pages read on 11 October 2026.
This is a comparison
from public pages, not legal clearance for any reuse plan.

| Project | Licence (read 11 Oct 2026) | What it covers beyond Auth |
|---|---|---|
| authentik | MIT core, separate enterprise terms | LDAP and RADIUS flows, and wider enterprise federation, for existing apps |
| Keycloak | Apache-2.0 | Broad self-hosted federation and administration |
| Ory Kratos | Apache-2.0 | Headless registration, verification and recovery; not by itself an OIDC server |
| ZITADEL | AGPL-3.0 from v3 (Apache-2.0 before), commercial licence available | Mature multi-tenant identity platform |
| Better Auth | MIT | TypeScript authentication framework, not a workforce directory |

Auth stays native and small because its job is narrow: one owner's people,
passkeys, email proof, and sign-in and provisioning for that owner's RER apps and
company apps over OpenID Connect, SAML and SCIM (see COMPANY-APPS.md), deployed by
`rer` on the owner's own Cloudflare account and changed by the owner's agents
in a codebase they can read whole. Wrapping a large product would not give that
small seed, and its upgrades and incidents would become the owner's to carry. A
business that needs device trust, conditional access or a full workforce
directory should choose a larger product, such as one of the above or a
commercial directory, instead of waiting for Auth to grow into one. For SAML,
OpenID Connect and SCIM, see COMPANY-APPS.md.
