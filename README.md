# Auth

Auth is an owner-run identity provider for email-link and passkey sign-in. It includes a directory of people, sign-in methods, activity, recovery and a private-key-authenticated OpenID Connect authorization-code service. It is MIT licensed, declares `oidc-provider@1`, and never depends on that interface itself.

The host owns the issuer and passkeys: choose it before linking apps. Changing that host is a provider move requiring the apps' owners to approve re-linking. It does not silently preserve an issuer or passkey origin.

Privacy: Auth shares each person's email and name with the apps they use. Under RER Managed, RER can sign as the account's Auth install. Managed installation, adoption, default linking and platform sign-in are outside this implementation.

## Start locally

The source lives at [just-every/run-auth](https://github.com/just-every/run-auth).

```sh
git clone https://github.com/just-every/run-auth.git
cd run-auth
node scripts/rer.mjs install
node scripts/rer.mjs setup --owner-email you@example.com
node scripts/rer.mjs dev
```

Fresh setup chooses `localhost`, which supports browser passkeys. Explicit hosts and saved issuers are preserved. An existing IP issuer needs an explicit host move before passkey enrollment; setup never rewrites it silently. Maintained runtimes are Node 22.20.0 and pnpm 10.12.4.

`rer setup` claims the first owner through Base, applies D1 migrations, publishes the initial signing key and stops its temporary runtime. Open the credential-bearing `RER_OPEN` URL from `rer dev` only on this computer. It establishes a genuine, key-gated Auth development session as that owner. A dev session has no administrator rights without passkey proof.

For first enrollment, open `/signin`, request an email link and open the link from the gated local outbox in that same browser. Complete `/setup`, open Sign-in methods, then register a passkey. Subsequent administrator sign-in requires the passkey. Email sessions on an account with a passkey cannot administer Auth or enroll another passkey. The local outbox sends no external mail. Setup does not issue a sign-in link bound to a CLI process.

## Implemented and pending

The independent slice includes browser-bound email proof, WebAuthn, recovery, people invitations/domain admission/suspension, account and activity pages, encrypted ES256 signing keys, and authorization code with PKCE, state, nonce and `private_key_jwt`. Google, Microsoft and Okta can be configured through the private optional `AUTH_UPSTREAM_PROVIDERS` JSON setting; no live upstream account is configured here. In People or Sign-in methods, a passkey-authenticated owner or administrator can require one configured provider for an exact email domain. This is separate from allowing new accounts at a domain. The owner is exempt; everyone else must prove that provider before email, passkey or recovery can continue.

Auth is an `oidc-provider@1` link provider: the Apps page approves and removes apps, and link tokens let `rer setup --non-interactive` link one app. Agents can propose links too. Auth keeps the interface versions apps report. Sign out everywhere, suspension fences and RP-initiated logout reach linked apps. `rer export` carries a signed grant map, and `rer import` restores it into a fresh install. [LINKING.md](LINKING.md) describes all of it. No OpenID certification or hosted deployment acceptance is claimed.

## Moving people in

People, **Move people in** stages a user list exported from Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud, shows what needs a decision, admits chosen rows as ordinary invitations and can undo the batch. Nothing but email, name, disabled state and the provider's id moves: no passwords, factors, roles, groups, sessions or apps. Staged rows that were never admitted would be left out of Auth's export when that arrives; today `rer export` still refuses. Read [MOVE-IN.md](MOVE-IN.md) before using it, including who should keep their current provider.

See [Auth commands](AUTH-COMMANDS.md) for browser sign-in, recovery, private settings and the exceptions to the copied [Base command contract](SEED-COMMAND-CONTRACT.md). [Acceptance](ACCEPTANCE.md) names the real checks and remaining dependencies.
