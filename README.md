# Auth

Auth is an owner-run identity provider for email-link and passkey sign-in. It includes a directory of people, sign-in methods, activity, recovery and a private-key-authenticated OpenID Connect authorization-code service. It is MIT licensed, declares `oidc-provider@1`, and never depends on that interface itself.

The host owns the issuer and passkeys: choose it before linking apps. Changing that host is a provider move requiring the apps' owners to approve re-linking. It does not silently preserve an issuer or passkey origin.

Privacy: Auth shares each person's email and name with the apps they use. Under RER Managed, RER can sign link approvals for the account's Auth install: Auth then links the account's newly admitted apps without anyone typing, marks each one RER-made and tells its administrators. RER never receives people's data from Auth except as an ordinary linked app, for the people who sign in to RER through it.

RER trust: an Auth install RER provisioned carries RER's per-account public key in its `RER_LINK_APPROVAL_KEYS` setting and its first owner is claimed through RER's signed owner claim (`/auth/owner-claim`). An owner who runs Auth themselves can adopt it into Managed by adding RER's key on **Sign-in methods** (passkey plus a fresh email proof in this browser). Withdraw it there at any time: the key ends for good, later approvals signed with it are refused, and links already made stay until you remove them on **Apps**. Leaving Managed withdraws it too. An install that trusts no RER key never contacts RER.

## Run Auth

Sign in with a touch: passkeys and email links for your team, and one sign-in across the apps you link. Visit [run-auth.com](https://run-auth.com) for Auth and [run-auth.com/run](https://run-auth.com/run) for the two steps; the guides are at [run-auth.com/docs](https://run-auth.com/docs) and in [docs/](docs/).

```sh
npx -y @runeditrun/rer dev just-every/run-auth
```

That one line clones Auth, installs everything, makes you the owner and prints a link that opens Auth signed in. It needs Node 22 or later; without Node, `curl -fsSL https://runeditrun.com/install.sh | sh -s -- dev just-every/run-auth` brings its own. To set it up without starting it, use `npx -y @runeditrun/rer setup just-every/run-auth`. To start it again later, run `cd run-auth && rer dev`. Runs on macOS, Linux or Windows with WSL2, with git; rer brings pnpm.

## Start locally with your own owner email

The source lives at [just-every/run-auth](https://github.com/just-every/run-auth). The checkout carries its own copy of rer, so after one command to fetch it, the steps run from the checkout without installing rer:

```sh
npx -y @runeditrun/rer install just-every/run-auth
cd run-auth
rer setup --owner-email you@example.com
rer dev
```

Fresh setup chooses `localhost`, which supports browser passkeys. Explicit hosts and saved issuers are preserved. An existing IP issuer needs an explicit host move before passkey enrollment; setup never rewrites it silently. Maintained runtimes are Node 22.20.0 and pnpm 10.12.4.

`rer setup` claims the first owner through Base, applies D1 migrations, publishes the initial signing key and stops its temporary runtime. Open the credential-bearing `RER_OPEN` URL from `rer dev` only on this computer. It establishes a genuine, key-gated Auth development session as that owner. A dev session has no administrator rights without passkey proof.

For first enrollment, open `/signin`, request an email link and open the link from the gated local outbox in that same browser. Complete `/setup`, open Sign-in methods, then register a passkey. Subsequent administrator sign-in requires the passkey. Email sessions on an account with a passkey cannot administer Auth or enroll another passkey. The local outbox sends no external mail. Setup does not issue a sign-in link bound to a CLI process.

## Implemented and pending

The independent slice includes browser-bound email proof, WebAuthn, recovery, people invitations/domain admission/suspension, account and activity pages, encrypted ES256 signing keys, and authorization code with PKCE, state, nonce and `private_key_jwt`. Google, Microsoft and Okta can be configured through the private optional `AUTH_UPSTREAM_PROVIDERS` JSON setting; no live upstream account is configured here. In People or Sign-in methods, a passkey-authenticated owner or administrator can require one configured provider for an exact email domain. This is separate from allowing new accounts at a domain. The owner is exempt; everyone else must prove that provider before email, passkey or recovery can continue.

Auth is an `oidc-provider@1` link provider: the Apps page approves and removes apps, and link tokens let `rer setup --non-interactive` link one app. Agents can propose links too. Auth keeps the interface versions apps report. Sign out everywhere, suspension fences and RP-initiated logout reach linked apps. `rer export` carries a signed grant map, and `rer import` restores it into a fresh install. [LINKING.md](LINKING.md) describes all of it. No OpenID certification or hosted deployment acceptance is claimed.

## Moving people in

People, **Move people in** stages a user list exported from Google Workspace, Microsoft Entra, Auth0, Okta or JumpCloud, shows what needs a decision, admits chosen rows as ordinary invitations and can undo the batch. Nothing but email, name, disabled state and the provider's id moves: no passwords, factors, roles, groups, sessions or apps. `rer export` leaves out staged rows that were never admitted. Read [MOVE-IN.md](MOVE-IN.md) before using it, including who should keep their current provider.

See [Auth commands](AUTH-COMMANDS.md) for browser sign-in, recovery, private settings and the exceptions to the copied [Base command contract](SEED-COMMAND-CONTRACT.md). [Acceptance](ACCEPTANCE.md) names the real checks and remaining dependencies.

Hosted mail and deployment inputs are documented in [Host Auth](HOSTING.md).
