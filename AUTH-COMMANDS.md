# Auth commands

This edition guide describes Auth's behavior where the copied Base command documentation describes a generic seed. The copied Base source remains unchanged.

Auth's host owns its issuer and passkeys. Choose it before linking; changing it is a provider move requiring the apps' owners to approve re-linking. Fresh local setup defaults to `localhost`; an explicit host or saved issuer is retained. Existing IP issuers require an explicit move before browser passkeys can be enrolled. The saved port is reused, otherwise 8787. An explicitly busy port fails.

Privacy: Auth shares email and name with apps each person uses. Under RER Managed, RER can sign link approvals for the account's Auth install; it receives people's data only as an ordinary linked app (README.md, RER trust).

Start from nothing with `npx -y @runeditrun/rer dev just-every/run-auth` (set up only: `npx -y @runeditrun/rer setup just-every/run-auth`; without Node: `curl -fsSL https://runeditrun.com/install.sh | sh -s -- dev just-every/run-auth`). The commands below run from the checkout it creates:

```sh
rer setup --owner-email you@example.com
rer dev
rer dev --stop
rer preview
rer preview --stop
rer check --profile first-party
rer verify
```

Setup validates `rer-setup.json`, generates private settings, builds the Worker, migrates D1, claims the owner and publishes the initial public signing key. The key must age through the advertised JWKS cache lifetime before authorization can use it. Repeated setup preserves the saved owner and secrets. Setup does not mail a CLI-bound sign-in link.

`dev` runs Vite with real D1 data and prints `RER_OPEN`, which carries the checkout key. Open it only on this computer. The browser becomes the real development owner and can finish `/setup`; passkey administration remains unavailable until the owner proves email and enrolls/signs in with a passkey. `dev --login` disables dev identity. The inherited CLI points to the gated outbox; its Auth link opens `/signin`. Request a link there, then open its outbox message in that same browser. `preview` serves the production build and also requires ordinary Auth sign-in.

First passkey enrollment begins with an Auth email-link session. An account with an existing passkey must use that passkey to enroll another. Email proof expires after 30 days; a passkey sign-in attempt then requests a new bound-browser email proof. Optional upstream sign-in still requires Auth email proof before first passkey enrollment and does not grant passkey administration.

Private local settings are mode-0600 `.dev.vars`; D1 lives in `.wrangler/state`. `AUTH_ENCRYPTION_KEY` is the generated wrapping secret. `AUTH_UPSTREAM_PROVIDERS` is an optional private JSON array of Base IdentityProviderConfig objects, restricted to Google, Microsoft and Okta. Each includes its id, preset and clientId, with the provider's issuer/tenant and private client authentication material. Microsoft and Okta require explicit subjectEmails mappings. Only safe visible provider labels and sign-in paths reach HTML. No live upstream credentials are included.

```sh
pnpm recovery --local
```

Recovery invokes local wrangler D1, invalidates unused prior token digests and installs a new digest. The raw token is saved to `.rer/local/recovery-token` with mode 0600; the command prints only that path. An authenticated owner redeems it through `POST /api/auth/recovery/token` with a same-origin JSON body containing `token`. The normal delayed recovery controls are on My account. This seed script (`scripts/auth-recovery.mjs`, not a `rer` verb) accepts no arguments or `--local`; it does not inherit the generic verb flags or perform a remote operation.

`export` first writes a signed grant map, then exports Auth's data by policy: people, emails, passkey public keys, clients, grants, subjects and history, with no sessions, keys or pairwise key. `import` restores into an empty checkout and refuses app origins that checkout cannot serve and active dev personas. See LINKING.md. `reset --yes` destructively removes the declared local installation state and private settings; export first to keep it.

`build`, `doctor`, `describe`, `check`, `outbox`, `deploy` and `release` remain on the shared dispatcher. Deploying a hosted issuer, upstream account registration and public release are separate owner operations. Local tests do not establish hosted acceptance or OpenID certification.

`rer deploy --demo --dry-run` uses `deploy-demo.json` to build the native throwaway demo plan for `demo.run-auth.com` under `.rer/demo-host`, without provider requests or deployment credentials. It does not deploy a hosted issuer. For an owner-account production deployment, replace the placeholder `MAIL_FROM` in `deploy.json` with a verified sender and supply the required private settings. `OWNER_EMAIL` is a deployment secret, never a Wrangler plain variable or public packaging input.

Required providers: People and Sign-in methods let passkey-authenticated owners and administrators set, change or remove an exact-domain provider rule. This uses the private configured provider ID; enrollment permission remains separate. Rules immediately apply to existing sessions and pending sign-in actions. If the provider is missing, access stays closed until the owner changes or removes the rule. The owner is exempt. After matching upstream sign-in, use Confirm my email for Auth email proof and then register or authenticate a passkey in that browser.
