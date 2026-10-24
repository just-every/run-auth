# Host Auth

Auth sends sign-in links through a configured mail provider. For an Assisted installation, select Resend, SendGrid or Cloudflare Email Sending and provide a verified sender address and the provider API key. Cloudflare also needs the account ID. These inputs are in `rer-setup.json`; the API key is private and required for the selected provider. RER Managed assigns the `rer` provider, sender, relay URL and private installation credential.

For an owner-operated deployment, edit `MAIL_PROVIDER`, `MAIL_FROM`, `MAIL_RELAY_URL` and, for Cloudflare, `MAIL_ACCOUNT_ID` in `deploy.json`, then commit the declaration before deploying. `MAIL_FROM` must be a sender your provider permits. A direct provider leaves the relay URL empty. The `rer` provider requires the assigned HTTPS relay URL and installation credential; it never uses a direct provider key as a substitute.

Supply the owner email through setup. Set the required private deployment inputs `SESSION_SECRET`, `SETUP_TOKEN`, `AUTH_ENCRYPTION_KEY` and `MAIL_API_KEY` in the deployment environment. Never commit their values. Keep the chosen issuer host before enrolling passkeys or linking apps. Follow [backup and restore](docs/backup-and-restore.md) before any move; installation export and restore refuse active isolated employers.

The committed `packaging.json`, `rer-project.json` and `management/integration/deployment-spec.json` declare hosted installation. Build with `pnpm run build`, regenerate with `pnpm delivery:spec`, and require `pnpm check:deployment-spec` before packaging. The Managed workflow is dispatch only. These declarations prepare installation; they do not establish a published listing or hosted acceptance.
