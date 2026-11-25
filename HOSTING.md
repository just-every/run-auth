# Host Auth

Auth sends sign-in links through a configured mail provider. For an Assisted installation, select Resend, SendGrid or Cloudflare Email Sending and provide a verified sender address and the provider API key. Cloudflare also needs the account ID. These inputs are in `rer-setup.json`; the API key is private and required for the selected provider. RER Managed assigns the `rer` provider, sender, relay URL and private installation credential.

For an owner-operated deployment with mail, set `MAIL_PROVIDER`, `MAIL_FROM`, `MAIL_API_KEY` and any provider-specific inputs in the environment or a private `--env-file`. `MAIL_FROM` must be a sender your provider permits. Cloudflare also needs `MAIL_ACCOUNT_ID`. The `rer` provider requires its assigned HTTPS `MAIL_RELAY_URL` and installation credential.

To set up a Business before it has mail, set `MAIL_PROVIDER=none` when running `rer deploy`. Omit the sender and mail credentials. Run `rer signin` from the checkout with the deployment's Cloudflare credentials to open a one-time link to the installation owner's setup status. Outbound mail is disabled. Auth account sign-in, passkey enrollment and identity administration still require the usual Auth proofs and a configured mail provider.

Supply the owner email through setup. Set the private deployment inputs `SESSION_SECRET`, `SETUP_TOKEN` and `AUTH_ENCRYPTION_KEY` in the deployment environment. Never commit their values. Keep the chosen issuer host before enrolling passkeys or linking apps. Follow [backup and restore](docs/backup-and-restore.md) before any move; installation export and restore refuse active isolated employers.

The committed `packaging.json`, `rer-project.json` and `management/integration/deployment-spec.json` declare hosted installation. Build with `pnpm run build`, regenerate with `pnpm delivery:spec`, and require `pnpm check:deployment-spec` before packaging. The Managed workflow is dispatch only. These declarations prepare installation; they do not establish a published listing or hosted acceptance.
