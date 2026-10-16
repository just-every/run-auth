# Company apps: SAML, OpenID Connect and SCIM

Administrators connect the company's SaaS and internal apps on **Apps** (`/app/apps`). Every write there needs a passkey administrator with a fresh email confirmation, like all Auth administration; publishing a new SAML signing certificate is the owner's. Access is decided by **assignment**: a person, or a group they belong to, assigned to the app, while the person is active. Unassigned people get no assertion, code or token, and removing an assignment ends access at the next sign-in. Apps added for RER linking (LINKING.md) are separate and keep their strict profile.

## SAML 2.0 identity provider

| | |
| --- | --- |
| Entity ID and metadata | `https://<issuer host>/saml/metadata` |
| Single sign-on | `/saml/sso` (HTTP-Redirect and HTTP-POST) |
| Single logout | `/saml/slo` (HTTP-Redirect and HTTP-POST) |
| IdP-initiated launch | `/saml/launch/<app id>`, only for apps that allow it |
| Sign out of Auth and every SAML app | `/saml/logout` |

Add an app from its service-provider metadata (pasted) or from its entity ID and assertion consumer URL. Per app: NameID format (`persistent`, `emailAddress`, `unspecified`, `transient`; persistent is a stable identifier for that app alone), what is signed (response, assertion or both) with RSA-SHA256 or RSA-SHA512, optional assertion encryption (AES-256-GCM or AES-128-CBC, RSA-OAEP key transport) to the app's encryption certificate, attributes mapped from email, name, first and last name, person ID, app role or groups, and whether people may open it from Auth. RSA-SHA1 is accepted only as a named exception on an app.

Auth checks each request: the issuer is a configured app, the signature (required when the app signs requests, always for logout messages), the destination, a five-minute clock window, that the request ID was not used before, and that the consumer address is one the app registered. A failure before the consumer address is trusted shows a page in Auth and sends nothing to the app. Single logout ends the Auth session first, then visits every other app the session signed in to, then answers the app that asked.

Certificates roll over with overlap: **Publish a new certificate** adds it to the metadata without signing; once apps trust it, **Start signing with it**; the previous certificate stays published until **Stop publishing**.

## OpenID Connect apps (general profile)

Register an app with its redirect URIs and client authentication: `client_secret_basic`, `client_secret_post`, `private_key_jwt` (its public JWKS) or `none` for a public native or browser app, which must use PKCE (S256); any app can be made to require PKCE. Redirect URIs match exactly; a native app may use a private-use scheme (`com.example.app:/callback`). A client secret has 256 random bits, is shown once and stored only as a digest; **Make a new secret** keeps the previous one working for the overlap you choose (up to seven days).

- **Consent:** an administrator's assignment is the employer's consent; people are not asked again. Scopes: `openid` with `email`, `profile` (name and the app's mapped claims) and `groups`.
- **Session:** a code lasts 60 seconds and is redeemed once. ID tokens and access tokens last at most five minutes and never outlive the Auth session; no refresh tokens are issued. Subjects are pairwise per app unless the app is set to the public subject (the person ID).
- **UserInfo** (`/oidc/userinfo`) answers only while the session, the person and the assignment all hold.
- **Logout:** RP-initiated logout at `/oidc/logout` (with `id_token_hint` and a registered `post_logout_redirect_uri`) ends the Auth session, loads each signed-in app's front-channel logout URI with `iss` and `sid`, and posts a signed `logout+jwt` to each back-channel logout URI, retried for up to 24 hours.
- **Keys:** ID tokens are RS256 by default (ES256 per app), signed with keys published in `/oidc/jwks` before use and retained until issued tokens expire.
- The implicit and hybrid flows are available only to an app registered with them allowed, for legacy software that needs them.

## SCIM 2.0 provisioning

Connect an app's SCIM base URL and bearer token (sealed in Auth, never shown again; replace it with **Replace token**). Auth then creates, updates (name, email, app role), deactivates or deletes, and reactivates accounts as assignments, group membership and people change, and pushes assigned groups if asked. Each change is sent when it happens and read back; the app's page shows every obligation with its event, sent and verified times, and flags anything unverified after 15 minutes. Auth adopts only accounts carrying its own external ID: an existing account with the same user name is held until an administrator binds it. Rate limits (429 with Retry-After) and outages are retried; **Reconcile now** (and a daily run) reads every page of remote users and repairs drift. **Preview changes** lists what a sync would do, marking deactivations and deletions.

## Catalog

Google Workspace, Microsoft 365, Slack, GitHub Enterprise Cloud, AWS IAM Identity Center, Salesforce and Zoom recipes fill an app's SAML settings and, where the vendor offers SCIM, its connector. Each recipe states the edition and permissions it needs, how to test with one person, how to roll certificates and what sessions survive. None is marked verified until it has been run against an authorized test tenant.

## Lifecycle events

**Event subscriptions** send each lifecycle event to an HTTPS endpoint as it happens: people invited, activated, suspended, restored or given a new role; group membership; app assignments and removals; provisioning verified or failed; recovery requested, approved, cancelled or completed; and domain policy. Each event has a stable ID (`evt_…`), a version, an ordering number (`seq`), a subject and data, and never carries a secret, link or token. Deliveries follow the Standard Webhooks scheme: `webhook-id`, `webhook-timestamp` and `webhook-signature` (`v1,` and a base64 HMAC-SHA256 over `id.timestamp.body` with the `whsec_` secret). A 2xx answer means received, nothing more; 429 (with Retry-After), timeouts and 5xx are retried with backoff for three days, other 4xx answers stop that delivery. **Make a new secret** signs with both secrets for 24 hours. A subscriber that missed events reads `GET /api/auth/events?after=<seq>&limit=<n>` with `Authorization: Bearer <read key>`; the read key opens nothing else. Endpoints must be public HTTPS host names: IP addresses and private or internal names are refused.
