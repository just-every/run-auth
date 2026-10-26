# Upstream setup and cutover campaigns

Open **People → Move people in** with an owner passkey and confirm your email in this browser. A representative provider test never signs the employee into Auth and never replaces the owner’s session.

## Prepare, test and activate an upstream

First verify the exact employer domain on Sign-in methods. Admit the reviewed workers as ordinary invitations. Under **Upstream federation → Configure an upstream**, enter that domain and private provider configuration. Every subject association must name an existing ordinary worker in the verified domain. An address asserted by an upstream token does not create an association.

All providers need `id`, `preset` and `subjectEmails`, a JSON object mapping immutable upstream subjects to work addresses. Google uses `preset: "google"`; Microsoft uses `"microsoft"` and an exact `tenant`; Okta uses `"okta"` and its exact `issuer`. OIDC providers also need `clientId` and their configured token authentication method and credentials. Register the callback shown in the mapping preview at the provider.

Generic OIDC uses `preset: "oidc"`, an exact HTTPS `issuer`, and `endpointPins` containing the exact `authorization`, `token` and `jwks` URLs. The current profile accepts RS256, authorization code with PKCE, bounded public-network discovery and explicit immutable subject associations. Client secrets are sealed. Private-key authentication is also available through the configuration API. Provider keys are refreshed when a previously unknown signing key is presented; changing issuer, client or reviewed trust requires new approved setup.

Generic SAML uses `preset: "saml"`, with either `metadataUrl`, `metadataXml`, or explicit `issuer`, `ssoUrl` and `certificates`. The profile accepts a single IdP entity, Redirect AuthnRequests and POST responses with a signed response or assertion, correlated one-use requests, persistent NameIDs and pinned RSA certificates. Explicitly configured unspecified NameIDs are supported; email NameIDs do not establish identity. `signAuthnRequests` enables signed requests. Overlapping certificates may be configured for upstream rotation. Encrypted assertions and arbitrary authentication contexts are not supported. Only the REFEDS MFA context establishes SAML MFA for a campaign.

Choose a reviewed **Representative immutable subject**, then **Test representative sign-in**. Complete the real provider sign-in in the same browser. Auth checks the provider proof and the initiating owner session, records the tested subject, and returns to the mapping preview. Review the exact people and trust, confirm, then **Activate upstream**. Tests, drafts and a matching email cannot activate trust. Disabling an upstream destroys its sealed private configuration and ends its provider evidence; local Auth proof and administrator requirements remain independent.

## Run a passkey enrollment campaign

Use a dedicated campaign provider with the reviewed immutable subjects. Its discovery must have been tested and pinned. Stage and admit an Okta or Entra export, then expand **Start an enrollment campaign** under that batch. Select the upstream and cohort, opening time, deadline and cutover time. A selected cohort manager must be an existing active person.

Notification consent is separate for workers, the selected cohort manager and the approving administrator. No checkbox is selected automatically. Selected worker notices are due at opening, manager reminders three days before the deadline, and administrator notices at the deadline. The existing follow-up engine records each occurrence before delivery, rechecks custody and recipient consent, and does not repeat an unknown delivery after restart. Slack and Teams delivery remains outside this profile.

Each worker signs in through the incumbent with explicit MFA evidence, confirms their local Auth email and enrolls a passkey. A mismatched subject, unstaged worker, exempt person, privileged person or proof outside the window is refused. Removing or changing the campaign’s provider, closing the campaign or ending its administrator custody stops further campaign proof and reminders.

The dashboard distinguishes **Passkey ready**, **Pending**, **Overdue**, **Exempt** and **Review required**, and counts down without replacing the page. **Passkey ready** means incumbent proof plus a local passkey; it does not claim enrollment of the native Auth authenticator or preservation of an incumbent password. Export stragglers as CSV. Exemptions require an explicit reason and are audited.

The native authenticator, live employee callback qualification, JumpCloud, the optional Okta password preservation bridge and its RADIUS cutover remain unqualified. The held Okta application inspected in this round is a service client without an authorization-code grant or callback; a separate authorized web registration is required. Google callback registration and a consenting test user remain an owner console step. These limits keep AUTH-MIGRATION-003 and AUTH-FEDERATION-001 partial.
