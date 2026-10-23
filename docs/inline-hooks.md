# Inline hook protocol

An Auth administrator with a passkey session and a local email confirmation less
than ten minutes old registers an endpoint with `POST /api/auth/hooks/register`.
Both checks are repeated in the committing write. The JSON configuration is:

```json
{"point":"token","url":"https://hooks.example.com/token","appId":"synthetic-auth-1","allowedFields":["cost_center"],"timeoutMs":3000,"failClosed":true}
```

Registration returns the hook ID and its signing `secret` once. Auth stores the
secret encrypted. Retain it only in the employer's endpoint secret store. Disable
with `POST /api/auth/hooks/disable` and `{"id":"the hook ID"}` under the same
administrator proof. A disabled hook is skipped by subsequent invocations.
The administrative model exposes configuration and status, never signing secrets.

Token hooks require exactly one target: `appId` for a company OIDC app or
`clientId` for a strict RER client. SAML hooks require a SAML `appId`. Other points
are installation-wide and reject either target field. At most four active hooks
are permitted per point and target. Calls run in creation order; later validated
outputs replace earlier outputs for the same permitted field.

## Requests and signatures

Auth POSTs JSON with `id`, `version: 1`, `point`, ISO `occurredAt` and `data`.
The endpoint receives only the following projected data, when available:

| Point | Data | Successful JSON response |
| --- | --- | --- |
| `token` | `personId`, `appId`, `clientId` | `{"claims":{"cost_center":"synthetic-auth-2"}}` |
| `saml` | `personId`, `appId` | `{"attributes":{"cost_center":"synthetic-auth-2"}}` |
| `registration` | `email`, `name` | `{"allow":true,"profile":{"name":"Synthetic person"}}` |
| `user_import` | `sourceId`, `email`, `name` | `{"allow":true}` |


No token, password, credential, signing key, session proof, existing claim set,
imported authority or MFA state is forwarded. A hook can use its own directory
and the supplied identifier to obtain its business metadata.

The signature follows Standard Webhooks: `webhook-id` is the call ID,
`webhook-timestamp` is the Unix timestamp in seconds, and `webhook-signature` is
`v1,BASE64_HMAC_SHA256`. Decode the signing secret after its `whsec_` prefix as
base64; sign the exact UTF-8 bytes of `id.timestamp.body`. Verify the signature
against the raw request body, reject timestamps outside a short local tolerance,
and retain call IDs during that tolerance to reject replays. Auth does not retry
an inline call; each invocation has a new ID. Lifecycle event delivery is separate.

## Output boundaries and failure policy

The registration `allowedFields` list defaults to empty. Token and SAML custom
names are ASCII identifiers up to 64 characters; protocol, identity and authority
fields such as `sub`, `role`, `roles`, `groups`, `amr`, `acr`, `scope`, `email`,
`install_owner` and MFA/policy fields are reserved. The hook cannot authorize an
app assignment, change a subject or bypass sign-in policy. Token values are
bounded strings, numbers, booleans or arrays of those values. SAML values are
bounded strings or arrays of strings. Null and nested objects are refused.

Registration and user import may allow-list only `name`; name changes require
that explicit field and stay bounded to 160 characters. Email, source identity,
account matching and all authority remain Auth decisions. `{"allow":false}`
refuses the operation. Current import doors are staged move-in admission and the
source-id-matched directory feed. Auth keeps their reviewed identity bindings;
the hook cannot turn an email match into identity proof or rebind a subject.

The current-capability boundary includes the first-login legacy verifier bridge in AUTH-MIGRATION-002. Its `password_import` hook receives only the reviewed person and source IDs, with no password, bridge credential or configurable output fields. The independent signed legacy verifier request is documented in `docs/progressive-migration.md`; it is a different, explicitly authorized credential-verification boundary. The hook retains the existing signature, minimal-payload, timeout/failure, protected-identity, destination and audit checks. New match/create doors in AUTH-HRIS-001, AUTH-HRIS-002 and AUTH-SCIM-002 inherit the complete AUTH-HOOKS-001 obligations before shipping.

Responses must be 2xx JSON, at most 32 KiB, with exactly the documented keys.
Unknown keys, reserved or unallowlisted fields, malformed responses, explicit
denials and HTTP 403 always refuse, including with fail-open configured.

`timeoutMs` defaults to 3000 and ranges from 100 to 10000. The deadline includes
DNS validation, signing, sending and reading the full bounded response.
`failClosed` defaults to true for every point. Fail-open continues with Auth's
original decision only after a timeout or unavailable service/DNS resolver; it
cannot override a denial or invalid response. Errors include `hook_timeout`,
`hook_refused`, `hook_invalid_response` and `hook_unavailable`. Every attempted
call is audited with ID, point, latency, outcome and failure policy. Request and
response bodies and the signing secret are excluded from audit.

## Destination validation

Endpoints must use HTTPS, including local installs, and cannot contain userinfo
or fragments or query parameters. Auth applies its outbound hostname restrictions and resolves A and
AAAA records through Cloudflare's public DNS-over-HTTPS JSON endpoint both at
registration and before each send. Empty, truncated, failed and nonpublic results
are refused. Every returned address must be public; mixed public/private answers
are refused. Returned CNAME targets undergo hostname validation. Redirects are
never followed. A private address answer is a refusal even for fail-open hooks.

The runtime's `connectorFetch` seam covers DNS and hook HTTP calls; a host may
instead provide trusted `hookResolve(hostname,{signal})`, returning all resolved
address strings. It must enforce the same complete-answer semantics.

The Workers fetch API resolves the destination again and does not expose an IP
pinning option here. Preflight DNS validation therefore cannot guarantee that
the address fetch connects to matches the checked answers during DNS rebinding.
Deployments needing that guarantee require a transport enforcing destination IP
policy at connection time; this module does not claim that protection.
