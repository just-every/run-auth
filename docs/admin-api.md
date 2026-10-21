# Machine administration API

The version 1 machine API is at `/api/auth/admin/v1`. Its OpenAPI description is available at `/api/auth/admin/v1/openapi.json`. It covers the current directory, company apps, domain-provider rules and availability of owner-configured identity providers. Future custom-role, policy and federation capabilities remain in AUTH-ROLES-001, AUTH-POLICY-001 and AUTH-FEDERATION-001; their machine doors must reuse this credential, scope, exclusion, audit and concurrency model before shipping. The Terraform provider remains AUTH-TERRAFORM-001.

## Register a service app

An administrator opens **Agents**, proves their passkey and confirms their email locally within ten minutes, then registers an **admin service app**. Give it a name, published purpose, accountable active human administrator, expiry, public JWK set and only the scopes it needs. Auth accepts public RSA keys for RS256 or P-256 keys for ES256; the private key stays with your automation. Admin scopes never offer client-secret authentication.

Registrations expire within 365 days. Optional source-IP restrictions accept individual IPv4/IPv6 addresses and CIDR networks. Auth uses `CF-Connecting-IP` at its trusted Cloudflare Worker boundary as the authoritative source address; `Forwarded` and `X-Forwarded-For` cannot substitute for it. A configured allow-list refuses requests whose authoritative address is missing or outside the list.

Resource restrictions cover three kinds: `people`, `groups` and `apps`. Each kind contains explicit IDs, `['*']` for all, or `[]` for none. An omitted kind defaults to all, so specify every kind when narrowing a registration. For example:

```json
{
  "people": ["person-id"],
  "groups": ["group-id"],
  "apps": ["app-id"]
}
```

These are restrictions on a credential, not a way for that credential to create or edit administrator roles or resource sets. Creating a person, group or app needs unrestricted access to that kind because the new ID does not exist yet. Mutations must also cover affected people, groups and apps; having permission for the direct target alone does not authorize side effects on other resources.

If the accountable owner is demoted, suspended or leaves, the service app suspends and existing tokens stop working. Restoring that person does not silently restore the app. A human administrator must assign an active administrator as the accountable owner again. Reassignment invalidates existing tokens. Revocation and expiry also end access; machine credentials cannot manage these registrations.

## Obtain a token

POST an `application/x-www-form-urlencoded` body to `/oidc/token` with:

| Field | Value |
| --- | --- |
| `grant_type` | `client_credentials` |
| `client_id` | The registered ID, in the `auth-admin-service:` namespace |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | A JWT signed with your registered private key |
| `scope` | Optional space-separated subset of registered scopes; omission uses the registered scopes |

The assertion has `iss` and `sub` equal to the client ID, `aud` exactly equal to the issuer origin followed by `/oidc/token`, integer `iat` and `exp` times in seconds, and a unique, nonempty `jti`. Assertions last at most five minutes and cannot be replayed. Include the public key's `kid` when more than one key is registered. Do not send HTTP Basic authentication or `client_secret`.

The response contains `access_token`, `token_type: "Bearer"`, `expires_in` and `scope`. Tokens last at most five minutes, end sooner if the registration expires, and carry the `/api/auth/admin/v1` audience. Send the token in `Authorization: Bearer <access_token>` on REST requests. The current registration, owner, scope, expiry, revision and source address are rechecked on every call.

Admin service apps use a distinct client namespace and token profile. General company OIDC clients and RER registrations cannot request these scopes. Browser cookies and preparer keys cannot authenticate this API. Preparer keys remain proposal-only; an admin token grants no interactive sign-in or passkey/email proof.

## Scopes and routes

All paths below are relative to `/api/auth/admin/v1`. A `.manage` scope also permits the corresponding safe reads. `domains.read` and `logs.read` have no management equivalent.

| Family | Read routes | Mutation scope and routes |
| --- | --- | --- |
| People | `GET /people`, `GET /people/{id}` | `people.manage`: `POST /people`, `PATCH /people/{id}` |
| Groups | `GET /groups`, `GET /groups/{id}`, `GET /groups/{id}/members` | `groups.manage`: `POST /groups`, `DELETE /groups/{id}`, `PUT` or `DELETE /groups/{id}/members/{personId}`, `PUT /groups/{id}/rule` |
| Apps | `GET /apps`, `GET /apps/{id}` | `apps.manage`: `POST /apps`, `PATCH` or `DELETE /apps/{id}` |
| Assignments | `GET /assignments` | `assignments.manage`: `PUT` or `DELETE /assignments/{appId}/{principalType}/{principalId}` |
| Policies | `GET /policies` | `policies.manage`: `PUT` or `DELETE /policies/{domain}` |
| Identity providers | `GET /idps` | `idps.manage`: `PUT /idps/{id}` with `{ "enabled": true }` or `{ "enabled": false }` |
| Allowed enrollment domains | `GET /domains` | Read-only through `domains.read` |
| Activity | `GET /logs` | Read-only through `logs.read` |

Use the matching `.read` scope for each read family. Group membership reads use `groups.read` or `groups.manage` and filter each member against the permitted people IDs. Assignment reads and writes require both the app and its person/group target to be permitted. Resource lookups outside the credential's permitted read set return `404`, as do unknown IDs.

People responses expose `id`, `email`, effective `name`, lifecycle `state` and `profile` values, including configured custom attributes. They do not expose administrator roles, authentication or credential state. A manager reference outside the permitted people set is omitted. Owner and administrator person records can be read through this safe projection; machine writes to those people are excluded.

`POST /people` accepts `email`, optional `name`, `kind`, `source`, `sourceId` and `set`. It creates an invited member record without sending an invitation, accepting it, granting proof or merging an existing account by email. `PATCH /people/{id}` accepts `source`, `set`, `email` and `state`; it uses the directory's source precedence, lifecycle validation, group evaluation and provisioning. `set` maps directory keys to values; custom attributes use `x.<name>`. A null value clears that source's value. States are `active`, `suspended` and `terminated`; setting an invited record to active does not accept the invitation.

`POST /groups` takes `{ "name": "Engineering" }`. `PUT /groups/{id}/rule` takes `{ "rule": { "match": "all", "conditions": [{ "field": "department", "op": "eq", "value": "Engineering" }] } }`; `rule: null` clears it. Conditions support `eq`, `neq`, `in`, `present` and `absent`. Removing a member who matches the rule adds the ordinary explicit exclusion.

Company apps use the native SAML or OIDC settings and validation. `POST /apps` selects `protocol: "saml"` or `"oidc"`; `PATCH /apps/{id}` currently updates SAML apps only. OIDC updates and secret rotation have no machine route. `DELETE /apps/{id}` disables the app. App reads exclude client secrets, secret digests, verification/signing key material, sessions and provisioning credentials. Assignment `principalType` is `person` or `group`; the optional `role` in an assignment body is an app role, never an Auth administrator role.

Policies currently mean **exact-domain required-provider rules**, distinct from allowed enrollment domains. `PUT /policies/{domain}` takes `{ "providerId": "configured-provider-id" }`; DELETE removes that requirement. Providers must already be configured through Base's private `AUTH_UPSTREAM_PROVIDERS` environment setting. `GET /idps` exposes only configured provider ID, label, preset and availability. It does not expose client IDs, secrets, tenant configuration or external-identity bindings. Provider availability can be changed with `idps.manage`. Disabling a provider ends its current upstream proofs and refuses callbacks already in flight; a required-provider rule stays required, so disabling cannot open an alternate employee sign-in. Enabling restores only the existing owner-configured issuer/client/subject associations. Creation and credential/issuer changes remain in Base configuration; generic provider setup, broader policy types and domain verification are outside this implementation.

Logs are a safe Activity projection of supported business events: event, subject and time, with ID for ordering. Credential, factor, recovery, signing-key, administrator-role and service-app lifecycle events are excluded. Supported machine request events may additionally expose only service app ID, accountable owner ID, known scope and result. Arbitrary audit details are never returned.

## Pagination, concurrency and errors

Collection reads accept `limit` from 1 to 100 (default 25) and a nonnegative integer `offset` (default 0). The response is `{ "items": [], "total": 0, "nextOffset": null }`. `total` counts only permitted results; follow `nextOffset` until it is null. Offsets describe the current data rather than a frozen snapshot.

Successful REST responses other than log reads carry a strong `ETag`. Read an authorized resource or collection immediately before changing existing data and send that exact tag, including quotes, as `If-Match`. Existing-resource PATCH, PUT and DELETE operations require it, including membership, rule, assignment and policy changes. Weak tags and `*` are refused. Auth uses a shared administration revision: a concurrent administration change can invalidate a tag even when your target's visible fields are unchanged. On `412`, reread and review the current state before submitting the new change. Resource creation by POST does not require `If-Match`.

| Status | Meaning |
| --- | --- |
| `200` | Read or mutation succeeded |
| `201` | Resource created |
| `400` | Invalid request or pagination |
| `401` | Missing, invalid, expired or revoked machine authentication |
| `403` | Missing scope, excluded operation, disallowed resource effect or lost authority |
| `404` | Unknown route/resource, or resource outside a read restriction |
| `405` | Unsupported HTTP method |
| `409` | Current directory/app state refuses the change |
| `412` | Stale or invalid `If-Match` |
| `413` | Request body too large |
| `415` | Unsupported mutation content type |
| `428` | Required `If-Match` missing |
| `429` | Rate limit exceeded |

Error bodies include `error`; directory validation may also return `refusals`. REST responses include `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` and `RateLimit-Policy`. Rate-limited responses include `Retry-After` in seconds. The token endpoint has its own rate window and returns OAuth-style errors.

Every machine call is audited with service app, accountable owner, scope and result. No admin scope can assign or change administrator roles or resource sets, modify a person's factors or recovery, approve recovery, manage signing keys, create or edit admin service apps, change emergency accounts or widen its own policy. Those actions remain with interactive administrators under their normal proof requirements.

Admin access tokens are accepted only by this issuer’s Admin API. Its verifier reads the current local JWKS on every request, so these tokens can use a newly published issuer key immediately; external OIDC ID/access tokens keep their existing JWKS cache warm-up.

For domain-policy rows, Base’s `created_by` foreign key records the accountable human custodian. The committing guard is the machine’s own authority, and Activity separately identifies the actual service app, current accountable owner, scope and result. No human session or proof is manufactured.
