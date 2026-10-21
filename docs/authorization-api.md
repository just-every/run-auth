# External application authorization

Auth's registered resource APIs evaluate current workforce roles, directory attributes and resource relationships. These decisions govern an external application's permissions; the application must enforce the decision before accessing its resource. A decision is a snapshot, not a durable permission or a transaction lock in the external application's database. Call again for the next protected operation.

Configuration requires an owner/admin or an explicitly delegated app-administrator permission over the target app, authenticated with a hardware passkey. Every configuration mutation also requires that session's local email confirmation within ten minutes; session, person version, role, active status and email proof are checked by the committing SQL statement. App ownership alone does not open administration: the owner grants `apps.edit` (configuration) or `apps.assign` (assignment) through Roles. Service-owner and assignment effects also require the affected people and all their groups in the holder's edit scope; equal or higher administrators are refused. Preparer keys, external API tokens and machine administration tokens cannot configure resource APIs.

All routes are relative to the selected organization's Auth base path: `/org/<id>` for a non-root organization, or the root path for root Auth. The issuer is the HTTP origin plus that organization prefix. Cookie requests include the actual HTTP `Origin` header, without the organization prefix. Every lookup uses that organization's physically scoped database; an identifier from another organization is insufficient.

## Configuration routes

`GET /api/auth/resource-apis` requires a passkey session with app-view permission and returns only scoped apps as `{organizationId,configurationAuthority,apis,services}`. Service records include purpose, accountable owner, scope, target resources, expiry, revision, revocation and last token issuance. Private keys, secrets and bearer tokens are never returned or stored.

`POST /api/auth/resource-apis/register` accepts JSON like:

```json
{
  "appId": "company-app-id",
  "name": "Documents API",
  "audience": "https://documents.example/api",
  "scopes": ["read", "write"],
  "roles": [
    {"role": "reader", "scopes": ["read"], "resources": ["document:*"]},
    {"role": "editor", "scopes": ["read", "write"], "resources": ["document:*"],
     "attributes": {"department": "engineering"},
     "relations": {"ownerId": "$person"}}
  ],
  "resources": [
    {"id": "document:budget", "attributes": {"ownerId": "person-id"}}
  ]
}
```

It returns `{id,apiId,appId,audience,revision}`. Include `apiId` to replace the complete configuration of an existing API. Its company app binding is immutable. API audiences are unique in the tenant; Auth administration audiences are refused. Every replacement advances the policy revision, immediately invalidating earlier service access tokens.

All role constraints are conjunctive. `resources` accepts exact IDs, `*`, or a terminal-prefix wildcard such as `document:*`. A target must also be in the API's registered resource catalogue: a wildcard does not make an unknown resource accessible. The catalogue is authoritative; permission callers cannot inject resource attributes. A registered resource may declare `organizationId`, which must equal the current organization. IDs are tenant local.

`attributes` compares exact normalized string values against the person's current effective directory fields, using the existing precedence: manual, HR, directory, self. The workforce default for `kind` is `employee`. Missing attributes deny. `relations` maps registered resource attribute names to `$person` (the current person's ID) or `$attribute:<field>` (for example `$attribute:department`). Missing relation values deny. There is no executable policy or caller-supplied SQL.

`POST /api/auth/resource-apis/assign` takes `{apiId,principalType:"group"|"person",principalId,role}`. It updates the existing company app assignment, including the existing workforce event and provisioning queue; it does not create an independent API-only role. `{apiId,principalType,principalId,remove:true}` removes it. Therefore launcher access, SCIM-provisioned roles and API authorization share the same assignment. Direct person assignments take precedence over group assignments. Where several groups assign different roles, the existing workforce selection chooses one matching group role; use one consistent role per person/app to avoid ambiguity. A role absent from the registered API policy denies API access even when an app launch remains assigned. Group membership and role removal affect the next permission decision; previous access tokens do not retain the old role.

## Accountable service clients

`POST /api/auth/resource-apis/service-create` takes:

```json
{
  "apiId": "registered-api-id",
  "name": "Document indexer",
  "purpose": "Index approved engineering documents",
  "ownerId": "active-accountable-person-id",
  "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "indexer-1", "x": "PUBLIC_X", "y": "PUBLIC_Y"}]},
  "scopes": ["read"],
  "resources": ["document:budget"],
  "expiresAt": "2026-12-01T00:00:00Z"
}
```

`PUBLIC_X` and `PUBLIC_Y` denote the client's actual public JWK coordinates. Generate and retain the private key in the service's own secure environment. Auth accepts public ES256 or RS256 signing keys with distinct `kid` values and refuses private-key material. There are no client secrets. Expiry is mandatory and at most 365 days ahead. Each target pattern must match at least one registered resource. Scope must be a subset of the API's scopes.

The result contains `{id,clientId,apiId,audience,ownerId,expiresAt,tokenEndpoint,tokenEndpointAuthMethod}`. Client IDs have the distinct `resource-service:` namespace. The owner must be an active person in the same organization. The credential binds the owner's current person version. Suspension, departure or a person-version change ends the credential permanently; restoration requires a new credential. Removing the owner's app role denies the next protected decision. A service's permission is the intersection of its configured scopes/resources and its accountable owner's current workforce role, attribute and resource restrictions.

`POST /api/auth/resource-apis/service-revoke` takes `{clientId}`. Revocation advances the credential revision and immediately ends both future token issuance and existing tokens at online checks. Credentials and revocations are audited with the acting administrator. Token issuance and permission checks record the distinct service actor, accountable owner, API and outcome.

The service posts form data to its returned `tokenEndpoint` (`<issuer>/oidc/token`):

```text
grant_type=client_credentials
client_id=resource-service:<id>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<signed assertion>
scope=read
```

The assertion has `iss=sub=clientId`, `aud` exactly equal to the organization-specific token endpoint, unique `jti`, and integer `iat`/`exp` covering at most five minutes. Auth checks its signature, exact audience, expiry and replay in the authoritative tenant database. Assertions are one use. Basic authentication and `client_secret` are refused. Omitted scope uses the registered scope; empty or excess scope fails. Assertions never supply a human subject.

The response is standard OAuth `{access_token,token_type:"Bearer",expires_in,scope}`. Access tokens are signed `at+jwt`, expire within five minutes and never beyond the credential's expiry. Their `iss` is the organization issuer and `aud` is the registered API audience. Claims bind organization, API/policy revision, credential/revision, accountable owner/version and scope. `sub` is the distinct service identity; it is never the owner. Tokens confer no cookie, interactive proof, enrollment permission, impersonation permission or Auth administration authority.

## Live permission checks

`POST /api/auth/resource-apis/check` takes `{apiId,action,resource}`. `action` is a registered scope. `resource` is a registered ID string, or `{id,organizationId}`. An optional `audience` must exactly match the registered API audience. Wrong organization, unknown API/resource/action, missing or removed role, missing directory attribute and failed resource relation all deny. A successful denial response is `{allowed:false,reason,apiId,organizationId}`; an allow response additionally identifies action, resource, distinct principal, current role and policy revision. Treat every failure or non-allow as denial.

An employee calls with their Auth session cookie and actual HTTP `Origin`. Auth uses the current person, live session/version and current group/app assignments. An optional `subject` may only equal that employee's own person ID; substitution is refused. No admin role is required for a person's own check.

A service calls with `Authorization: Bearer <resource access token>`; no cookie or `Origin` is necessary. It may only check its token's registered API, audience, scopes and resource targets. `subject` is refused for services. The current owner supplies accountability and current workforce restrictions, while the reported principal remains the service. Each check verifies the signature against current tenant-local public signing keys, issuer, exact audience, expiry, policy revision, service revision, owner/version/status and credential expiry/revocation. The decisive SQLite snapshot checks the live credential again together with the workforce role and directory values. Neither another API's token nor an identity/admin token is accepted.

Online checks are required for immediate revocation and role removal. External applications may verify signature/issuer/audience/type/expiry locally as preliminary validation, but a cached/offline JWT decision cannot prove current authority. The verifier reads current tenant-local JWKS on each check, so newly published Auth signing keys can be used immediately without an external JWKS cache delay. External verifiers must refresh discovery/JWKS when an unknown key is seen. API authorization is always enforced by the external application; Auth does not proxy or transact that application's data operations.

## Backend integration

`src/auth/grants/index.mjs` exports `isGrantAction(path)`, `grantAction(ctx,request,path,data)`, `grantRead(ctx,request,path)`, `grantCheck(ctx,request)`, `resourceToken(ctx,request)` and `grantModel(ctx)`. Action paths accept `/resource-apis/...` or `/api/auth/resource-apis/...`; the read path is `/api/auth/resource-apis`. `resourceToken` reads a clone of the request and returns `null` for clients outside its namespace. Call it before other OAuth token handlers. All handlers return `Response` and use the existing `AuthError` for typed failures. Dispatch `grantCheck(ctx,request)` for POST `/api/auth/resource-apis/check` before the generic browser POST parser. It parses bounded JSON for bearer clients and calls the existing Origin-checked input parser for cookie clients; configuration handlers enforce their own Origin check. `grantModel` is an internal model loader whose caller must have authenticated an administrator.

Migration `0040_auth_resource_grants.sql` adds `auth_resource_apis`, `auth_resource_services`, and replay table `auth_resource_assertions`, plus indexes and a permanent credential revocation trigger on accountable person status/version changes. It reuses `auth_apps`, `auth_app_assignments`, `auth_groups`, `auth_group_members`, `auth_person_fields`, existing session/email proofs and the issuer's signing keys. No separate workforce roles, personal sessions, or machine administration grant is created.
