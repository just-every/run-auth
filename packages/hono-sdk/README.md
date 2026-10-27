# Hono authorization SDK 0.1.0

This server-only adapter checks a real Auth resource permission on every request.
It exports the OAuth session client and scoped administration client. The packaged
browser quickstart adds login, callback binding, isolated employer sessions,
explicit switching, rotation and application logout followed by Auth confirmation.

Pack both packages from the Auth checkout, then install both archives into an
empty Node 22.20 or later application:

```sh
npm pack ./packages/session-sdk --pack-destination /tmp
npm pack ./packages/hono-sdk --pack-destination /tmp
mkdir documents-app
cd documents-app
npm init -y
npm install /tmp/runeditrun-auth-sdk-0.1.0.tgz /tmp/runeditrun-auth-hono-0.1.0.tgz
```

Registry publication is not claimed. Run the installed example unchanged:

```sh
AUTH_APP_CONFIG=./app.json node node_modules/@runeditrun/auth-hono/examples/server.mjs
```

Create `app.json` using your public registrations (no private keys or tokens):

```json
{
  "origin": "http://127.0.0.1:3000",
  "organizations": [
    {
      "id": "a",
      "name": "Employer A",
      "issuer": "http://localhost:8787",
      "clientId": "registered-public-client",
      "apiId": "registered-resource-api",
      "resource": "http://127.0.0.1:3000/api/a"
    }
  ]
}
```

In a fresh Auth installation, complete owner setup and enroll the owner's passkey
through the ordinary email link and passkey doors. Invite an employee. On Apps,
register a public OAuth client (authentication method `none`) with the exact
callback `http://127.0.0.1:3000/callback/a`. Register the app's resource API with
the configured audience, `read` scope, `document:budget` resource and a `reader`
role granting `read` on `document:*`. Choose ES256 for the example's ID-token
signing algorithm. Let a fresh signing key's published use-after deadline pass
before completing the first callback; `signing_key_not_ready` requires waiting
and deliberately starting a new authorization, never bypassing key publication. Assign that role to the employee. Publish
the explicit offline session profile for this client, API and scope with chosen
idle and absolute lifetimes. These are human-authorized Auth operations; the
quickstart cannot grant itself access or create production authority.

The employee opens Auth's sign-in page, proves email in the same browser and
registers a passkey on Sign-in methods. Open the application, choose **Sign in to
Employer A**, and review Auth's real offline-access consent. The exact callback
exchanges its single-use code on the server. **Read budget** checks the live API
permission before returning a document and an opaque subject. Auth tokens, PKCE
verifiers and nonextractable DPoP keys remain in server memory. The browser holds
only an opaque HttpOnly, SameSite cookie; HTTPS adds Secure and the host prefix.
Every application POST requires its own form token and exact application Origin.

For another employer, add another configured entry with a different id, its full
employer issuer (including `/org/<id>`), separately registered client and API,
and exact callback ending in that id. In that employer, independently prove the
owner and employee email and passkey, assignment and consent. A root session,
matching email or unproved employer is never a membership credential. **Switch
to Employer B** requires an already proved employer session and a new live
permission check. It changes only the active application slot. Each slot retains
its own issuer, client, subject, tokens and DPoP key; identities are not linked.

**Rotate session** explicitly rotates the active employer's refresh credential.
The core client shares concurrent refresh calls and publishes a replacement only
after storage succeeds. This example uses only memory, never durable tokens or a
shared grant across processes. A failed rotation needs deliberate new sign-in;
there is no automatic retry, refresh or reuse recovery. Revoke the device grant
on Auth's My account page: the next protected request is refused immediately.
Switching to that grant also fails, without falling back to another employer.

**Sign out of application and Auth** destroys every local employer slot and all
pending callbacks before redirecting to the active employer's `/oidc/logout`.
Confirm **Sign out** on Auth. Auth ends that employer's browser source session
and its dependent grants. Other employers' Auth source sessions remain separate;
end them through their own Auth logout door if desired. Old application cookies
and callbacks cannot restore ended application sessions. Application logout alone
is not a claim that every independent Auth source session or remote device ended.

## Errors and deployment

`invalid_callback` means the configured callback and delivered address differ;
correct the registration and configuration together. Auth refuses an unregistered
redirect before issuing a code. `invalid_state` means the transaction is absent,
expired, replayed or belongs to another browser. `invalid_issuer` means the
callback did not name that slot's exact issuer. Begin a deliberate new sign-in;
never edit installed SDK internals to bypass these checks. An unavailable or
unproved employer is refused, and authorization failure never grants a document.
The permission middleware returns 401 for a missing or ended session, 403 for
refused access and 503 for unavailable authorization; application operations
return safe error codes without raw upstream responses or credentials.

The Node entry point listens on loopback at the origin's explicit port, or 3000.
Set `listenPort` in configuration for a separate reverse-proxy listener port. Production requires a trusted HTTPS
reverse proxy, the exact public `origin`, HTTPS employer issuers, dedicated
registrations and matching callback addresses. The app never trusts forwarded
headers to select its origin or employer. Do not serve this HTTP Node listener
directly as HTTPS. Keep configuration and server access under operator custody;
use a dedicated browser-cookie namespace when adapting the example.

This is a bounded single-process quickstart with a one-hour absolute local session
lifetime, ten-minute login transactions and a capacity limit of 1,000 browser
sessions by default. `createBrowserApp` accepts `sessionLifetimeMs` and
`maxSessions` overrides. Process restart deliberately discards all sessions and
keys: old cookies and callbacks fail closed and the employee signs in again.
Do not run independent replicas behind it and assume their stores are shared.
A durable deployment must implement atomic token and matching DPoP-key custody,
expiry, cross-process refresh coordination and fail-closed storage clearing as
documented in the core SDK before claiming continuity. No issuer JWT or JWKS
cache is used here; Auth rechecks live authority and its signing keys. Application
DPoP-key replacement requires a new explicit authorization, never restoring old
tokens under a replacement key.

`examples/protected.mjs` still exports `createProtectedApp({session, apiId})` for
hosts with their own authenticated server session store. `session(context)` must
resolve the current caller's own SDK instance or null. Never use one employee's
client for all requests or expose service credentials as employee sessions.
`requirePermission({session, apiId, action, resource})` fixes a permission in
server configuration, authorizes each request and exposes only `authPrincipal`
in Hono context. It never caches a grant or silently retries.

The installed browser journey covers this Hono and Node public-client profile.
Next.js and React, full Python employee sessions, other framework browser
journeys and embedded user and organization components remain unproved.
Embedded components still require the shared theme and component release under
AUTH-EXPERIENCE-001; this slice does not qualify it or the whole SDK clause.
