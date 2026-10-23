# Hono authorization SDK 0.1.0

This server-only adapter checks a real Auth resource permission on every request.
It exports the existing OAuth session client and scoped administration client.
It supplies neither a cookie store nor a complete browser sign-in application.

Pack both packages from the Auth checkout, then install both archives into an
empty Node 22.20 or later application:

```sh
npm pack ./packages/session-sdk --pack-destination /tmp
npm pack ./packages/hono-sdk --pack-destination /tmp
npm init -y
npm install /tmp/runeditrun-auth-sdk-0.1.0.tgz /tmp/runeditrun-auth-hono-0.1.0.tgz
```

Registry publication is not claimed. `examples/protected.mjs` in the installed
Hono package exports `createProtectedApp({session, apiId})`. Register a public
OAuth client with its exact callback and an API containing the `read` action
and `document:budget` resource. Assign the employee an eligible role and enable
the explicit offline session profile. Enroll the employee through ordinary Auth
email and passkey doors. Use `createSessionClient` from this package to request
authorization, obtain the employee's consent and complete the exact callback.
See the core SDK README for its state, issuer, PKCE and DPoP checks.

`session(context)` must resolve the current caller to their own server-held SDK
instance using your application's authenticated session store. Return null when
absent. Never use one employee's client for all requests, accept a user-supplied
subject, or expose a service credential as an employee session. Separate employers
require separately registered clients, issuers and isolated session storage.

The quickstart returns a Hono application. Mount its `fetch` handler in your
Node server or Worker using that runtime's ordinary Hono adapter. Protect session
cookies, enforce the app's CSRF policy and keep private keys and tokens off the
browser. Development uses a fresh local Auth install and dedicated registrations;
production uses HTTPS with its own exact registered issuer and callback.

`requirePermission({session, apiId, action, resource})` fixes the permission in
server configuration. A missing session returns 401, a refusal returns 403, and
an unavailable authorization service returns 503. No handler runs on any of
those responses. Successful checks expose only `authPrincipal` in Hono context.
The adapter never caches a grant, refreshes a session or retries a request.
Revocation therefore applies to the next request. Auth token rotation and key
custody follow the core SDK's explicit profile; use its shared in-flight refresh
and atomically persist replacements in your session store.

A wrong callback is diagnosed as `invalid_callback`; fix the registration and
configured redirect together. Never edit SDK checks to accept it. The installed
quickstart proves scoped access after genuine consent, a wrong callback refusal,
rotation and immediate denial after revocation. Browser login pages, organization
switching, embedded components and complete logout remain future work.
