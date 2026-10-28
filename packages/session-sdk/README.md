# OAuth session client

`index.mjs` exports `await createSessionClient({ issuer, clientId, redirectUri,
fetch = globalThis.fetch, keyPair, storage })` for public browser and native
clients registered with token endpoint authentication method `none`. It uses
WebCrypto through `globalThis.crypto` and the repository's `jose` dependency;
there are no Node-specific APIs. A native host must supply real WebCrypto and
Fetch implementations. Register the exact redirect URI, including any custom
scheme, before use.

```js
import { createSessionClient } from './packages/session-sdk/index.mjs';

const client = await createSessionClient({
  issuer: 'https://identity.example.com',
  clientId: 'registered-native-client',
  redirectUri: 'com.example.documents:/oauth/callback',
});
const { url } = await client.authorization({
  resource: 'https://documents.example.com/api',
  scopes: ['records.read'],
  deviceName: 'Personal phone',
});
// Open url in the system browser; deliver its redirect to this same instance.
```

`authorization` returns `{ url, state }`. It requests code flow with S256 PKCE,
`openid offline_access`, the supplied scopes, audience, device name, DPoP key
thumbprint, nonce and explicit consent. `scopes` may be an array or a
space-separated string. Starting another authorization replaces the pending
transaction. State and verifier stay only in this client's memory. Keep the
instance alive while the browser is open; after a process restart, start a new
authorization.

`await client.complete(callbackURL)` accepts the authorization redirect only at
the configured scheme, authority and path, including for custom schemes. It
requires a matching state and exact issuer `iss`, rejects OAuth errors and
duplicate response parameters, and consumes the transaction before exchanging
the code. The token request includes the verifier and an ES256 DPoP proof.
It returns a copy of the saved tokens.

`await client.refresh()` rotates the refresh token. Concurrent calls on one
instance share a single promise. Each HTTP request has a new DPoP proof. A
`use_dpop_nonce` response carrying `DPoP-Nonce` permits exactly one continuation
at that endpoint with a new proof; no other failure triggers a repeat request.
Any refresh failure clears the in-memory session and awaits durable storage
clearing. If storage clearing also fails, the original error retains its code
and has `storageClearFailed: true`; the host must clear its durable copy before
restoring a session. There is no automatic refresh, sign-in, network retry or
replay recovery.

`await client.resourceRequest('/api/auth/resource-apis/check', data)` posts JSON
to this issuer's resource check endpoint with `Authorization: DPoP` and a proof
containing the access token's SHA-256 `ath`. It returns the parsed JSON result.
An HTTP error, an OAuth error or `allowed: false` rejects; callers must handle
the rejection as a denied request. Other paths are rejected. Resource requests
never silently refresh or start sign-in. Errors expose a stable `code` and,
when available, HTTP `status`; response descriptions and bodies are not placed
in error messages.

## Persistence and concurrency

By default a new, nonextractable P-256 key is generated for each client. Durable
sessions require the host to create, securely persist and pass the same
WebCrypto `{ publicKey, privateKey }` pair on every restart. Persisting tokens
without their DPoP key does not preserve a usable session. Browser hosts can
store nonextractable CryptoKeys using structured cloning in IndexedDB. Native
hosts own their secure key storage integration. The SDK never exports private
key material, stores a verifier or state durably, or logs credentials.

Optional `storage` implements async `save(tokens)` and `clear()`. Successful
code exchange and refresh await `save` before publishing replacement tokens in
memory. Store the entire supplied object atomically. `getTokens()` returns a
copy or `null`. `restore(tokens)` synchronously validates and loads a host-read
token object; `restore(null)` resets memory. Restore does not read or write
storage. Tokens contain `access_token`, `refresh_token`, `token_type: 'DPoP'`,
`expires_in`, `scope`, and `grant_id`. `expires_in` is the server's issuance-time
lifetime, not a countdown; hosts scheduling refresh must also track issuance
time. Do not log or embed token values.

Only a single instance coordinates concurrent refresh calls. The host must
coordinate refresh across instances, browser tabs and processes, including
atomic publication of the replacement to all consumers. Never allow separate
instances to refresh the same stored token concurrently. The server revokes
the grant family when a consumed refresh token is replayed. A timeout or failed
storage write can follow successful server rotation: clear the local session
and require deliberate user sign-in instead of retrying the old token.
Restore and code exchange reject while another token operation is in flight.

## Installable Node administration slice (0.1.0)

This package can be packed and installed in an empty Node 22.20+ app. From the
Auth checkout, run `npm pack ./packages/session-sdk --pack-destination /tmp`.
In the empty app run `npm init -y`, then
`npm install /tmp/runeditrun-auth-sdk-0.1.0.tgz`. Registry publication is not
claimed. Import `createSessionClient` from `@runeditrun/auth-sdk` for the
explicit public-client OAuth and DPoP profile documented above.

The server-only `@runeditrun/auth-sdk/admin` export provides
`createAdminClient({issuer,clientId,privateKey,kid,algorithm='ES256',scopes})`.
It uses the v1 machine API in `/docs/admin-api`: register a service under a
human custodian, with its public JWK, exact scopes, resources and expiry.
Import the private PKCS8 key into WebCrypto with `jose.importPKCS8`; keep it in
private server custody. HTTPS is required except at loopback during local
installation. For an isolated employer use its full `/org/<id>` issuer, never
a root token or a fabricated organization claim.

```js
import {createAdminClient} from '@runeditrun/auth-sdk/admin';
const client = createAdminClient({issuer, clientId, privateKey, kid,
  scopes: ['groups.manage']});
const {data: group} = await client.request('POST', '/groups', {
  body: {name: 'Engineering'},
});
const {etag} = await client.request('GET', '/groups/' + group.id);
await client.request('DELETE', '/groups/' + group.id, {etag});
```

`request` returns `{data,status,etag,rateLimitRemaining}`. ETags are never
silently fetched or retried: on 412 reread, review the change and deliberately
submit again. `pages('/groups', {limit:100})` yields each response following
`nextOffset`; it is a live offset traversal, not a frozen as-of export. There
is no automatic write, failure retry, privilege escalation or redirect follow.
Absolute URLs and path traversal are refused before any credential is sent.

Private-key assertions use a unique jti, exact token audience and a sixty-second
lifetime. Tokens remain in memory, shared by concurrent calls, and are renewed
before expiry; the server rechecks live authority on every request. A 401 clears
the cached token and returns the refusal without retry. Errors expose only the
stable code, status and numeric retry-after, never provider bodies, keys,
assertions or tokens. This client does not verify external JWTs or cache JWKS.
For issuer signing-key rotation Auth verifies against its current local keys.
To replace a service signing key, register a replacement service with its signing key through
the authorized human door, deploy a new client instance and revoke the old
service; the SDK cannot mutate its own key custody.

`examples/admin.mjs` is a complete read-only quickstart. Configure
`AUTH_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_KEY_ID` and `AUTH_PRIVATE_KEY_FILE` on
your server, then run the installed package's example from `node_modules`.
It prints permitted groups and safe errors, never authentication material.
A scope/resource/IP refusal requires the registration's human custodian to
review it. A wrong web redirect must be corrected in the app registration and
SDK `redirectUri` together; callback validation remains exact and is never
bypassed by editing SDK internals. The Node administration slice adds no web
session or cross-employer authority. The Python administration package is in
`./packages/admin-python/README.md`; the Hono authorization adapter is in
`./packages/hono-sdk/README.md`. Next.js and React, embedded components and
other framework employee web journeys remain DEVELOPER-001 work. The installed
Hono and Node browser quickstart in `./packages/hono-sdk/README.md` holds each
employer session on the server, requires independent employer consent, and ends
local application authority before Auth logout confirmation. Its in-memory
sessions deliberately require new sign-in after restart; it does not establish
durable session continuity or embedded component support.
