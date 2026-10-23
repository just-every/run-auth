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
  redirectUri: 'example-app:/oauth/callback',
});
const { url } = await client.authorization({
  resource: 'https://identity.example.com/api/auth/resource-apis/check',
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
