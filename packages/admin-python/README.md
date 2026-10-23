# Python administration SDK 0.1.0

Python 3.10 or later. This server-only package implements scoped v1 machine
administration. It does not implement employee sign-in or organization switching.
Registry publication is not claimed.

From the Auth checkout, build a wheel:

```sh
python3 -m pip wheel --no-deps ./packages/admin-python --wheel-dir /tmp/auth-wheels
```

In an empty application, create a virtual environment and install the wheel:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install /tmp/auth-wheels/runeditrun_auth-0.1.0-py3-none-any.whl
.venv/bin/python -m runeditrun_auth.quickstart
```

Before the last command, configure `AUTH_ISSUER`, `AUTH_CLIENT_ID`,
`AUTH_KEY_ID` and `AUTH_PRIVATE_KEY_FILE` privately. An administrator registers
the service through [the admin API guide](/docs/admin-api), using its public JWK,
named human custodian, expiry, exact scopes and resources. The quickstart needs
`groups.read`. Use a fresh local Auth installation and a dedicated test service.
The private PKCS8 key stays in a protected server file. Never send it to a browser.
For a separate employer, use its full issuer path and its own service registration.

```python
from runeditrun_auth import AdminClient

client = AdminClient(issuer=issuer, client_id=client_id, private_key=pem_bytes,
                     kid=key_id, scopes=["groups.manage"])
group = client.request("POST", "/groups", body={"name": "Engineering"})["data"]
current = client.request("GET", "/groups/" + group["id"])
client.request("DELETE", "/groups/" + group["id"], etag=current["etag"])
```

ES256 P-256 and RS256 keys of at least 2048 bits are supported. Assertions have a
unique ID, exact audience and sixty-second lifetime. An in-memory token cache
is locked across threads and renewed before expiry. Tokens never cross issuers.
Every request still passes the server's current scope, resource and owner gates.
Redirects and unsafe paths are refused; HTTPS is required except at loopback.
Responses are limited to one MiB and requests time out after fifteen seconds.

`request` returns `data`, `status`, `etag` and `rate_limit_remaining`.
`pages` follows live offsets; it is not a frozen export. `AuthAdminError` exposes
only `code`, `status` and numeric `retry_after`. A 401 clears cached authority.
No failure or stale ETag is retried automatically. On 412, reread and review the
change before submitting again; on a scope refusal, ask the service's human
custodian to review the registration. Network uncertainty requires reconciliation
through a read before any deliberate repeat write.

The client neither verifies external JWTs nor caches issuer signing keys. To
rotate its signing key, register a replacement service with the authorized human
door, deploy a new client instance, then revoke the old service. There is no
SDK operation for changing its own authority. Employee callback validation,
logout, framework components and complete web quickstarts remain unimplemented.
