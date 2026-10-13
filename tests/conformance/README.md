This is the pinned OpenID Foundation release-v5.3.2 runner at commit
11999aad62ec292f36101410d9d5b761d44903ff. Image digests are in versions.env.
The suite modules and configured runner remain upstream code.

Run from the Auth repository after installing its pinned dependencies:

```sh
node tests/conformance/run-auth.mjs conformance-current-results
```

This starts actual Auth protocol routes in Workerd with disposable D1,
provisions two independent ES256 private-key client fixtures selecting RS256 ID/access tokens, and proves a real
bound-email identity through a fake mail edge. Fixture provisioning does not
establish owner-approved app linking. That operation still requires Base's app-linking APIs.
The fixture waits for the actual advertised signing-key publication interval.

The actual plan attempts use Auth's code/PKCE, private_key_jwt, scoped access
tokens/UserInfo and managed ES256/RS256 profile. Basic and backchannel select
the provider's private_key_jwt profile. The plans' fixed secret authentication
conflicts with that selection; refusals must remain visible. An unchanged Basic
static plan also generates positive requests without required PKCE. It needs a
wider protocol decision and browser automation before it can certify Auth.
Config reads actual Auth discovery. The native suite configuration declares
`rer_interfaces` through `server.allow_unexpected_metadata_fields`, because
Base requires that legitimate extension for version negotiation. An unannotated
run reports a schema WARNING for it; no failed protocol
condition, module or structural validation is suppressed. No refresh token, logout endpoint, alternate
client authentication method or certification claim is added. Terminal module results, warnings, reviews,
and literal plan refusals must be reported individually.

Docker Compose, Python 3, Git, OpenSSL and network access are required. The
local HTTPS fixture listens on port 19443; the suite owns ports 8443/8444.
Existing listeners on those ports must belong to another run and must not be
stopped by this command. The harness writes restricted evidence archives outside
successful checkouts.

Raw results can include private client keys, tokens and cookies. Keep result
folders and generated configuration outside Git and restrict their permissions.
The default conformance-current-results folder is ignored. If generating a
separate static configuration, use an absolute private directory outside this
checkout. Publish only a redacted report, never raw module exports.

The wrapper stops its HTTPS server and Workerd runtime and removes its private
fixture directory. The suite stops only its own Compose project and records
remaining containers, volumes and networks in cleanup.json. Auth teardown is
recorded separately in auth-cleanup.json. Inspect both receipts; process exit
alone establishes neither cleanup nor certification.
