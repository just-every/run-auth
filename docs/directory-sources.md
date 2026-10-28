# Reviewed inbound directory sources

Open **People → Move people in → Directory sources** with an administrator passkey. Confirm your email in this browser before connecting, approving or disabling a source. Source credentials only submit or read observations; they cannot sign in, approve changes, merge identities by email or acquire administrator rights.

## Connect a source

Choose **Connect a directory source**, a name, provider and connection direction. Select only the fields this source should own: name, department, title and location. Existing manual and HR values retain their higher precedence. Organization binding and custody are rechecked before observations or approved work can proceed.

- **Okta:** use the exact organization HTTPS origin as both base URL and organization binding, with an authorized API token. Auth reads paginated users, groups and membership, including explicit deprovisioned records.
- **Microsoft Entra ID:** use the exact tenant ID as organization binding. Supply private JSON containing `clientId` and `clientSecret`. Auth exchanges the sealed credential for a Graph token on every pull and verifies the authenticated organization before reading users, groups and membership. A supplied bearer token is also supported, with its expiry remaining the operator’s responsibility.
- **Google Workspace:** use the immutable customer ID as organization binding and an authorized Directory API bearer token. Google OAuth sign-in credentials alone do not establish directory delegation.
- **Generic SCIM pull:** supply the SCIM base URL, its exact HTTPS origin as binding and a scoped bearer token.
- **Generic SCIM client:** choose **Receive a generic SCIM client** and bind it to this Auth issuer, including the employer path when applicable. Leave the remote URL and credential empty. Copy the one-time scoped credential and endpoint before leaving the page. Auth stores only its digest.

Redirects, private network destinations, foreign pagination and partial provider failures are refused. Nested groups, external members and unresolved member IDs currently refuse the snapshot rather than silently dropping membership. Polling stages observations every fifteen minutes; it never approves them.

## Review and apply

A new observation does not change the native directory. Open **Review changes** and inspect person fields, lifecycle and group membership effects. The preview binds the exact snapshot, current target state, source revision and administrator. A stale preview cannot commit. Imported identities use a connector-specific immutable source ID; an unknown ID at an existing email remains a collision.

Choose **I approve these exact directory changes**. Incomplete, empty or destructive observations also require separate held-change confirmation. The native planner applies the approved effects, retains stable person IDs, respects source ownership and protected-account rules, and fences an explicitly deactivated worker’s sessions. Each step records its application with the native write, so interrupted approved work can resume without creating another person. A full snapshot omitting people never means those people left.

The inbound SCIM profile supports Users and Groups reads, creates, replacements, bounded patches and deletes. Responses describe received source observations and identify the pending snapshot in `X-Auth-Directory-Snapshot`; receipt does not claim an applied native change. Repeated identical observations retain the same snapshot. Another connector’s token, a browser cookie or a disabled custodian cannot use the ingress credential.

Disabling a source destroys its stored credential and ingress digest and stops polling and pending authority. Credentials, observation snapshots and pending approvals are excluded from portable archives; review retained source bindings before establishing replacement custody; automatic reconnection is not supported. No invitation, outbound reminder or destructive approval is implied by source registration.

AUTH-SCIM-002 remains partial: complete live provider qualification, pushed application timing and automatic full-reconciliation timing are unproved; Google Workspace directory delegation is not held. Stale-source follow-up for other profiles, all outbound reminders and unsupported membership profiles remain explicit gaps. Existing exact per-file approval protections inherited from AUTH-HRIS-002 govern scheduled application of approved work.

## Generic SCIM freshness

A generic SCIM pull source tracks its last successful authenticated observation separately from its snapshot content. An unchanged read updates liveness and the next scheduled read, without replacing a snapshot or approving any pending changes. Failed partial enumeration cannot refresh liveness. Valid empty or destructive observations retain their existing confirmation holds.

A failed read or an observation overdue against the existing fifteen-minute schedule creates one durable source-bound follow-up episode. The source card shows the registered custodian, the read error and the next action: check the credential and connection, then read the directory again. Activity links the episode back to its source. Restart and repeated maintenance retain the same episode. A successful observation closes it; disabling the source or ending its registered custodian's authority cancels it with a recorded reason and retained history. Restoring that person's authority does not revive the old source credential.

These freshness records are visible work only. Neither global follow-up consent nor HR source-owner reminder consent authorizes a directory reminder. Scheduled and early sends are refused for these records, and their ownership and schedule follow the source rather than manual follow-up reassignment. No reminder, approval, inferred departure or provider qualification follows from a freshness state.
