# Access decisions and certification

Account shows a person's owned groups, requests they made or must decide, and
review items assigned to them. Activity gives hardware administrators the same
records with review scheduling, delegation, privilege classification and exports.

Each membership, request approval/denial and review decision requires a new
user-verified passkey assertion. Its challenge binds the actor, browser session,
reason, exact target/effect and observed state. It expires after fifteen minutes,
is single-use and cannot be transferred between sessions or employers. Commit
rechecks live membership, reviewer/decider authority, separation of duties,
resource state and the authorization epoch in the mutation transaction.

Group owners can edit ordinary membership without local email confirmation.
An administrator acting as a group owner still needs the administrator gate.
Self-addition and self-certification are refused. Reviewers certify, reduce or revoke
existing access; neither action creates a privileged grant. Administrator recovery
continues through its existing, higher-rank hardware/fresh-email door.

App classification defaults to privileged. Only an owner/administrator with a
hardware passkey and fresh local email confirmation can classify an app ordinary,
or mark a group privileged. Every group assigned to a privileged app inherits that
classification. An exact app-role classification overrides the app default; changing it invalidates offered decisions. Ordinary group owners cannot downgrade it.
The same administrator gate protects request policies. Review scheduling, delegation and exports additionally require their published scoped review permission. These conservative defaults await CT approval.

## Temporary requests

An administrator explicitly names an independent decider for an app and sets a
maximum duration (at most thirty days). An employee signs in with a passkey,
submits an exact app role, purpose and duration with a decision-bound UV passkey assertion, and the decider signs that exact
request. A policy revision invalidates older pending requests. An approval cannot
overwrite a standing direct assignment. Only the approved direct assignment is
created; expiry removes that exact assignment and queues SCIM revocation. If
another path still grants access, or remote removal cannot be verified, the
request remains `revocation_pending`. Provider acknowledgment alone never closes
it. A requester can cancel a pending request; nobody can approve their own.

This is a native request/decision foundation, not the full AUTH-REQUESTS-001
Salesforce/AWS qualification. Multi-stage manager/app/security routing, extension
and emergency policies and Slack/Teams carriers
remain unbuilt. Authorized Salesforce and AWS role/elevation tenants are still
required for the live journeys.

## Quarterly reviews

A scheduled review snapshots employee, contractor and service identities, app
assignment roles and their direct/group source, membership, last observed passkey
use and provider freshness. App usage without a real source is labelled unknown.
Snapshots are never rewritten by later directory changes. The current view shows
drift and newly observed access separately. Holders of the published reviews.manage permission can delegate an
undecided item to a different active person; self-review is refused.

Certification records the reason and exact deciding actor. Revocation places an
app-specific denial across both direct and group assignment paths immediately,
then queues remote removal. Other apps granted by the same group stay available.
The review can close only when every original item is decided and every removal
is read-back verified. Missing connectors and failed removals remain explicit in
the export. It never claims SOC 2 certification.

An administrator publishes app roles in an explicit authority order before a
reviewer can reduce one. The saved per-person cap follows direct and group grants
through SAML, OIDC, provisioning and resource checks. A changed hierarchy closes
capped access until an administrator explicitly clears or reconfirms it; no
unknown ordering is guessed. Role-sourced mapping/hook output cannot restore the
higher role. Reduction remains unfinished until provider read-back confirms it.

Recurring snapshots stop when their accountable administrator or named reviewer
loses authority. Deadlines and new quarterly snapshots survive restart. The shared
follow-up policy can explicitly select the current reviewer as a decider recipient.
With that consent, business-calendar reminders follow delegation; absent reviewers
and overdue items escalate only to the policy's currently approved administrators.
Attempts are durable before transport, so an interrupted send cannot replay after
restart. A completed decision stops its reminders. Mail never certifies access.

Generic review obligations and request/stale-source reminders remain
AUTH-FOLLOWUP-003. The published reviews.view, reviews.manage and reviews.export permissions follow the same person/app view and edit scopes as other roles. Scheduling, delegation and export require hardware and fresh local email; exporting a campaign containing resources outside the exporter’s scope is refused in full. Recurrence stops when its creator loses the permission.

A campaign may explicitly include Auth administrator roles and grants. Their fixed snapshot preserves exact permissions, resources, sponsor and role revision. An independent reviewer may certify them; revoking them requires the existing role/rank authority and administrator proof. Owner removal and guessed native role reductions are refused. Auth verifies its own revocations locally and ends recipient sessions.

Future password/policy versions inherit these evidence requirements before shipping. The adopted hierarchy, delegation and scoped management defaults await CT approval.
