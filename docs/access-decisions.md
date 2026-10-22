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
Self-addition and self-certification are refused. Reviewers certify or revoke
existing access; neither action creates a privileged grant. Administrator recovery
continues through its existing, higher-rank hardware/fresh-email door.

App classification defaults to privileged. Only an owner/administrator with a
hardware passkey and fresh local email confirmation can classify an app ordinary,
or mark a group privileged. Every group assigned to a privileged app inherits that
classification. The app classification covers all of its roles until an explicit
per-role privilege catalogue ships. Ordinary group owners cannot downgrade it.
The same administrator gate protects request policies, review scheduling,
delegation and evidence exports. These conservative defaults await CT approval.

## Temporary requests

An administrator explicitly names an independent decider for an app and sets a
maximum duration (at most thirty days). An employee signs in with a passkey,
requests an exact app role, purpose and duration, and the decider signs that exact
request. A policy revision invalidates older pending requests. An approval cannot
overwrite a standing direct assignment. Only the approved direct assignment is
created; expiry removes that exact assignment and queues SCIM revocation. If
another path still grants access, or remote removal cannot be verified, the
request remains `revocation_pending`. Provider acknowledgment alone never closes
it. A requester can cancel a pending request; nobody can approve their own.

This is a native request/decision foundation, not the full AUTH-REQUESTS-001
Salesforce/AWS qualification. Multi-stage manager/app/security routing, extension
and emergency policies, decision-bound request submission and Slack/Teams carriers
remain unbuilt. Authorized Salesforce and AWS role/elevation tenants are still
required for the live journeys.

## Quarterly reviews

A scheduled review snapshots employee, contractor and service identities, app
assignment roles and their direct/group source, membership, last observed passkey
use and provider freshness. App usage without a real source is labelled unknown.
Snapshots are never rewritten by later directory changes. The current view shows
drift and newly observed access separately. Administrators can delegate an
undecided item to a different active person; self-review is refused.

Certification records the reason and exact deciding actor. Revocation places an
app-specific denial across both direct and group assignment paths immediately,
then queues remote removal. Other apps granted by the same group stay available.
The review can close only when every original item is decided and every removal
is read-back verified. Missing connectors and failed removals remain explicit in
the export. It never claims SOC 2 certification.

Recurring snapshots stop when their accountable administrator or named reviewer
loses authority. Deadlines record overdue escalation, which survives restart.
Email reminder routing into AUTH-FOLLOWUP-003, reviewer absence/reassignment
policy, role reduction against a published app role hierarchy, scoped custom
review-management permissions and complete audit/policy-version packaging remain
unbuilt. The quarterly acceptance is therefore partial.
