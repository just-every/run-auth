# Auth’s shared agent door

An identity steward discovers the supported jobs at `/mcp` with `server/discover`.
The production Worker serves the shared Base door before Auth sign-in or setup
redirects. `/agents` shows the company policy, approvals, review and agent audit.
The transport supports MCP 2026-07-28 and 2025-11-25. Text in directory records,
app metadata and imported names is untrusted data, never authority.

This adoption declares a bounded core: inspect redacted identities and internal
static groups, create an empty group, add or remove an existing identity’s internal
membership, inspect the sponsor’s launcher and read scoped redacted activity.
`auth.workspace.snapshot` fingerprints the visible native records for verification.
`auth.groups.grants` inspects one membership. `auth.events.list` is the shared
retained decision-event reader. It does not claim the complete Auth lifecycle
subscription or downstream reconciliation surface.

The read tools carry `standard`; membership changes carry `access`, with direction
computed by the server. An empty group does not grant access. A membership touching
a configured SCIM connector refuses with `connector_door_required`; any other
app-assigned group refuses with `app_assignment_door_required`. Rule-driven groups also refuse with `dynamic_group_door_required`. Active claim or subject mappings that read a group also refuse with `app_mapping_door_required`, even without a group assignment. A group-list projection or computed group lookup can read every group, so membership changes wait for the native app door while it is active. These are native
app-access and computed-membership jobs beyond this internal-group subset, including indirect outside
exposure. Refusal happens before queueing provider work. No money, paid account, regulated profile data, credential, issuer,
provider, recovery, installation or identity-admission action is exposed. There is
no provider cost registration; spend is `none`. There is no agent Undo because
membership removal is a separate native action rather than a historical reversal.

The tools call the same Auth directory commands and role/resource/rank checks as
the native machine API. A Business token is never a human session or passkey.
Signed Business settings bind `owner_id` to the installation’s setup owner id and
team ids to already admitted native people. The roster cannot create, activate,
promote or invite an identity. Conflicting roles or unavailable identities do not
bind. Omitted roster entries retain inactive bindings; subsequent address changes never select another native id. Removed or stopped bindings narrow current scopes and fence pending execution in the native transaction. A local admin
promotion does not make someone a Business policy editor. An owner must have
completed Auth’s email and passkey lifecycle before agent admission; Base’s setup
cookie alone is insufficient. A required upstream provider is not satisfied by a
Business token.

The company’s signed policy decides autonomous work, review, approval and blocks.
Native authority always applies. An agent cannot add its own sponsor to a new
group. Approval records retain the exact native target and summary; the real person
is the approver and the agent remains the preparer. Native Activity uses
`<agent> for <person>` and records the door operation id and named approvers.
Repeated keys retain one effect, changed arguments conflict, and every retry
passes current admission, scopes, revocation, Pause and policy again.

Use the `inspect-workforce` prompt to inspect the current people and groups, then
propose only an internal membership change allowed by the sponsor’s native role.
Use the existing Auth screens and protocols for identity admission, passkey proof,
app setup, recovery and provider work. The preparer and person-bound delegated-task
profiles keep their existing narrow purposes and do not become general MCP tokens.

The wider ct identity-steward table remains a target. Organization, request,
review, obligation, task and native lifecycle event resources, subscriptions,
multiple-sponsor journeys, provider jobs, SaaS onboarding, sign-in repair,
certification and workforce-week journeys are undeclared here. No full target
completion, hosted acceptance or external provider result follows from this core.

The runtime and conformance CLI are both pinned to Base’s released rer-v0.2.87 source,
`5381ab872b5ab4de80e811bcb4b1a803dd713e0f`. Verification claims only a fresh
production build with actual migrations and the signed claim, email and native
passkey lifecycle in `tests/agent-door/initialize-owner.mjs`.

Door audit, approvals, outcomes and signed bindings are installation-local and
excluded from archives. Native root erasure refuses with
`agent_custody_review_required` after agent evidence or signed bindings exist. A root installation with prior erasure journal evidence also refuses new pairing.
Its capture/erasure boundary stays closed until client mapping, evidence redaction
and retention are agreed; deleting a native person cannot silently preserve a
replayable result. Isolated employers have no shared door in this subset.
