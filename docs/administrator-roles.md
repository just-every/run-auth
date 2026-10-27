# Scoped administrator roles

Scoped human administration uses the same passkey and local-email sessions as
Auth. Each organization has its own `ctx.db`; role definitions, grants, cases,
previews and directory reads stay in that selected database. A scoped grant
never changes `oa_operators.role`. Existing directory/signing owner/admin-only doors continue to
require their existing authority. Admin service custody has its own scoped
permission gate. A scoped administrator uses the dedicated
`/api/auth/roles` doors below.

Every read requires a live hardware-passkey session (`hwk`). People and audit
exports additionally require fresh local email and are audited writes. Every write,
including filing a preview and recording case verification, also requires local
email confirmation on that same session within ten minutes. Committing SQL
checks live session methods/version, status, expiry, local-email age and an
authority epoch. Directory membership/attribute changes, role/grant revisions,
app changes, case changes and factor changes advance that epoch. A changed
preview must be prepared again. D1 batches atomically claim an unpredictable
operation marker, perform its guarded changes and store detailed activity.

## Published built-in roles

The permission catalogue is returned by `GET /api/auth/roles` and exported in
`src/auth/roles/permissions.mjs`. Built-ins use exactly the same permissions and
resource sets as custom roles; their definitions are fixed.

| Role id | Rank | Permissions |
| --- | ---: | --- |
| `owner` | 100 | All published permissions; the legacy owner holds all resources implicitly |
| `identity-administrator` | 80 | All published permissions except `roles.edit` and `admin-api.manage` |
| `security-policy-administrator` | 80 | `roles.view`, `roles.grant`, `people.view`, `people.export`, `policy.manage`, `identity-providers.manage`, `audit.view`, `audit.export`, `cases.view` |
| `app-administrator` | 50 | `roles.view`, `roles.grant`, `apps.view`, `apps.edit`, `apps.assign` |
| `group-owner` | 0 | `roles.view`, `people.view`, `groups.view`, `groups.edit`, `groups.rules.edit` |
| `manager` | 0 | `roles.view`, `people.view`, `groups.view` |
| `app-owner` | 0 | `roles.view`, `apps.view`, `apps.assign` |
| `help-desk` | 20 | `roles.view`, `people.view`, `people.sessions.end`, `people.factors.reset`, `groups.view`, `cases.view`, `cases.open`, `cases.verify`, `recovery.approve`, `people.suspend`, `people.restore` |
| `auditor` | 10 | `roles.view`, `people.view`, `people.export`, `groups.view`, `apps.view`, `cases.view`, `audit.view`, `audit.export` |
| `employee` | 0 | No administration permissions; ordinary employee profile doors continue to apply |

Built-in administrator ranks are immutable and defined once in
`src/auth/ranks.mjs`: owner 100, installation administrator 90, identity and
security/policy administrators 80, app administrator 50, help desk 20, auditor
10. Group owner, manager, app owner and employee have administrator rank 0.
Their ordinary group/app decisions remain permission- and resource-scoped;
rank does not make them administrators or block help-desk recovery.

Rank grants no permission or resource access. Authorization checks the selected
organization boundary, published permission, view/edit resource set, then rank
for administration of an account. Viewing uses view scope without a rank fence.
The account fence covers profile, status, factors, recovery approval, roles,
sessions and exports of that person's data. Equal or higher accounts cannot be
administered; this does not prohibit everyday app/group decisions.

Legacy `admin` has implicit rank 90 and all published permissions/resources.
The published `admin-api.manage` permission permits scoped credential custody.
A custom custodian creates and revokes their own service apps through Roles;
only legacy owner/admin custodians may reassign a service to another person.
Every credential's named resources and scopes must fit one current role grant,
including its view/edit limits. Scoped credentials require explicit resource IDs
and cannot use all-resource wildcards or organization-wide policy/provider
scopes. Tokens and native decisions recheck the accountable person's current
permissions, rank and resources. Sponsor loss, role revision, scope loss,
suspension or revocation ends authority; stored machine scopes never substitute
for the human owner's current authority. No scoped owner grant can be issued: delegation must be strictly below the
issuer's rank. Custom role ranks are integers 1–89, strictly below the chooser's active rank,
with permissions no wider than the chooser can delegate. The chooser is the
installation owner, an installation admin within an installation-operated
organization, or that organization's owner. In the current isolated employers,
only the employer owner may create or revise custom role definitions; the
installation itself also permits its own legacy owner/admin. Built-ins cannot be changed.
Revising a custom role invalidates its previous authority grants; explicitly
grant the new revision to restore intended authority. Any unrevoked assigned
administrator role still protects its holder's account while suspended, after
its sponsor loses authority, or while a revised grant has no active authority.
Explicitly revoking the assignment removes its rank contribution. Conversely,
an inactive high-rank assignment grants its holder no authority to administer
others through a lower active role.

## Resources and delegation

A grant has separate `view` and `edit` objects. Each contains arrays named
`people`, `groups`, `apps`, `cases`. Missing arrays are empty. `['*']` grants all
resources of that kind; it cannot be combined with other ids. Every edit array
must be a subset of the corresponding view array.

People can be selected directly or through groups. Viewing a person requires
one matching view selector. Editing requires a matching edit selector **and
every current group of that person inside the same grant's edit groups**.
Thus a help desk holder may view group B but edit only A; a person belonging
to both A and B cannot be edited. An account-administration action refuses the actor
and people of equal or higher administrator rank. People export uses edit
scope and the same account fence; ordinary viewing still uses view scope.
App/group assignments are ordinary decisions and do not inherit that fence. Factor reset is
stricter: it refuses every legacy or scoped administrator, even a lower one.

Membership is evaluated on every decision using the existing directory's
normalized attribute rules, effective source precedence, manual memberships
and explicit exclusions. Stale materialized rule memberships do not retain
access after a source attribute changes. Source changes therefore affect the
next decision without waiting for a job.

Delegation requires `roles.grant`, a strictly lower role, a strictly lower
recipient, and no recipient group outside the issuer's edit groups. The new
role's permissions and all resource arrays must be subsets of **one** held
grant; combining unrelated grants cannot create wider authority. App/case-only
delegation to an ungrouped recipient does not require directory access. All
named resources must exist in this organization. Scoped delegation records
its sponsoring grant. Revoking that sponsor, changing its role revision, or
removing its issuer's authority ends descendants at their next decision.
A legacy grant issuer must remain an active owner/admin.

Example: view A and B, edit A, no export permission:

```json
{
  "kind": "grant",
  "personId": "help-desk-person",
  "roleId": "help-desk",
  "resources": {
    "view": {"groups": ["A", "B"]},
    "edit": {"groups": ["A"]}
  }
}
```

Permissions do not imply one another. In particular `people.view` never grants
`people.export`. App permissions apply to the workforce `auth_apps` resource.
A case grant permits viewing/recording that review only; it does not authorize
people profile edits, factor reset or administrator recovery.

## HTTP API

POST paths below are relative to `/api/auth`. All POST bodies are JSON with
the selected issuer's `Origin` header and session cookie. The runtime parses
its ordinary bounded input before calling `roleAction`.

| Door | Request / result |
| --- | --- |
| `GET /api/auth/roles` | Permission catalogue, built-ins/custom roles, visible grants, own grants/rank, scoped groups/apps/cases, epoch |
| `GET /api/auth/roles/people` | Scoped people with fields, visible group ids and edit/reset capabilities; optional `personId`, `groupId`, `q` filters |
| `GET /api/auth/roles/export` | JSON attachment of scoped people; independently requires `people.export` and records export activity |
| `POST /roles/preview` | One change below; returns `previewId`, exact `plan`, `epoch`, ten-minute `expiresAt` |
| `POST /roles/apply` | `{ "previewId": "..." }`; commits the unchanged preview once, bound to its actor **and session** |
| `POST /roles/end-sessions` | `{ "personId": "...", "reason": "..." }`; `people.sessions.end`, current edit resources and a strictly lower account rank |
| `GET /api/auth/session-control?personId=...` | Latest 20 session-control operations for an editable lower-ranked person; hardware passkey and `people.sessions.end` |
| `POST /roles/reset-factors` | `{ "personId": "...", "reason": "...", "caseId": "optional" }` |
| `POST /roles/profile` | `{ "personId": "...", "fields": { "title": "..." } }`; typed manual-source directory edits; null clears the manual value |
| `POST /roles/group` | `{ "groupId": "...", "personId": "...", "action": "add" }` or `remove`; rule removals create exclusions |
| `GET /api/auth/roles/audit` | Scoped role activity summaries; `audit.view` |
| `GET /api/auth/roles/audit/export` | Scoped activity JSON attachment; `audit.export` and fresh local email |
| `POST /roles/command` | `{ "action": "/company-apps/update", "params": { "id": "..." } }`; explicit native commands below |
| `POST /roles/admin-service` | `{ "action": "existing admin-service action", "params": {} }`; scoped self custody; legacy owner/admin may reassign |
| `POST /roles/app` | `{ "appId": "...", "name": "optional", "enabled": true }`; rename or enable/disable the assigned app |
| `POST /roles/recovery-case` | Open, verify or close a case as described below |

Preview kinds:

```json
{"kind":"role","role":{"name":"Regional help desk","rank":15,"permissions":["roles.view","people.view","people.factors.reset"]}}
```

An optional `role.id` revises an existing custom role. Grant previews use the
resource example above. Revoke previews use
`{"kind":"revoke","grantId":"..."}`. Apply takes only the saved preview id;
changing role, grant, recipient, membership or relevant directory state between
preview and apply returns a conflict instead of applying a revised effect.
Detailed audit stores the exact plan and its prior role/grant state. The
`effects` array lists each affected person and their actual `gained` and `lost`
actions by permission and current resource id. It accounts for overlapping
grants, role-revision invalidation and transitive sponsor revocation.

A profile edit reuses directory type validation, source precedence and rule
membership calculation; it refuses changes that move the target outside the
holder's edit scope. It emits existing directory/provisioning events. Group
changes also create the ordinary provisioning obligations. App changes bump
the app version and reconcile ordinary provisioning.

Recovery review cases are distinct from administrator recovery:

```json
{"action":"open","personId":"employee-person","reason":"Employee reported a lost passkey"}
```

Open requires `cases.open` and an editable non-administrator target. It returns
a generated `caseId`, which an owner/admin can delegate as a case resource.
An assigned verifier submits:

```json
{"action":"verify","caseId":"...","verification":{"method":"Live identity check","reference":"Internal case reference"}}
```

Verification requires `cases.verify` and `recovery.approve`, an explicit nonempty method/reference,
a current hardware session and fresh local email. It records the verifier and
session. `{"action":"close","caseId":"..."}` closes the review. These
operations never approve an `auth_recoveries` request, shorten its waiting
period or enroll replacement factors. If supplied to factor reset, the case
must be verified, match the person, and be viewable by the resetter; ordinary
people reset permission and edit scope remain mandatory.

A successful factor reset deletes the non-administrator's passkeys, increments
identity version, revokes every session, cancels pending ordinary recovery,
records notices for the affected sessions, sends an email notice, and fences
linked apps. It returns no factors, tokens or session secrets. The employee
uses ordinary email sign-in and enrollment next. Administrator recovery stays
on the existing protected recovery doors.

## Native scoped commands

`POST /api/auth/roles/command` accepts an `action` and `params` object. The
model publishes the exact action registry. These are human session commands;
admin service tokens and preparer keys never enter this route. Existing machine
scope exclusions and credential/accountability rules are unchanged.

| Permission | Commands |
| --- | --- |
| `apps.edit` | `/company-apps/create`, `/company-apps/update`, `/company-apps/remove`, `/catalog/add`, `/oidc-apps/create`, `/oidc-apps/update`, `/oidc-apps/rotate-secret`, `/provisioning/connect`, `/provisioning/rotate`, `/provisioning/disconnect` |
| `apps.assign` | `/company-apps/assign`, `/company-apps/unassign` |
| `groups.edit` | `/groups/create`, `/groups/delete` |
| `groups.rules.edit` | `/groups/rule` |
| `people.suspend` / `people.restore` | `/people/suspend` / `/people/restore` |
| `policy.manage` | `/policy/domain-rule` |
| `identity-providers.manage` | `/identity-providers/availability` |

App creation requires wildcard edit app resources. Existing app configuration,
credentials and connectors require the named app; SAML configuration uses the
existing complete native settings payload. OIDC updates merge existing public
settings with submitted redirect/JWKS/logout/PKCE/algorithm settings, validate
through the existing client settings validator, and preserve the authentication
method; a method change needs a new credential ceremony. OIDC creation and
rotation preserve the existing one-time secret display and digest-only storage.
The scoped audit records action/resource identifiers, never submitted secrets.

Assignments use explicit `appId`, `principalType` (`person` or `group`) and
`principalId`; form shorthand is refused. Both app and principal must be inside
the holder's edit resources, and every affected person must meet the rank and
all-group rule. Conflicting resource ids are refused. Group creation requires
wildcard edit groups; delete and rule changes check every current and newly
affected person. Rule normalization, lifecycle planning, events and provisioning
remain the existing native implementations. Policy/provider availability
commands require wildcard people, groups and apps since their effects are
organization-wide. Provider changes only enable/disable already configured
providers; they cannot replace provider identity or server credentials.

`recovery.approve` applies to explicit scoped case verification, never to an
administrator recovery request. `admin-api.manage` authorizes only the
credential custody covered by the person's current permission/resource grant;
it never bypasses machine scope exclusions or permits wider automation.

## Integration and schema

`src/auth/roles/index.mjs` exports `ROLE_READS`, `roleModel(ctx,s)`,
`isRoleAction(path)`, `roleAction(ctx,request,path,data)`,
`roleRead(ctx,request,path)` and
`requireRolePermission(ctx,s,permission,{personId,appId,groupId,caseId,write})`.
The last function returns `{clause,args,state}`. A future caller **must append
that clause and args to its committing SQL**, or atomically claim an operation
under the guard before a transactional batch. An earlier JavaScript permission
check alone is insufficient. `write` defaults from the permission catalogue.
Ordinary reads need hardware; exports also require fresh email. No alternate admin cookie,
API key, role column value or machine token is accepted by these doors.

Migration `0039_auth_roles.sql` adds custom definitions (`auth_roles`), scoped
memberships (`auth_role_grants`), saved exact previews (`auth_role_previews`),
review cases (`auth_role_cases`), transaction claims (`auth_role_operations`),
detailed audit (`auth_role_events`) and the triggered authority epoch
(`auth_role_epoch`). Ordinary Activity receives the same committed events and
details. It adds no user-facing secrets and changes no existing role column.

The shared `ranks.mjs` helpers also fence the legacy suspend/role and recovery
approval doors, and directory profile/lifecycle writes through their common
native planner. The directory transaction claims the effective human owner's
rank and the current authority epoch before applying any statement, including
machine calls; its own epoch changes cannot leave a partially applied plan.
The ordinary employee's own profile and self-session controls remain separate
self-service actions. Recovery of an equal/higher administrator follows the
existing delay or emergency mechanism; a lower administrator cannot approve it.

## End all sessions

People provides a Sessions dialog on each eligible person. Scoped help desk
uses Session control under People in your scope on Roles. The published
`people.sessions.end` permission is separate from factor reset, suspension,
app administration and directory viewing. Built-in help desk and identity
administrator roles include it. Custom roles must include it explicitly.

The action needs a recorded single-line reason, hardware passkey and local
email confirmation in the last ten minutes. Auth rechecks session methods,
version, active status, expiry, email proof and the role authority epoch when
claiming the transaction. The person must be strictly lower-ranked and all of
their current groups must fit one held grant's edit scope. The actor cannot
end their own sessions through this administration door; self-service sign
out remains available separately.

The same transaction records the actor and reason, revokes every native Auth
session and refresh family, and queues supported linked-app and general OIDC
back-channel deliveries. It changes no account status, identity version,
passkey, group membership or app assignment. Old browser authority, pending
codes tied to ended sessions and refresh credentials stop at their next
request. A retained passkey can establish a new session normally.

The receipt records Auth session and refresh grant counts. Back-channel
counts distinguish pending, delivered, failed and unavailable. Delivered
means the endpoint accepted the signed logout; it never establishes remote
session completion. Restart resumes durable delivery queues under the
existing retry policy. A refusal or exhausted delivery remains failed, and
an unavailable endpoint cannot be reported delivered. Only current holders
of the same session-management authority can read a person's receipts.

This native action does not qualify vendor session-revocation APIs, vendor
readback, desktop or mobile clients, downstream timing, unsupported manual
resolution, password reset, factor-review policy or notification delivery.
Those remain explicit AUTH-LOGOUT-002 obligations.
