import type { AuthPageModel, DelegatedTask } from '../model.js'
import { escape, emptyState, timeElement } from '../helpers.js'

const open = (task: DelegatedTask): boolean => ['requested', 'consented', 'approved'].includes(task.state) && task.authorityCurrent
const reviewLink = (id: string): string => `/app/account?delegation=${encodeURIComponent(id)}`

function reversalControls(grant: DelegatedTask): string {
  if (grant.reversalRequest) return `<p data-reversal-state>Reversal requested. The assignment stays unchanged until an authorized employer administrator reviews it through the ordinary app-assignment controls.</p>`
  return grant.canRequestReversal ? `<form method="post" action="/api/auth/delegations/reverse" data-auth-action data-reload="true"><input type="hidden" name="grantId" value="${escape(grant.id)}"><button class="secondary-button">Request reversal</button><p>This asks an employer administrator to review a reversal. It does not undo the assignment or give the agent new authority.</p></form>` : ''
}

function taskReview(model: AuthPageModel): string {
  const grant = model.delegation
  if (!grant) return ''
  const task = grant.task
  const facts = [
    ['Person', grant.personEmail ?? grant.personName ?? task.personId], ['Employer', grant.organizationId],
    ['Agent', grant.agentName ?? 'Registered task agent'], ['Purpose', task.purpose],
    ['App', grant.appName ?? task.appId], ['Assignment change', `${grant.before.role ?? 'No role'} → ${grant.after.role}`],
    ['Target API', task.audience], ['Scope', task.scopes.join(', ')], ['Deadline', new Date(grant.expiresAt).toISOString()],
  ]
  const consent = grant.canConsent ? `<button class="primary-button" type="button" data-delegation-consent="${escape(grant.id)}" data-effect-digest="${escape(grant.effectDigest)}">Consent to this task</button>` : ''
  const approve = grant.canApprove ? `<button class="primary-button" type="button" data-delegation-approve="${escape(grant.id)}" data-effect-digest="${escape(grant.effectDigest)}">Approve this task with passkey</button>` : ''
  return `<section class="panel row-panel issuer-host" data-delegation-review><h2>Review delegated task</h2><p>The agent may make this one assignment change. New purpose, scope, target or resource needs a new request and consent.</p><dl class="effect-list">${facts.map(([label, value]) => `<div><dt>${escape(label)}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl><p>State: <strong data-delegation-state>${escape(grant.state)}</strong>${grant.authorityCurrent ? '' : ' · Authority ended or changed; this task cannot run.'}</p><h3>Required approvals</h3><ul>${grant.requiredApprovals.map(value => `<li>${escape(value)}</li>`).join('')}</ul><p>Consent signs this exact task with your passkey. Administrator approval also needs a passkey and email confirmation in this browser within ten minutes. <a href="/app/methods#email-confirmation">Sign-in methods</a></p><div class="button-row">${consent}${approve}</div><h3>Revocation reach</h3><p>${escape(grant.revocationReach.local)} ${escape(grant.revocationReach.completedEffect)} ${escape(grant.revocationReach.downstream)}</p>${reversalControls(grant)}</section>`
}

export function delegatedTasksPanel(model: AuthPageModel): string {
  const inventory = model.delegations
  if (!inventory) return ''
  const rows = inventory.grants.map(grant => `<div class="data-row issuer-host" data-delegated-task="${escape(grant.id)}"><div><strong>${escape(grant.agentName ?? 'Task agent')} · ${escape(grant.appName ?? 'Assigned app')}</strong><p>${escape(grant.task.purpose)}</p><p>${escape(grant.personEmail ?? grant.personName ?? '')}</p><p>Expires ${timeElement(grant.expiresAt)} · <span data-task-state>${escape(grant.state)}</span>${grant.authorityCurrent ? '' : ' · Not authorized'}</p></div><div class="button-row"><a class="secondary-button" href="${reviewLink(grant.id)}">Review task</a>${model.delegation?.id===grant.id?'':reversalControls(grant)}${open(grant) ? `<form action="/api/auth/delegations/revoke" method="post" data-auth-action data-reload="true" data-confirm="Revoke this task? Its next request is refused; a completed assignment is not undone."><input type="hidden" name="grantId" value="${escape(grant.id)}"><button class="danger-button">Revoke task</button></form>` : ''}</div></div>`).join('')
  return `${taskReview(model)}<section class="panel row-panel" data-delegated-tasks><h2>Delegated tasks</h2><p>Your explicit task grants stay separate from your sign-in sessions and agent preparer keys. An employer owner can review the organization's tasks.</p>${rows ? `<div class="data-list">${rows}</div>` : emptyState('No delegated tasks.')} ${inventory.hasMore ? `<p><a href="/app/account?before=${encodeURIComponent(inventory.nextCursor ?? '')}">Older tasks</a></p>` : ''}</section>`
}

export function delegatedAgentsPanel(model: AuthPageModel): string {
  if (model.user?.role !== 'owner' || !model.delegationApps || !model.delegations) return ''
  const agents = model.delegations.agents.map(agent => `<div class="data-row issuer-host"><div><strong>${escape(agent.name)}</strong><p>Client ID: ${escape(agent.clientId)}</p><p>${escape(agent.state)} · expires ${timeElement(agent.expiresAt)}</p></div>${agent.state === 'active' ? `<form action="/api/auth/delegations/agents/suspend" method="post" data-auth-action data-reload="true" data-confirm="Suspend this agent and end all its unfinished tasks?"><input type="hidden" name="clientId" value="${escape(agent.clientId)}"><button class="danger-button">Suspend task agent</button></form>` : ''}</div>`).join('')
  const people = (model.people ?? []).filter(person => person.role === 'member' && person.status === 'active')
  return `<section class="panel row-panel" data-task-agent-registration><h2>Task agents</h2><p>Register a public signing key and the exact employees and apps this agent may request. Each task then needs that employee's consent and a different employer owner's or administrator's passkey approval. The agent's custodian cannot approve.</p>${agents || emptyState('No task agents registered.')}<form class="directory-form" data-delegated-agent-register><label class="field">Agent name<input name="name" maxlength="80" required></label><label class="field">Agent task purpose<input name="purpose" maxlength="500" required></label><label class="field">Task agent public JWKS<textarea name="jwks" rows="5" required></textarea></label><p>Generate and retain the private key in your agent. Paste only public signing keys.</p><div class="directory-fields"><label class="field">Allowed apps<select name="appIds" multiple required>${model.delegationApps.map(app => `<option value="${escape(app.id)}">${escape(app.name)}</option>`).join('')}</select></label><label class="field">Accountable employees<select name="personIds" multiple required>${people.map(person => `<option value="${escape(person.id)}">${escape(person.email)}</option>`).join('')}</select></label></div><label class="field">Agent registration expiry<input name="expiresAt" type="datetime-local" required></label><button class="primary-button">Register task agent</button><p data-task-agent-result role="status" class="issuer-host"></p></form></section>`
}
