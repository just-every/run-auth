import type { AgentEffect, AgentKey, AgentProposal, AuthPageModel } from '../model.js'
import { asArray, csrfField, emptyState, escape, noticeBox, timeElement } from '../helpers.js'

const kindNames: Record<string, string> = {
  suspend_person: 'Suspend a person', restore_person: 'Restore a person', invite_person: 'Invite a person',
  remove_invitation: 'Remove an invitation', add_domain_rule: 'Require a provider for a domain', remove_domain_rule: 'Remove a domain’s required provider',
}
const outcomeReasons: Record<string, string> = {
  approved: 'approved', stale: 'its target changed after filing', expired: 'it expired before approval', rejected_by_person: 'a person rejected it',
  second_administrator_required: 'it needs a second administrator', last_administrator: 'it would leave no administrator',
}
const kindName = (kind: string): string => kindNames[kind] ?? kind
const target = (effect: AgentEffect): string => effect.person?.email ?? effect.domain ?? 'Unknown target'

const endedReasons: Record<NonNullable<AgentKey['ended_reason']>, string> = {
  owner_suspended: 'its owner was suspended', owner_demoted: 'its owner is no longer an administrator',
  owner_changed: 'its owner’s role or status changed after it was minted',
}
const keyState = (key: AgentKey, now: number): string => key.revoked_at
  ? '<span class="status-pill suspended"><i class="status-dot"></i>Revoked</span>'
  : key.ended_reason ? '<span class="status-pill suspended"><i class="status-dot"></i>Ended</span>'
  : key.expires_at <= now ? '<span class="status-pill invited"><i class="status-dot"></i>Expired</span>' : '<span class="status-pill"><i class="status-dot"></i>Active</span>'

const keyForm = (action: string, key: AgentKey, label: string, kind: string, csrf?: string, confirm?: string): string =>
  `<form method="post" action="${action}" data-auth-action data-reload="true"${confirm ? ` data-confirm="${escape(confirm)}"` : ''}><input type="hidden" name="keyId" value="${escape(key.id)}">${csrfField(csrf)}<button class="${kind}" type="submit">${label}<span class="visually-hidden"> ${escape(key.label)}</span></button></form>`

const keyRows = (keys: AgentKey[], model: AuthPageModel, now: number): string => keys.length
  ? `<div class="data-list">${keys.map(key => {
    const live = !key.revoked_at && !key.ended_reason && key.expires_at > now
    const actions = live ? `<div class="button-row">${keyForm('/api/auth/agents/renew', key, 'Renew', 'secondary-button', model.csrf)}${keyForm('/api/auth/agents/revoke', key, 'Revoke', 'danger-button', model.csrf, `Revoke ${key.label}? The agent's next request is refused.`)}</div>` : '<span></span>'
    return `<div class="data-row" data-agent-key="${escape(key.label)}"><div><strong>${escape(key.label)}</strong><p>Accountable: ${escape(key.owner_email)}</p></div><div><span class="data-meta">Created ${timeElement(key.created_at)}. ${key.revoked_at ? `Revoked ${timeElement(key.revoked_at)}${key.revoked_by_email ? ` by ${escape(key.revoked_by_email)}` : ''}.` : key.ended_reason ? `Ended for good: ${endedReasons[key.ended_reason]}.` : `Expires ${timeElement(key.expires_at)}.`} ${key.last_used_at ? `Last used ${timeElement(key.last_used_at)}.` : 'Not used yet.'}</span> ${keyState(key, now)}</div>${actions}</div>`
  }).join('')}</div>`
  : emptyState('No agent keys have been minted.')

const proposalState = (proposal: AgentProposal): string => {
  const reason = proposal.outcome?.reason ? outcomeReasons[proposal.outcome.reason] ?? proposal.outcome.reason.replace(/_/g, ' ') : ''
  if (proposal.status === 'pending') return `<span class="status-pill invited" data-proposal-status="pending"><i class="status-dot"></i>Waiting for a person</span>`
  if (proposal.status === 'expired') return '<span class="status-pill suspended" data-proposal-status="expired"><i class="status-dot"></i>Expired</span>'
  if (proposal.status === 'done') return `<span class="status-pill" data-proposal-status="done"><i class="status-dot"></i>Done</span>`
  return `<span class="status-pill suspended" data-proposal-status="${escape(proposal.status)}"><i class="status-dot"></i>${proposal.status === 'failed' ? 'Failed' : 'Rejected'}${reason ? `: ${escape(reason)}` : ''}</span>`
}

const proposalRows = (proposals: AgentProposal[]): string => proposals.length
  ? `<div class="data-list">${proposals.map(proposal => `<div class="data-row" data-proposal-row="${escape(proposal.id)}"><div><strong>${escape(kindName(proposal.kind))}</strong><p class="email-text">${escape(target(proposal.effect))}</p></div><div><p>“${escape(proposal.reason)}”</p><span class="data-meta">Filed by ${escape(proposal.key_label)} ${timeElement(proposal.created_at)}.</span> ${proposalState(proposal)}</div><a class="secondary-button" href="/app/agents?proposal=${encodeURIComponent(proposal.id)}">Review<span class="visually-hidden"> ${escape(kindName(proposal.kind))} for ${escape(target(proposal.effect))}</span></a></div>`).join('')}</div>`
  : emptyState('No proposals have been filed.')

// One effect as a short list: who, what changes, and which apps and sessions it reaches.
const effectRows = (effect: AgentEffect): string => {
  const rows: Array<[string, string]> = []
  if (effect.person) {
    rows.push(['Person', `${effect.person.name && effect.person.name !== effect.person.email ? `${effect.person.name}, ` : ''}${effect.person.email}`])
    rows.push(['Change', `${effect.person.status ?? 'not in Auth'} → ${effect.after}`])
    if (effect.person.role) rows.push(['Role', effect.person.role])
    if (effect.activeSessions !== undefined) rows.push(['Active sessions', effect.after === 'suspended' ? `${effect.activeSessions}, all end` : String(effect.activeSessions)])
    if (effect.apps) rows.push(['Apps', effect.apps.length ? effect.apps.map(app => app.name).join(', ') : 'None'])
    if (effect.passkey !== undefined) rows.push(['Passkey', effect.passkey ? 'Registered' : 'None'])
    if (effect.invitationEmail) rows.push(['Email', 'One invitation email is sent'])
  } else if (effect.domain) {
    rows.push(['Domain', effect.domain])
    rows.push(['Required provider', `${effect.provider?.label ?? 'None'} → ${typeof effect.after === 'object' && effect.after ? effect.after.label : 'None'}`])
    rows.push(['People at this domain', effect.people?.length ? effect.people.map(p => p.email).join(', ') : 'None'])
  } else if (effect.app) {
    rows.push(['App origin', effect.app.origin])
    if (effect.app.name) rows.push(['App', effect.app.name])
    rows.push(['Change', effect.after === 'removed' ? 'Remove this app: it can no longer sign people in' : 'Link this app: people can sign in to it with Auth'])
    const notes = [effect.app.punycode ? 'Punycode origin' : '', effect.app.firstSeen ? 'First time Auth has seen this origin' : '', effect.app.replaces ? 'Replaces an existing link' : ''].filter(Boolean)
    if (notes.length) rows.push(['Check', notes.join('; ')])
  }
  return `<dl class="effect-list">${rows.map(([name, value]) => `<div><dt>${escape(name)}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl>`
}

const review = (model: AuthPageModel, proposal: AgentProposal): string => {
  const open = proposal.status === 'pending'
  const changed = proposal.unchanged
    ? noticeBox('Nothing about the target has changed since the agent filed this.', 'success')
    : noticeBox(`Changed since filing: ${(proposal.changed ?? []).join('; ')}. Approving now is refused as stale.`, 'error')
  const keyNote = proposal.key_ended_reason ? noticeBox(`The key ${proposal.key_label} has ended for good: ${endedReasons[proposal.key_ended_reason]}. A person can still approve or reject what it filed.`, 'info') : proposal.key_revoked_at ? noticeBox(`The key ${proposal.key_label} was revoked ${new Date(proposal.key_revoked_at).toISOString().slice(0, 10)}. A person can still approve or reject what it filed.`, 'info') : ''
  const decided = open ? '' : `<p data-proposal-outcome>${proposalState(proposal)}${proposal.decided_by_email ? ` by ${escape(proposal.decided_by_email)}` : ''}${proposal.decided_at ? ` ${timeElement(proposal.decided_at)}` : ''}.</p>`
  const actions = open
    ? `<div class="button-row review-actions"><form method="post" action="/api/auth/agents/reject" data-auth-action data-redirect="/app/agents?proposal=${encodeURIComponent(proposal.id)}"><input type="hidden" name="proposalId" value="${escape(proposal.id)}">${csrfField(model.csrf)}<button class="danger-button" type="submit">Reject</button></form><button class="primary-button" type="button" data-proposal-approve="${escape(proposal.id)}">Approve with passkey</button></div><p class="data-meta">Approving asks for your passkey and needs an email confirmation in this browser within the last ten minutes (<a href="/app/methods#email-confirmation">Sign-in methods</a>). It runs once, only if nothing above has changed.</p>`
    : decided
  return `<section class="panel proposal-review" aria-labelledby="proposal-heading"><div class="panel-header"><div><h2 id="proposal-heading">${escape(kindName(proposal.kind))}: ${escape(target(proposal.effect))}</h2><p>Filed by the key ${escape(proposal.key_label)} (accountable: ${escape(proposal.key_owner_email)}) ${timeElement(proposal.created_at)}. ${open ? `Expires ${timeElement(proposal.expires_at)}.` : ''}</p></div>${proposalState(proposal)}</div><blockquote class="agent-reason"><span class="data-meta">Agent’s reason</span><p>${escape(proposal.reason)}</p></blockquote>${keyNote}${open ? changed : ''}<div class="section-grid"><section class="panel" aria-labelledby="effect-filed"><h3 id="effect-filed">When filed</h3>${effectRows(proposal.effect)}</section><section class="panel" aria-labelledby="effect-now"><h3 id="effect-now">Now</h3>${proposal.fresh ? effectRows(proposal.fresh) : ''}</section></div>${actions}</section>`
}

export function renderAgentsPage(model: AuthPageModel): string {
  const agents = model.agents ?? { keys: [], proposals: [], proposal: null }
  const now = agents.now ?? Date.now()
  const keys = asArray<AgentKey>(agents.keys), proposals = asArray<AgentProposal>(agents.proposals)
  const pending = proposals.filter(p => p.status === 'pending').length
  const mint = `<form class="inline-form" method="post" action="/api/auth/agents/mint" data-agent-mint>${csrfField(model.csrf)}<div class="field"><label for="agent-key-label">Key label</label><input id="agent-key-label" name="label" maxlength="80" placeholder="Directory review agent" required></div><button type="submit">Mint a key</button></form><div class="agent-secret" data-agent-secret hidden><label for="agent-secret-value">Copy this key now. Auth keeps only its digest and will not show it again.</label><input id="agent-secret-value" readonly data-agent-secret-value></div>`
  const keyPanel = `<section class="panel" aria-labelledby="keys-heading"><div class="panel-header"><div><h2 id="keys-heading">Preparer keys</h2><p>A key lets an agent read the people inventory and file proposals through the preparer API. It cannot sign in, open these pages, approve, or change anything itself, and it is not an app access token. Each key expires 30 days after minting or renewal and stops at once when revoked or when its accountable administrator loses that role. Minting, renewing and revoking need an email confirmation in this browser within ten minutes.</p></div></div>${mint}${keyRows(keys, model, now)}</section>`
  const proposalPanel = `<section class="panel" aria-labelledby="proposals-heading"><div class="panel-header"><div><h2 id="proposals-heading">Proposals</h2><p>What agents asked for, with the effect Auth computed when they filed. Nothing changes until a person approves; proposals expire after 24 hours.</p></div><span class="pill">${pending} waiting</span></div>${proposalRows(proposals)}</section>`
  return `${agents.proposal ? `<div class="toolbar"><a class="action" href="/app/agents">All proposals and keys</a></div>${review(model, agents.proposal)}` : ''}${proposalPanel}${keyPanel}`
}
