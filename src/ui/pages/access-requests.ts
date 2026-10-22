import { csrfField, emptyState, escape, timeElement } from '../helpers.js'

export interface AccessRequest {
  id: string
  app_id: string
  person_id: string
  app_name: string
  role: string | null
  purpose: string
  duration_ms: number
  decider_id: string
  state: string
  expires_at: number | null
  reason: string | null
  decided_by?: string | null
  decided_at?: number | null
}
export interface AccessRequestsModel {
  requests: AccessRequest[]
  policies: Array<{ app_id: string; max_duration_ms: number; name: string }>
  canManage: boolean
  meId: string
  people?: Array<{ id: string; name?: string | null; email?: string }>
  adminApps?: Array<{ id: string; name: string }>
}

const stateLabels: Record<string, string> = {
  pending: 'Pending decision', approved: 'Approved temporary access', denied: 'Denied',
  cancelled: 'Cancelled by requester', revocation_pending: 'Revocation pending', expired_verified: 'Expired · Provider removal verified',
}

export function requestsPanel(model: { requests?: AccessRequestsModel; csrf?: string }): string {
  const data = model.requests
  if (!data) return ''
  const person = (id: string): string => {
    if (id === data.meId) return 'You'
    const found = data.people?.find(item => item.id === id)
    return found ? `${found.name || found.email || found.id}${found.name && found.email ? ` · ${found.email}` : ''}` : id
  }
  const firstLimit = data.policies.length ? Math.floor(data.policies[0].max_duration_ms / 60000) : 1
  const create = data.policies.length ? `<form class="directory-form" method="post" action="/api/auth/requests/create" data-access-form="request-create">${csrfField(model.csrf)}<div class="directory-fields"><label class="field">App<select name="appId" required>${data.policies.map(policy => `<option value="${escape(policy.app_id)}" data-max-duration-minutes="${Math.floor(policy.max_duration_ms / 60000)}">${escape(policy.name)} · Up to ${Math.floor(policy.max_duration_ms / 60000)} minutes</option>`).join('')}</select></label><label class="field">App role, if needed<input name="role" maxlength="80"></label><label class="field">Purpose<input name="purpose" required maxlength="500"></label><label class="field">Duration in minutes<input name="durationMinutes" type="number" min="1" max="${firstLimit}" value="${Math.min(60, firstLimit)}" step="1" required></label></div><button class="primary-button" type="submit">Request temporary access</button><p data-access-result role="status"></p></form>` : emptyState('No apps accept temporary access requests yet.')
  const policy = data.canManage && data.adminApps?.length && data.people?.length ? `<section class="panel stacked" data-access-request-policy><h2>Temporary access policy</h2><p>Choose the person who decides requests for this app and the longest permitted access period. Changing the policy makes older pending requests stale.</p><form class="directory-form" method="post" action="/api/auth/requests/policy" data-access-form="request-policy">${csrfField(model.csrf)}<div class="directory-fields"><label class="field">App<select name="appId" required>${data.adminApps.map(app => `<option value="${escape(app.id)}">${escape(app.name)}</option>`).join('')}</select></label><label class="field">Decider<select name="deciderId" required>${data.people.map(item => `<option value="${escape(item.id)}">${escape(item.name || item.email || item.id)}${item.name && item.email ? ` · ${escape(item.email)}` : ''}</option>`).join('')}</select></label><label class="field">Maximum duration in minutes<input name="maxDurationMinutes" type="number" min="1" max="43200" value="60" step="1" required></label></div><button class="secondary-button" type="submit">Save request policy</button><p data-access-result role="status"></p></form></section>` : ''
  const rows = data.requests.map(request => {
    const decision = request.state === 'pending' && request.decider_id === data.meId && request.person_id !== data.meId ? `<form class="directory-form" method="post" action="/api/auth/decisions/options" data-access-decision="request">${csrfField(model.csrf)}<input type="hidden" name="targetId" value="${escape(request.id)}"><label class="field">Decision reason<input name="reason" required maxlength="500"></label><div class="button-row"><button class="primary-button" type="submit" name="operation" value="approve">Approve request with passkey</button><button class="danger-button" type="submit" name="operation" value="deny">Deny request with passkey</button></div><p data-access-result role="status"></p></form>` : ''
    const cancel = request.state === 'pending' && request.person_id === data.meId ? `<form method="post" action="/api/auth/requests/cancel" data-access-form="request-cancel">${csrfField(model.csrf)}<input type="hidden" name="id" value="${escape(request.id)}"><button class="quiet-button" type="submit">Cancel request</button><p data-access-result role="status"></p></form>` : ''
    return `<div class="data-row" data-access-request="${escape(request.id)}"><div><h3 class="issuer-host">${escape(request.app_name)}${request.role ? ` · ${escape(request.role)}` : ''}</h3><p class="issuer-host">${escape(request.purpose)}</p><p>Requester: ${escape(person(request.person_id))} · Decider: ${escape(person(request.decider_id))}</p><p>Requested duration: ${request.duration_ms / 60000} minutes · <strong data-request-state>${escape(stateLabels[request.state] ?? request.state.replace(/_/g, ' '))}</strong></p>${request.expires_at ? `<p>Access expires ${timeElement(request.expires_at)}</p>` : ''}${request.decided_by ? `<p>Decided by ${escape(person(request.decided_by))}${request.decided_at ? ` · ${timeElement(request.decided_at)}` : ''}</p>` : ''}${request.reason ? `<p class="issuer-host">Reason: ${escape(request.reason)}</p>` : ''}${request.state === 'revocation_pending' ? '<p class="data-meta">Remote removal is unfinished. Expiry is not verified complete.</p>' : ''}${decision}${cancel}</div></div>`
  }).join('')
  return `<section class="panel stacked" data-access-request-create><h2>Request temporary app access</h2><p>Give a purpose and duration. The designated decider confirms the exact request with a passkey; privileged access also needs administrator proof. You cannot approve your own request.</p>${create}</section>${policy}<section class="panel stacked" data-access-requests><h2>Temporary access requests</h2>${rows ? `<div class="data-list">${rows}</div>` : emptyState('No temporary access requests.')}</section><script src="/auth-assets/decisions-ui.js" defer></script>`
}
