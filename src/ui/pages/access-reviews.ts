import { csrfField, emptyState, escape, timeElement } from '../helpers.js'

export interface AccessReviewPerson { id: string; email: string; name: string }
export interface AccessReviewItem {
  id: string
  reviewer_id: string
  subject_id: string
  subject_name: string
  app_name: string
  role: string | null
  snapshot: unknown
  decision: string | null
  reason: string | null
  remediation: unknown
  drift: boolean
  canDecide: boolean
}
export interface AccessReview {
  id: string
  name: string
  status: string
  due_at: number | string
  overdue: boolean
  period_start: number | string
  period_end: number | string
  items: AccessReviewItem[]
  completion: { decided: number; total: number; unfinished: number; complete: boolean }
}
export interface AccessReviewsModel {
  canManage: boolean
  people: AccessReviewPerson[]
  apps: Array<{ id: string; name: string }>
  reviews: AccessReview[]
}

const peopleOptions = (people: AccessReviewPerson[], selected?: string): string => people.map(person => `<option value="${escape(person.id)}"${person.id === selected ? ' selected' : ''}>${escape(person.name || person.email)} · ${escape(person.email)}</option>`).join('')
const valueText = (value: unknown): string => {
  if (value == null) return 'Not recorded'
  if (Array.isArray(value)) return value.length ? value.map(valueText).join('; ') : 'None'
  if (typeof value === 'object') return Object.entries(value).map(([key, entry]) => `${key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/_/g, ' ')}: ${valueText(entry)}`).join('; ')
  return typeof value === 'string' && /^[a-z]+(?:_[a-z]+)+$/.test(value) ? value.replace(/_/g, ' ') : String(value)
}
const evidence = (snapshot: unknown): string => {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return `<p class="issuer-host">${escape(valueText(snapshot))}</p>`
  const labels: Record<string, string> = { identity: 'Identity', groups: 'Groups', source: 'Access source', lastObservedUse: 'Last observed use', freshness: 'Evidence freshness' }
  return `<dl class="effect-list">${Object.entries(snapshot).map(([key, value]) => `<div><dt>${escape(labels[key] ?? key.replace(/_/g, ' '))}</dt><dd>${escape(valueText(value))}</dd></div>`).join('')}</dl>`
}

function itemRow(item: AccessReviewItem, data: AccessReviewsModel, reviewOpen: boolean, csrf?: string): string {
  const reviewer = data.people.find(person => person.id === item.reviewer_id)
  const decision = reviewOpen && item.canDecide && !item.decision ? `<form class="directory-form" method="post" action="/api/auth/decisions/options" data-access-decision="review">${csrfField(csrf)}<input type="hidden" name="targetId" value="${escape(item.id)}"><label class="field">Decision reason<input name="reason" required maxlength="500"></label><div class="button-row"><button class="primary-button" type="submit" name="operation" value="certify">Certify access with passkey</button><button class="danger-button" type="submit" name="operation" value="revoke">Revoke access with passkey</button></div><p data-access-result role="status"></p></form>` : ''
  const delegates = data.people.filter(person => person.id !== item.subject_id)
  const delegate = reviewOpen && data.canManage && !item.decision && delegates.length ? `<details><summary>Delegate this review item</summary><form class="directory-form" method="post" action="/api/auth/reviews/delegate" data-access-form="review-delegate">${csrfField(csrf)}<input type="hidden" name="itemId" value="${escape(item.id)}"><label class="field">Reviewer<select name="reviewerId" required>${peopleOptions(delegates, item.reviewer_id)}</select></label><label class="field">Delegation reason<input name="reason" required maxlength="500"></label><button class="secondary-button" type="submit">Delegate item</button><p data-access-result role="status"></p></form></details>` : ''
  const remediation = item.remediation == null || item.remediation === '' ? '' : `<p class="issuer-host">Remediation: ${escape(valueText(item.remediation))}</p>`
  return `<div class="data-row issuer-host" data-review-item="${escape(item.id)}"><div><h4 class="issuer-host">${escape(item.subject_name)} · ${escape(item.app_name)}</h4><p>Role: ${escape(item.role || 'No role')} · Reviewer: ${escape(reviewer?.name || reviewer?.email || item.reviewer_id)}</p><p>${item.decision ? `Decision: ${escape(item.decision)}${item.reason ? ` · ${escape(item.reason)}` : ''}` : 'Awaiting decision'}${item.drift ? ' · Access changed since the snapshot.' : ''}</p>${remediation}<details><summary>Access evidence at review creation</summary>${evidence(item.snapshot)}</details>${decision}${delegate}</div></div>`
}

export function reviewsPanel(model: { reviews?: AccessReviewsModel; csrf?: string }): string {
  const data = model.reviews
  if (!data) return ''
  const create = data.canManage ? `<section class="panel stacked" data-access-review-create><h2>Create a quarterly access review</h2><p>Snapshot current app access and assign a reviewer. A person cannot certify their own access. Revoke decisions track remediation before the review can close.</p><form class="directory-form" method="post" action="/api/auth/reviews/create" data-access-form="review-create">${csrfField(model.csrf)}<div class="directory-fields"><label class="field">Review name<input name="name" required maxlength="120"></label><label class="field">Reviewer<select name="reviewerId" required>${peopleOptions(data.people)}</select></label><label class="field">Due at<input name="dueAt" type="datetime-local" required></label><label class="field">Period start<input name="periodStart" type="date" required></label><label class="field">Period end<input name="periodEnd" type="date" required></label></div><input type="hidden" name="intervalMonths" value="3"><button class="primary-button" type="submit"${data.people.length ? '' : ' disabled'}>Create quarterly review</button><p data-access-result role="status"></p></form></section>` : ''
  const rows = data.reviews.map(review => {
    const open = review.status === 'open'
    const completion = review.completion
    const close = data.canManage && open ? `<form method="post" action="/api/auth/reviews/close" data-access-form="review-close">${csrfField(model.csrf)}<input type="hidden" name="id" value="${escape(review.id)}"><button class="secondary-button" type="submit"${completion.complete ? '' : ' disabled'}>Close review</button><p data-access-result role="status"></p></form>` : ''
    return `<section class="panel stacked" data-access-review="${escape(review.id)}"><h3 class="issuer-host">${escape(review.name)}</h3><p>Status: ${escape(review.status)}${review.overdue ? ' · Overdue' : ''} · Due ${timeElement(review.due_at)}</p><p>Review period: ${timeElement(review.period_start)} – ${timeElement(review.period_end)}</p><p>${completion.decided} of ${completion.total} decisions recorded · ${completion.unfinished} unfinished remediation${completion.unfinished === 1 ? '' : 's'}${completion.complete ? ' · Ready to close' : ''}</p><div class="button-row"><a class="secondary-button" href="/api/auth/reviews/export?id=${encodeURIComponent(review.id)}">Export review evidence</a>${close}</div>${open && !completion.complete && data.canManage ? '<p class="data-meta">Finish every decision and remediation before closing this review.</p>' : ''}<div class="data-list">${review.items.map(item => itemRow(item, data, open, model.csrf)).join('') || emptyState('No access items in this review.')}</div></section>`
  }).join('')
  return `${create}<section class="panel stacked" data-access-reviews><div class="panel-header"><div><h2>Access reviews</h2><p>Review the recorded access and its evidence, certify what is needed, or revoke what is no longer needed.</p><p class="data-meta">Role reduction needs a published app role hierarchy; certify or revoke available.</p></div></div>${rows || emptyState('No access reviews yet.')}</section><script src="/auth-assets/decisions-ui.js" defer></script>`
}
