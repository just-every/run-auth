import type { AuthActivity, AuthPageModel } from '../model.js'
import { asArray, escape, timeElement } from '../helpers.js'

const activityName = (event: string): string => event.replace(/[_.-]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/\b\w/g, char => char.toUpperCase())
const parsed = (detail?: string | null): Record<string, unknown> => {
  if (!detail) return {}
  try { const value = JSON.parse(detail); return value && typeof value === 'object' ? value : {} } catch { return {} }
}
// What was recorded with an entry: who a move-in undo removed and kept, or which
// key filed a proposal, its target and the result.
const detailText = (detail?: string | null): string => {
  const item = (entry: unknown): string => typeof entry === 'string' ? entry
    : entry && typeof entry === 'object' && 'email' in entry ? `${String((entry as { email: unknown }).email)} (${asArray((entry as { reasons?: string[] }).reasons).map(reason => reason.replace(/_/g, ' ')).join(', ')})` : ''
  return Object.entries(parsed(detail)).filter(([, value]) => typeof value === 'string' ? value : Array.isArray(value) && value.length)
    .map(([key, value]) => `${activityName(key)}: ${Array.isArray(value) ? value.map(item).join(', ') : String(value).replace(/_/g, ' ')}`).join('. ')
}
const actor = (event: AuthActivity): string => event.actor_email ?? event.actorEmail
  ?? (typeof parsed(event.detail).key === 'string' ? `Agent key ${parsed(event.detail).key}` : 'Actor unavailable')
const activityRows = (events: AuthActivity[]): string => events.length
  ? events.map(event => `<tr class="activity-row"><td><span class="activity-event">${escape(activityName(event.event))}</span>${detailText(event.detail) ? `<span class="activity-subject" data-activity-detail>${escape(detailText(event.detail))}</span>` : ''}</td><td><span class="mobile-label">Person</span>${escape(actor(event))}</td><td><span class="mobile-label">Time</span>${timeElement(event.created_at ?? event.createdAt)}</td></tr>`).join('')
  : '<tr><td colspan="3">No activity has been recorded.</td></tr>'

export function renderActivityPage(model: AuthPageModel): string {
  const events = asArray<AuthActivity>(model.activity)
  return `<section class="table-panel activity-table" aria-label="Activity"><div class="table-scroll" tabindex="0" role="region" aria-label="Activity table"><table><thead><tr><th scope="col">Event</th><th scope="col">Person</th><th scope="col">Time</th></tr></thead><tbody>${activityRows(events)}</tbody></table></div><footer class="table-footer">${events.length} ${events.length === 1 ? 'event' : 'events'}</footer></section>`
}
