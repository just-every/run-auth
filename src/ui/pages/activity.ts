import { requestsPanel } from './access-requests.js'
import { retentionPanel } from './retention.js'
import { decisionsPanel } from './access-decisions.js'
import { reviewsPanel } from './access-reviews.js'
import { followupPanel } from './followup.js'
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
const actor = (event: AuthActivity): string => event.service_name ? `Service app ${event.service_name}${event.service_owner_email ? ` · Accountable: ${event.service_owner_email}` : ''}` : event.actor_email ?? event.actorEmail
  ?? event.actor_id ?? (typeof parsed(event.detail).key === 'string' ? `Agent key ${parsed(event.detail).key}` : 'Actor unavailable')
const activityRows = (events: AuthActivity[]): string => events.length
  ? events.map(event => `<tr class="activity-row"><td><span class="activity-event">${escape(activityName(event.event))}</span>${event.subject_id ? `<span class="activity-subject">Target: ${escape(event.subject_id)}</span>` : ''}${event.eventId ? `<span class="activity-subject">${escape(event.eventId)}</span>` : ''}${detailText(event.detail) ? `<span class="activity-subject" data-activity-detail>${escape(detailText(event.detail))}</span>` : ''}</td><td><span class="mobile-label">Actor</span>${escape(actor(event))}</td><td><span class="mobile-label">Time</span>${timeElement(event.created_at ?? event.createdAt)}</td></tr>`).join('')
  : '<tr><td colspan="3">No activity has been recorded.</td></tr>'

export function renderActivityPage(model: AuthPageModel): string {
  const events = asArray<AuthActivity>(model.activity)
  const history = model.activityPage
  const filters = history?.filters
  const date = (value: number | undefined): string => value && value < 8640000000000000 ? new Date(value).toISOString().slice(0, 16) : ''
  const query = new URLSearchParams({from: String(filters?.from ?? 0), to: String(filters?.to ?? 8640000000000000), person: filters?.person ?? '', event: filters?.event ?? '', limit: String(history?.limit ?? 50)})
  if (history?.nextCursor) query.set('cursor', history.nextCursor)
  const controls = `<form method="get" action="/app/activity" class="form-grid" aria-label="Filter activity"><label>From (UTC)<input type="datetime-local" name="from" value="${escape(date(filters?.from))}"></label><label>Until (UTC)<input type="datetime-local" name="to" value="${escape(date(filters?.to))}"></label><label>Person reference<input name="person" maxlength="200" value="${escape(filters?.person ?? '')}"></label><label>Event type<input name="event" maxlength="100" value="${escape(filters?.event ?? '')}" placeholder="email_confirmed"></label><button type="submit" class="quiet-button">Filter activity</button><a class="quiet-button" href="/app/activity">Newest events</a></form>`
  return `<a class="quiet-button" href="#activity-history">Skip to activity history</a>${controls}${retentionPanel(model)}${decisionsPanel(model)}${requestsPanel(model)}${reviewsPanel(model)}${followupPanel(model)}<section class="table-panel activity-table" aria-label="Activity"><div class="table-scroll" id="activity-history" tabindex="0" role="region" aria-label="Activity table"><table><thead><tr><th scope="col">Event</th><th scope="col">Actor</th><th scope="col">Time</th></tr></thead><tbody>${activityRows(events)}</tbody></table></div><footer class="table-footer">${events.length} of ${history?.total ?? events.length} events${history?.nextCursor ? ` · <a class="quiet-button" href="/app/activity?${escape(query.toString())}#activity-history">Older events</a>` : ''}</footer></section>`
}
