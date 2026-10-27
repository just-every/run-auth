import type { AuthPageModel, SessionControlOperation } from '../model.js'
import { csrfField, escape, fullName, timeElement } from '../helpers.js'

type Person = NonNullable<AuthPageModel['rolePeople']>[number]

const operationReceipt = (operation: SessionControlOperation, model: AuthPageModel): string => {
  const actor = model.rolePeople?.find(person => person.id === operation.actorId)
  const current = model.user ?? model.me
  const actorLabel = current?.id === operation.actorId ? current.email : actor?.email || operation.actorId
  const delivery = operation.logout
  return `<article data-session-operation="${escape(operation.id)}"><h3>Auth sessions ended</h3><p class="issuer-host">${timeElement(operation.createdAt)} · ${escape(actorLabel)}</p><p class="issuer-host">Reason: ${escape(operation.reason)}</p><p>${operation.nativeSessionsEnded} Auth sessions and ${operation.refreshGrantsEnded} refresh grants ended. Account, passkeys and assignments retained.</p><details><summary>Back-channel delivery</summary>${delivery.evidenceExpired ? '<p>Historical delivery evidence expired or was not retained. Counts show only the remaining queue evidence.</p>' : ''}<p>${delivery.delivered} delivered · ${delivery.pending} pending · ${delivery.failed} failed · ${delivery.unavailable} unavailable</p><p>These counts describe supported back-channel delivery. Delivery does not confirm that an app ended its remote session. Unsupported app sessions may remain active.</p></details></article>`
}

// Keep this action inside the selected person's details on both administrator doors.
function sessionControlContents(model: AuthPageModel, person: Person): string {
  if (!person.canEndSessions) return ''
  const operations = model.sessionControl?.people.find(row => row.personId === person.id)?.operations ?? []
  const name = fullName(person)
  return `<p>End this person's Auth sessions and refresh grants. Their account, passkeys and assignments stay in place.</p><form class="directory-form" method="post" action="/api/auth/roles/end-sessions" data-auth-action data-reload="true" data-confirm="${escape(`End all Auth sessions and refresh grants for ${name}? Their account, passkeys and assignments will be retained. Supported apps will receive back-channel logout; remote session completion is not confirmed.`)}">${csrfField(model.csrf)}<input type="hidden" name="personId" value="${escape(person.id)}"><label class="field">Reason for ending sessions<input name="reason" required maxlength="500" autocomplete="off"></label><button class="danger-button" type="submit">End all sessions</button></form>${operations.map(operation => operationReceipt(operation, model)).join('')}`
}

export function personSessionControl(model: AuthPageModel, person: Person): string {
  if (!person.canEndSessions) return ''
  return `<details data-session-control="${escape(person.id)}"><summary>Session control</summary>${sessionControlContents(model, person)}</details>`
}

export function sessionControlDialogs(model: AuthPageModel): string {
  return (model.rolePeople ?? []).filter(person => person.canEndSessions).map(person => `<dialog class="toolbar-dialog directory-dialog" id="sessions-${escape(person.id)}" data-session-control="${escape(person.id)}" aria-labelledby="sessions-title-${escape(person.id)}"><h2 id="sessions-title-${escape(person.id)}">Session control for ${escape(fullName(person))}</h2>${sessionControlContents(model, person)}<div class="dialog-actions"><button class="quiet-button" type="button" data-close-dialog>Close</button></div></dialog>`).join('')
}

export function scopedSessionControls(model: AuthPageModel): string {
  const people = (model.rolePeople ?? []).filter(person => person.canEndSessions)
  if (!people.length) return ''
  return `<section class="panel row-panel" aria-labelledby="session-controls-heading"><h2 id="session-controls-heading">People in your scope</h2>${people.map(person => `<div class="data-row"><div><strong>${escape(fullName(person))}</strong><p class="issuer-host">${escape(person.email)}</p>${personSessionControl(model, person)}</div></div>`).join('')}</section>`
}
