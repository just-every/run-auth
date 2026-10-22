import type { AuthPageModel, AuthRecovery, AuthUser } from '../model.js'
import { renderLauncher } from './company-apps.js'
import { followupPanel } from './followup.js'
import { profilePanels } from './profile.js'
import { delegatedTasksPanel } from './delegation.js'
import { actionUnavailable, asArray, csrfField, dateText, dateValue, emptyState, escape, fullName, hasAdminRole, initials, safeRole } from '../helpers.js'

const amrLabels = (amr?: string[]): string[] => (amr ?? []).map(method => {
  if (method === 'hwk') return 'Passkey'
  if (method === 'email') return 'Email link'
  if (method === 'dev') return 'Development identity'
  return method
})

const recoveryActions = (recovery: AuthRecovery, currentUser: AuthUser, isAdmin: boolean, csrf?: string): string => {
  const current = (recovery.person_id ?? recovery.personId) === currentUser.id
  const readyAt = dateValue(recovery.ready_at ?? recovery.readyAt)
  const ready = Boolean(readyAt && readyAt.valueOf() <= Date.now()) || Boolean(recovery.approved_by ?? recovery.approvedBy)
  const controls: string[] = []
  if (current && ready) controls.push(`<form class="button-row" method="post" action="/api/auth/recovery/complete" data-auth-action data-reload="true" data-confirm="Complete recovery and replace this account's passkeys?"><input type="hidden" name="recoveryId" value="${escape(recovery.id)}">${csrfField(csrf)}<button class="danger-button" type="submit">Complete recovery</button></form>`)
  if (current) controls.push(`<form class="button-row" method="post" action="/api/auth/recovery/cancel" data-auth-action data-reload="true"><input type="hidden" name="recoveryId" value="${escape(recovery.id)}">${csrfField(csrf)}<button class="quiet-button" type="submit">Cancel request</button></form>`)
  if (!current && isAdmin) controls.push(`<form class="button-row" method="post" action="/api/auth/recovery/approve" data-auth-action data-reload="true" data-confirm="Approve this passkey recovery?"><input type="hidden" name="recoveryId" value="${escape(recovery.id)}">${csrfField(csrf)}<button class="secondary-button" type="submit">Approve recovery</button></form>`)
  return controls.length ? `<div class="button-row">${controls.join('')}</div>` : '<span class="muted">Waiting for the 72-hour delay or another administrator.</span>'
}

const recoveryCard = (recovery: AuthRecovery, currentUser: AuthUser, isAdmin: boolean, csrf?: string): string => {
  const personId = recovery.person_id ?? recovery.personId
  const current = personId === currentUser.id
  const heading = current ? 'Your recovery request' : recovery.email ? `Recovery for ${recovery.email}` : 'Recovery request'
  const approval = recovery.approved_by ?? recovery.approvedBy ? '<p>Approved by another administrator.</p>' : ''
  return `<div class="data-row"><div><strong>${escape(heading)}</strong><p>Requested ${escape(dateText(recovery.created_at ?? recovery.createdAt))}; available ${escape(dateText(recovery.ready_at ?? recovery.readyAt))}.</p>${approval}</div>${recoveryActions(recovery, currentUser, isAdmin, csrf)}</div>`
}

export function renderAccountPage(model: AuthPageModel): string {
  const user = model.user ?? model.me ?? null
  if (!user) return '<section class="availability">Sign in to manage your account.</section>'
  const passkeys = asArray(model.passkeys ?? model.methods)
  const recoveries = asArray<AuthRecovery>(model.recoveries)
  const methods = amrLabels(user.amr)
  const hasPendingSelf = recoveries.some(recovery => (recovery.person_id ?? recovery.personId) === user.id)
  const recoveryControl = passkeys.length && !hasPendingSelf
    ? `<form method="post" action="/api/auth/recovery/start" data-auth-action data-reload="true" data-confirm="Request recovery for this account? Every active session will be notified.">${csrfField(model.csrf)}<button class="danger-button" type="submit">Request passkey recovery</button></form>`
    : passkeys.length ? '<p class="muted">A recovery request is already pending for this account.</p>' : '<p class="muted">Register a passkey before requesting recovery.</p>'
  const recoveriesContent = recoveries.length
    ? `<div class="data-list">${recoveries.map(recovery => recoveryCard(recovery, user, model.isAdmin, model.csrf)).join('')}</div>`
    : emptyState('No passkey recovery requests are pending.')
  const adminStep = hasAdminRole(user) && !model.isAdmin
    ? '<div class="availability"><strong>Administrator access is paused.</strong><p>Sign in with a passkey to use administrator pages.</p></div>'
    : ''
  const everywhere = actionUnavailable(model, 'account.signout-everywhere')
    ? '<section class="panel row-panel"><div class="panel-header"><div><h2>Sign out everywhere is pending.</h2><p>Cross-app session sign-out will be available when linked-app support is ready.</p></div><button class="quiet-button" type="button" disabled aria-disabled="true">Sign out everywhere unavailable</button></div></section>'
    : `<section class="panel row-panel"><div class="panel-header"><div><h2>Sign out everywhere</h2><p>End your Auth sessions and sign out of every app linked to this issuer.</p></div><form method="post" action="/api/auth/signout-everywhere" data-auth-action data-redirect="/signin" data-confirm="Sign out every session for this account?">${csrfField(model.csrf)}<button class="secondary-button" type="submit">Sign out everywhere</button></form></div></section>`
  return `${adminStep}${renderLauncher(model)}<section class="panel profile-panel"><div class="person-heading"><span class="initials">${escape(initials(user.name) || '•')}</span><div><h2>${escape(fullName(user))}</h2><p>${escape(user.email)}</p></div></div><div class="field-grid"><div class="field"><span class="form-label">Role</span><span class="field-value">${escape(safeRole(user.role))}</span></div><div class="field"><span class="form-label">This session used</span><span class="field-value">${methods.length ? escape(methods.join(', ')) : 'Not recorded'}</span></div></div></section>${profilePanels(model)}${followupPanel(model)}${delegatedTasksPanel(model)}<section class="panel row-panel"><div class="panel-header"><div><h2>Current session</h2><p>Sign out of this browser session.</p></div><form method="post" action="/api/auth/signout" data-auth-action data-redirect="/signin">${csrfField(model.csrf)}<button class="secondary-button" type="submit">Sign out of this session</button></form></div></section>${everywhere}<section class="panel row-panel"><div class="panel-header"><div><h2>Passkey recovery</h2><p>A recovery waits 72 hours unless another administrator approves it. Every active session is notified.</p></div>${recoveryControl}</div>${recoveriesContent}</section>`
}
