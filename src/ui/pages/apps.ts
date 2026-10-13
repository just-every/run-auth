import type { AuthApp, AuthPageModel } from '../model.js'
import { actionUnavailable, asArray, emptyState, escape, timeElement } from '../helpers.js'

const appOrigin = (value: string): { host: string; punycode: boolean } => {
  try {
    const url = new URL(value)
    return { host: url.host, punycode: url.hostname.split('.').some(part => part.toLowerCase().startsWith('xn--')) }
  } catch { return { host: value, punycode: false } }
}

const linkSource = (source?: string | null): string => {
  if (!source) return 'Source not recorded'
  const value = source.toLowerCase()
  if (value.includes('rer')) return 'Created by RER'
  if (value.includes('token')) return 'Created with a link token'
  return `Link source: ${source}`
}

const actionForm = (action: string, name: string, value: string, label: string, csrf?: string, confirm?: string): string =>
  `<form class="button-row" method="post" action="${action}" data-auth-action data-reload="true"${confirm ? ` data-confirm="${escape(confirm)}"` : ''}><input type="hidden" name="${name}" value="${escape(value)}"><input type="hidden" name="csrf" value="${escape(csrf ?? '')}"><button class="${label === 'Remove app' ? 'danger-button' : 'secondary-button'}" type="submit">${label}</button></form>`

const appRows = (apps: AuthApp[], model: AuthPageModel): string => apps.length ? apps.map(app => {
  const origin = appOrigin(app.origin)
  const name = app.name?.trim() || origin.host
  const disabled = Boolean(app.disabled_at ?? app.disabledAt)
  const pending = app.status?.toLowerCase() === 'pending'
  const source = linkSource(app.source)
  const sourceFlags = `${origin.punycode ? '<span class="pill">Punycode origin</span>' : ''}${app.source?.toLowerCase().includes('rer') ? '<span class="pill">RER link</span>' : ''}${app.source?.toLowerCase().includes('token') ? '<span class="pill">Link token</span>' : ''}`
  const approvalUnavailable = actionUnavailable(model, 'apps.approve')
  const removalUnavailable = actionUnavailable(model, 'apps.remove')
  const controls = pending
    ? approvalUnavailable ? '<span class="muted">Approval is pending link-service support.</span>' : actionForm('/api/auth/apps/approve', 'origin', app.origin, 'Approve app', model.csrf)
    : removalUnavailable ? '<span class="muted">Removal is pending link-service support.</span>' : actionForm('/api/auth/apps/remove', 'id', app.id, 'Remove app', model.csrf, `Remove ${name} from this issuer?`)
  const versions = app.versions?.length ? app.versions.join(', ') : 'No version report'
  const status = pending ? '<span class="pill">Approval pending</span>' : disabled ? '<span class="status-pill suspended"><i class="status-dot"></i>Disabled</span>' : '<span class="status-pill active"><i class="status-dot"></i>Active</span>'
  return `<tr><td><strong>${escape(name)}</strong><div class="data-meta">${escape(origin.host)}</div></td><td><span class="pill">${escape(source)}</span>${sourceFlags ? `<div class="button-row flag-list">${sourceFlags}</div>` : ''}</td><td>${status}</td><td>${escape(versions)}</td><td>${timeElement(app.created_at ?? app.createdAt)}</td><td class="actions-cell">${controls}</td></tr>`
}).join('') : '<tr><td colspan="6">No connected apps are available for this issuer.</td></tr>'

export function renderAppsPage(model: AuthPageModel): string {
  const apps = asArray<AuthApp>(model.apps)
  const pendingApps = asArray<AuthApp>(model.pendingApps)
  const allApps = [...pendingApps, ...apps.filter(app => !pendingApps.some(pending => pending.id === app.id))]
  const approvalUnavailable = actionUnavailable(model, 'apps.approve')
  const removalUnavailable = actionUnavailable(model, 'apps.remove')
  const pendingNotice = approvalUnavailable || removalUnavailable
    ? '<div class="availability"><strong>Some link controls are pending.</strong><p>Approving new app links and removing connected apps are not available until link-service support is ready.</p></div>'
    : ''
  return `${pendingNotice}<section class="table-panel app-table" aria-label="Connected apps"><div class="table-scroll" tabindex="0" role="region" aria-label="Connected apps table"><table><thead><tr><th scope="col">App and origin</th><th scope="col">Link source</th><th scope="col">Status</th><th scope="col">Versions in use</th><th scope="col">Added</th><th scope="col">Actions</th></tr></thead><tbody>${appRows(allApps, model)}</tbody></table></div>${allApps.length ? `<footer class="table-footer">${allApps.length} ${allApps.length === 1 ? 'app' : 'apps'}</footer>` : ''}</section>${allApps.some(app => app.versions?.length) ? '' : `<section class="panel stacked"><div class="panel-header"><div><h2>Versions in use</h2><p>Interface version reporting is pending linked-app support.</p></div></div>${emptyState('No live-version reports are available.')}</section>`}`
}
