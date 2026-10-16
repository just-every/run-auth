import type { AuthApp, AuthPageModel } from '../model.js'
import { asArray, csrfField, emptyState, escape, replacementText, timeElement } from '../helpers.js'

const appOrigin = (value: string): { host: string; punycode: boolean } => {
  try {
    const url = new URL(value)
    return { host: url.host, punycode: url.hostname.split('.').some(part => part.toLowerCase().startsWith('xn--')) }
  } catch { return { host: value, punycode: false } }
}

const SOURCES: Record<string, string> = { owner: 'Approved here', token: 'Created with a link token', rer: 'Created by RER', proposal: 'Approved from an agent proposal' }
const linkSource = (source?: string | null): string => source ? SOURCES[source] ?? `Link source: ${source}` : 'Source not recorded'

const actionForm = (action: string, fields: Record<string, string>, label: string, csrf?: string, confirm?: string, danger = false): string =>
  `<form class="button-row" method="post" action="${action}" data-auth-action data-reload="true"${confirm ? ` data-confirm="${escape(confirm)}"` : ''}>${Object.entries(fields).map(([name, value]) => `<input type="hidden" name="${name}" value="${escape(value)}">`).join('')}${csrfField(csrf)}<button class="${danger ? 'danger-button' : 'secondary-button'}" type="submit">${label}</button></form>`

const flags = (app: AuthApp, punycode: boolean): string => [
  punycode ? '<span class="pill">Punycode origin</span>' : '',
  app.firstSeen ? '<span class="pill">First time Auth has seen this origin</span>' : '',
  app.replacesClient ? `<span class="pill">${app.keyChanged ? 'Replaces an existing link with a new key' : 'Re-links an existing app'}</span>` : '',
  ...asArray(app.replaces).map(replaced => `<span class="pill">${escape(replacementText(replaced))}</span>`),
  app.source === 'rer' ? '<span class="pill">RER link</span>' : '',
  app.source === 'token' ? '<span class="pill">Link token</span>' : '',
].join('')

const versionCell = (app: AuthApp, model: AuthPageModel): string => {
  const inUse = app.versions?.length ? escape(app.versions.join(', ')) : 'No version report'
  const held = asArray<string>(app.heldVersions).map(version => model.user?.role === 'owner'
    ? `<div class="data-meta">${escape(version)} reported, lower than in use</div>${actionForm('/api/auth/apps/version', { id: app.id, version }, 'Accept lower version', model.csrf, `Accept ${version} for this app?`)}`
    : `<div class="data-meta">${escape(version)} reported, waiting for the owner</div>`).join('')
  return inUse + held
}

const appRows = (apps: AuthApp[], model: AuthPageModel): string => apps.map(app => {
  const origin = appOrigin(app.origin)
  const name = app.name?.trim() || origin.host
  const pending = app.status === 'pending'
  const removed = app.status === 'removed' || Boolean(app.disabled_at ?? app.disabledAt)
  const appFlags = flags(app, origin.punycode)
  const controls = pending
    ? `${actionForm('/api/auth/apps/approve', { id: app.id }, 'Approve app', model.csrf, `Link ${origin.host} to this issuer? People will be able to sign in to it with Auth.`)}<p class="data-meta">The app's owner must also approve this link in the app, within ten minutes.</p>`
    : removed ? '' : actionForm('/api/auth/apps/remove', { id: app.id }, 'Remove app', model.csrf, `Remove ${name} from this issuer?`, true)
  const status = pending ? '<span class="status-pill">Approval pending</span>' : removed ? '<span class="status-pill suspended">Removed</span>' : '<span class="status-pill active">Active</span>'
  return `<tr class="app-row"><td><strong class="app-origin">${escape(origin.host)}</strong><div class="data-meta">${escape(name)}</div></td><td><span class="mobile-label">Link source</span><span class="pill">${escape(pending ? 'Waiting for approval' : linkSource(app.source))}</span>${appFlags ? `<div class="button-row flag-list">${appFlags}</div>` : ''}</td><td><span class="mobile-label">Status</span>${status}</td><td><span class="mobile-label">Versions in use</span>${versionCell(app, model)}</td><td><span class="mobile-label">Linked</span>${timeElement(app.linked_at ?? app.created_at ?? app.createdAt)}</td><td class="actions-cell">${controls}</td></tr>`
}).join('')

const originField = (id: string, label: string): string => `<div class="field"><label for="${id}">${label}</label><input id="${id}" name="origin" type="url" inputmode="url" placeholder="https://app.example.com" required></div>`

export function renderAppsPage(model: AuthPageModel): string {
  const apps = asArray<AuthApp>(model.apps)
  const pendingApps = asArray<AuthApp>(model.pendingApps)
  const allApps = [...pendingApps, ...apps]
  const add = `<section class="panel stacked" aria-labelledby="add-app-heading"><div class="panel-header"><div><h2 id="add-app-heading">Add an app</h2><p>Auth reads the app's own link document at this exact address, then shows it here for approval.</p></div></div><form class="inline-form" method="post" action="/api/auth/apps/request" data-auth-action data-reload="true">${csrfField(model.csrf)}${originField('app-origin', 'App address')}<button type="submit">Check app</button></form></section>`
  const token = `<section class="panel stacked" aria-labelledby="link-token-heading"><div class="panel-header"><div><h2 id="link-token-heading">Link token for rer setup</h2><p>One use, for one exact app address and its sign-in callbacks, valid for an hour. Save it to a private file and pass it as RER_LINK_TOKEN_FILE.</p></div></div><form class="inline-form" method="post" action="/api/auth/apps/link-token" data-link-token>${csrfField(model.csrf)}${originField('token-origin', 'App address')}<button type="submit">Create link token</button></form><div class="agent-secret" data-link-token-output hidden><label for="link-token-value">Copy this now. Auth keeps only its digest and will not show it again.</label><textarea id="link-token-value" rows="6" readonly data-link-token-value></textarea></div></section>`
  const table = `<section class="table-panel app-table" aria-label="Connected apps"><div class="table-scroll" tabindex="0" role="region" aria-label="Connected apps table"><table><thead><tr><th scope="col">Origin and app</th><th scope="col">Link source</th><th scope="col">Status</th><th scope="col">Versions in use</th><th scope="col">Linked</th><th scope="col">Actions</th></tr></thead><tbody>${appRows(allApps, model)}</tbody></table></div>${allApps.length ? `<footer class="table-footer">${allApps.length} ${allApps.length === 1 ? 'app' : 'apps'}</footer>` : ''}</section>`
  const empty = emptyState('No connected apps are available for this issuer.', 'Add an app below, or link one with rer setup and a link token.')
  return `${allApps.length ? table : empty}<div class="section-grid">${add}${token}</div>`
}
