import type { AuthNotice, AuthPage, AuthPageModel } from './model.js'
import { iconDefinitions } from './icons.js'
import { actionUnavailable, asArray, csrfField, escape, fullName, hasAdminRole, hostLabel, icon, initials } from './helpers.js'

const navItems: Array<{ page: AuthPage; label: string; symbol: string; admin?: boolean; href: string }> = [
  { page: 'permissions', label: 'API permissions', symbol: 'lock', admin: true, href: '/app/permissions' },
  { page: 'erasure', label: 'Erasure', symbol: 'eraser', admin: true, href: '/app/erasure' },
  { page: 'organizations', label: 'Organizations', symbol: 'building', href: '/app/organizations' },
  { page: 'people', label: 'People', symbol: 'user', admin: true, href: '/app/people' },
  { page: 'agents', label: 'Agents', symbol: 'robot', admin: true, href: '/app/agents' },
  { page: 'apps', label: 'Apps', symbol: 'apps', admin: true, href: '/app/apps' },
  { page: 'roles', label: 'Roles', symbol: 'shield', href: '/app/roles' },
  { page: 'methods', label: 'Sign-in methods', symbol: 'key', href: '/app/methods' },
  { page: 'activity', label: 'Activity', symbol: 'clock', admin: true, href: '/app/activity' },
  { page: 'account', label: 'My account', symbol: 'gear', href: '/app' },
]

// Administration stays out of a member's menu; Organizations appears once there is more than one to choose.
const inMenu = (model: AuthPageModel, page: AuthPage, admin?: boolean): boolean => {
  if (page === 'organizations') return (model.organizations?.memberships.length ?? 0) > 1
  if (page === 'roles') return Boolean(model.isAdmin || model.roles?.ownGrants.length)
  if (page === 'activity') return Boolean(model.isAdmin || model.canReadAudit || model.roles?.ownGrants.some(grant => grant.permissions.includes('audit.view')))
  return !admin || Boolean(model.isAdmin)
}

const adminOnly: AuthPage[] = ['people', 'move-in', 'agents', 'apps', 'activity', 'permissions', 'erasure']

// Whether this person may open the page: administrator pages need a passkey session; Roles also opens for delegated scopes.
export const pageAvailable = (model: AuthPageModel, page: AuthPage): boolean => {
  if (page === 'roles') return Boolean(model.isAdmin || model.roles)
  if (page === 'activity') return Boolean(model.isAdmin || model.canReadAudit)
  return !adminOnly.includes(page) || Boolean(model.isAdmin)
}

// One line and one way forward: an administrator without a passkey session signs in with one, anyone else goes back.
export const unavailablePage = (model: AuthPageModel, page: AuthPage): string => {
  const user = model.user ?? model.me
  if (!user || !hasAdminRole(user)) return '<section class="availability availability-action"><strong>This page is for administrators.</strong><a class="secondary-button" href="/app">Back to My account</a></section>'
  const action = asArray(model.passkeys ?? model.methods).length
    ? `<button class="primary-button" type="button" data-passkey-authenticate data-return-to="/app/${page}">Sign in with a passkey</button>`
    : '<a class="primary-button" href="/app/methods">Register a passkey</a>'
  return `<section class="availability availability-action"><strong>Administrator access is paused.</strong>${action}</section>`
}

export const pageCopy: Record<AuthPage, { title: string; subtitle: string }> = {
  roles: { title: 'Roles', subtitle: 'Delegate administration with separate view and edit scopes.' },
  permissions: { title: 'API permissions', subtitle: 'Register resource APIs and accountable service identities.' },
  erasure: { title: 'Erasure', subtitle: 'Preview authorized removal and retain anonymized accountability.' },
  organizations: { title: 'Organizations', subtitle: 'Choose the employer whose membership you want to use.' },
  people: { title: 'People', subtitle: 'Manage who can sign in to this identity.' },
  'move-in': { title: 'Move people in', subtitle: 'Stage a directory export, review it, then admit people as invitations.' },
  agents: { title: 'Agents', subtitle: 'Let an agent prepare administration; a person approves each change.' },
  apps: { title: 'Apps', subtitle: 'Review apps connected to this issuer.' },
  methods: { title: 'Sign-in methods', subtitle: 'Manage the ways you sign in to Auth.' },
  activity: { title: 'Activity', subtitle: 'Review recent account and issuer events.' },
  account: { title: 'My account', subtitle: 'Manage your personal sign-in and recovery settings.' },
}

const modelNotices = (model: AuthPageModel): string => {
  const notes: string[] = []
  if (typeof model.notice === 'string' && model.notice) notes.push(model.notice)
  else if (model.notice && typeof model.notice === 'object' && model.notice.message) notes.push(model.notice.message)
  for (const notice of asArray<AuthNotice>(model.notices)) if (notice.message) notes.push(notice.message)
  return notes.map(message => `<div class="notice-panel" role="status">${escape(message)}</div>`).join('')
}

// The head every Auth document shares: fonts, the app stylesheet, the mark as favicon and the small client script.
export const documentHead = (title: string): string => `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${escape(title)}</title><link rel="icon" href="/brand/mark.svg" type="image/svg+xml"><link rel="stylesheet" href="/fonts/fonts.css"><link rel="stylesheet" href="/rer-theme.css"><link rel="stylesheet" href="/auth-assets/auth.css"><link rel="stylesheet" href="/auth-assets/shell.css"><link rel="stylesheet" href="/auth-assets/tables.css"><link rel="stylesheet" href="/auth-assets/pages.css"><link rel="stylesheet" href="/auth-assets/signin.css"><link rel="stylesheet" href="/auth-assets/tooltips.css"><script src="/auth-assets/tooltips.js" defer></script><script src="/auth-assets/auth-ui.js" defer></script>`

export const brandLockup = (tag: 'div' | 'a' = 'div'): string =>
  `<${tag} class="brand"${tag === 'a' ? ' href="/app"' : ''}><img class="brand-mark" src="/brand/mark.svg" alt="" width="32" height="32"><span class="brand-text"><strong>Auth</strong><span class="brand-line">Identity for your business</span></span></${tag}>`

const themeToggle = `<button class="icon-button" type="button" data-theme-toggle data-tooltip="Color theme" aria-label="Color theme" aria-pressed="false">${icon('theme')}</button>`

// The active organization: plain text, or a link to the switcher when there is more than one to choose.
const tenantName = (model: AuthPageModel, host: string): string => {
  const name = escape(model.organizations?.current.name ?? host)
  return (model.organizations?.memberships.length ?? 0) > 1 ? `<a class="tenant" href="/app/organizations">${name}</a>` : `<span class="tenant-name">${name}</span>`
}

// The signed-in person at the foot of the menu, with the only places to end a session.
const ownerBlock = (model: AuthPageModel): string => {
  const user = model.user ?? model.me
  if (!user) return ''
  const everywhere = actionUnavailable(model, 'account.signout-everywhere') ? '' : `<button class="quiet-button" type="button" data-open-dialog="signout-everywhere-dialog">Sign out everywhere</button><dialog class="toolbar-dialog" id="signout-everywhere-dialog" aria-labelledby="signout-everywhere-title"><h2 id="signout-everywhere-title">Sign out everywhere?</h2><p>This ends every Auth session for your account and signs you out of your linked apps.</p><form method="post" action="/api/auth/signout-everywhere" data-auth-action data-redirect="/signin">${csrfField(model.csrf)}<div class="dialog-actions"><button class="quiet-button" type="button" data-close-dialog>Cancel</button><button class="primary-button" type="submit">Sign out everywhere</button></div></form></dialog>`
  return `<section class="owner" aria-label="Signed in as ${escape(fullName(user))}"><div class="owner-person"><span class="initials">${escape(initials(user.name) || '•')}</span><div><strong data-person-name>${escape(fullName(user))}</strong><span class="data-meta" title="${escape(user.email)}">${escape(user.email)}</span></div></div><div class="owner-actions"><form method="post" action="/api/auth/signout" data-auth-action data-redirect="/signin">${csrfField(model.csrf)}<button class="secondary-button" type="submit">Sign out</button></form>${everywhere}</div></section>`
}

export const renderShell = (model: AuthPageModel, page: AuthPage | 'not-found', content: string): string => {
  const user = model.user ?? model.me ?? null
  const copy = page === 'not-found' ? { title: 'Page not found', subtitle: 'There is nothing at this address.' } : page === 'organizations' && (model.organizations?.memberships.length ?? 0) < 2 ? { ...pageCopy[page], subtitle: 'Start another employer directory.' } : pageCopy[page]
  const host = escape(hostLabel(model.issuer))
  const nav = navItems.filter(item => inMenu(model, item.page, item.admin)).map(item =>
    `<a href="${item.href}"${item.page === page || (page === 'move-in' && item.page === 'people') ? ' class="active" aria-current="page"' : ''}>${icon(item.symbol)}<span>${item.label}</span></a>`
  ).join('')
  const accountBadge = user
    ? `<a class="initials account-initials" data-tooltip="My account" href="/app" aria-label="My account">${escape(initials(user.name) || '•')}</a>`
    : ''
  return `<!doctype html><html lang="en"><head>${documentHead(`${copy.title} — Auth`)}</head><body>${iconDefinitions}<div class="app" data-auth-page="${page}"><aside class="sidebar"><div class="sidebar-top">${brandLockup('a')}${themeToggle}</div><nav aria-label="Main navigation">${nav}</nav>${ownerBlock(model)}</aside><main class="app-page"><header class="heading"><div><h1>${copy.title}</h1><p class="subtitle">${copy.subtitle}</p></div><div class="heading-tools">${themeToggle}${tenantName(model, host)}${accountBadge}</div></header><div class="page-content"><div class="notice-list">${modelNotices(model)}<div class="notice-panel" data-auth-status data-kind="info" role="status" aria-live="polite"></div></div>${content}</div></main></div><span class="visually-hidden" id="auth-page-title">${copy.title}</span></body></html>`
}
