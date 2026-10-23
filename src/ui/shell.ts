import type { AuthNotice, AuthPage, AuthPageModel } from './model.js'
import { iconDefinitions } from './icons.js'
import { asArray, escape, fullName, hostLabel, icon, initials } from './helpers.js'

const navItems: Array<{ page: AuthPage; label: string; symbol: string; admin?: boolean; href: string }> = [
  { page: 'roles', label: 'Roles', symbol: 'key', href: '/app/roles' },
  { page: 'permissions', label: 'API permissions', symbol: 'apps', admin: true, href: '/app/permissions' },
  { page: 'erasure', label: 'Erasure', symbol: 'gear', admin: true, href: '/app/erasure' },
  { page: 'organizations', label: 'Organizations', symbol: 'apps', href: '/app/organizations' },
  { page: 'people', label: 'People', symbol: 'user', admin: true, href: '/app/people' },
  { page: 'agents', label: 'Agents', symbol: 'robot', admin: true, href: '/app/agents' },
  { page: 'apps', label: 'Apps', symbol: 'apps', admin: true, href: '/app/apps' },
  { page: 'methods', label: 'Sign-in methods', symbol: 'key', href: '/app/methods' },
  { page: 'activity', label: 'Activity', symbol: 'clock', admin: true, href: '/app/activity' },
  { page: 'account', label: 'My account', symbol: 'gear', href: '/app/account' },
]

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
export const documentHead = (title: string): string => `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${escape(title)}</title><link rel="icon" href="/brand/mark.svg" type="image/svg+xml"><link rel="stylesheet" href="/fonts/fonts.css"><link rel="stylesheet" href="/rer-theme.css"><link rel="stylesheet" href="/auth-assets/auth.css"><link rel="stylesheet" href="/auth-assets/shell.css"><link rel="stylesheet" href="/auth-assets/tables.css"><link rel="stylesheet" href="/auth-assets/pages.css"><link rel="stylesheet" href="/auth-assets/signin.css"><link rel="stylesheet" href="/auth-assets/tooltips.css"><script src="/auth-assets/auth-ui.js" defer></script>`

export const brandLockup = (tag: 'div' | 'a' = 'div'): string =>
  `<${tag} class="brand"${tag === 'a' ? ' href="/app"' : ''}><img class="brand-mark" src="/brand/mark.svg" alt="" width="32" height="32"><span class="brand-text"><strong>Auth</strong><span class="brand-line">Identity for your business</span></span></${tag}>`

const themeToggle = `<button class="icon-button" type="button" data-theme-toggle data-tooltip="Color theme" aria-label="Toggle color theme" aria-pressed="false">${icon('theme')}</button>`

export const renderShell = (model: AuthPageModel, page: AuthPage, content: string): string => {
  const user = model.user ?? model.me ?? null
  const copy = pageCopy[page]
  const currentName = user ? fullName(user) : 'Signed out'
  const host = escape(hostLabel(model.issuer))
  const nav = navItems.filter(item => !item.admin || model.isAdmin).map(item =>
    `<a href="${item.href}"${item.page === page || (page === 'move-in' && item.page === 'people') ? ' class="active" aria-current="page"' : ''}>${icon(item.symbol)}<span>${item.label}</span></a>`
  ).join('')
  const accountBadge = user
    ? `<a class="initials account-initials" data-tooltip="My account" href="/app/account" aria-label="My account for ${escape(currentName)}">${escape(initials(user.name) || '•')}</a>`
    : ''
  const pageContent = model.isAdmin || !['people', 'move-in', 'agents', 'apps', 'activity'].includes(page)
    ? content
    : '<section class="availability"><strong>Administrator access required.</strong><p>Sign in with a passkey on an administrator account to view this page.</p></section>'
  return `<!doctype html><html lang="en"><head>${documentHead(`${copy.title} — Auth`)}</head><body>${iconDefinitions}<div class="app" data-auth-page="${page}"><aside class="sidebar"><div class="sidebar-top">${brandLockup('a')}${themeToggle}</div><nav aria-label="Main navigation">${nav}</nav><section class="issuer" aria-label="Issuer host"><div><p>Issuer host</p><span class="issuer-host">${host}</span></div><img class="issuer-door" src="/brand/door-small.webp" alt="" width="38" height="56"></section></aside><main class="app-page"><header class="heading"><div><h1>${copy.title}</h1><p class="subtitle">${copy.subtitle}</p></div><div class="heading-tools">${themeToggle}<span class="tenant" title="Active organization">${escape(model.organizations?.current.name ?? host)}</span>${accountBadge}</div></header><div class="page-content"><div class="notice-list">${modelNotices(model)}<div class="notice-panel" data-auth-status data-kind="info" role="status" aria-live="polite"></div></div>${pageContent}</div></main></div><span class="visually-hidden" id="auth-page-title">${copy.title}</span></body></html>`
}
