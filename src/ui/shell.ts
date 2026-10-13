import type { AuthNotice, AuthPage, AuthPageModel } from './model.js'
import { iconDefinitions } from './icons.js'
import { asArray, escape, fullName, hostLabel, icon, initials } from './helpers.js'

const navItems: Array<{ page: AuthPage; label: string; symbol: string; admin?: boolean; href: string }> = [
  { page: 'people', label: 'People', symbol: 'people', admin: true, href: '/app/people' },
  { page: 'agents', label: 'Agents', symbol: 'key', admin: true, href: '/app/agents' },
  { page: 'apps', label: 'Apps', symbol: 'apps', admin: true, href: '/app/apps' },
  { page: 'methods', label: 'Sign-in methods', symbol: 'lock', href: '/app/methods' },
  { page: 'activity', label: 'Activity', symbol: 'clock', admin: true, href: '/app/activity' },
  { page: 'account', label: 'My account', symbol: 'user', href: '/app/account' },
]

export const pageCopy: Record<AuthPage, { title: string; subtitle: string }> = {
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

export const renderShell = (model: AuthPageModel, page: AuthPage, content: string): string => {
  const user = model.user ?? model.me ?? null
  const copy = pageCopy[page]
  const currentName = user ? fullName(user) : 'Signed out'
  const nav = navItems.filter(item => !item.admin || model.isAdmin).map(item =>
    `<a href="${item.href}"${item.page === page || (page === 'move-in' && item.page === 'people') ? ' class="active" aria-current="page"' : ''}>${icon(item.symbol)}<span>${item.label}</span></a>`
  ).join('')
  const initial = initials(user?.name)
  const accountBadge = user
    ? `<a class="profile" href="/app/account" aria-label="My account for ${escape(currentName)}"><span class="initials account-initials">${escape(initial || '•')}</span>${icon('down')}</a>`
    : ''
  const pageContent = model.isAdmin || !['people', 'move-in', 'agents', 'apps', 'activity'].includes(page)
    ? content
    : '<section class="availability"><strong>Administrator access required.</strong><p>Sign in with a passkey on an administrator account to view this page.</p></section>'
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${copy.title} — Auth</title><link rel="stylesheet" href="/auth-assets/auth.css"><script src="/auth-assets/auth-ui.js" defer></script></head><body>${iconDefinitions}<div class="app" data-auth-page="${page}"><aside><div class="brand"><svg viewBox="0 0 32 36" aria-hidden="true"><use href="#shield"></use></svg><div><strong>Auth</strong><p>Identity for your business</p></div></div><nav aria-label="Main navigation">${nav}</nav><section class="issuer"><svg viewBox="0 0 24 24" aria-hidden="true"><use href="#building"></use></svg><p>Issuer host</p><span class="issuer-host">${escape(hostLabel(model.issuer))}</span><p class="description">Your organization’s identity service, hosted for your team.</p></section></aside><main class="app-page"><header class="heading"><div><h1>${copy.title}</h1><p class="subtitle">${copy.subtitle}</p></div><div class="heading-tools"><button type="button" data-theme-toggle aria-label="Toggle color theme" aria-pressed="false">Theme</button>${accountBadge ? `<div class="account"><div class="tenant"><i class="dot"></i><span>${escape(hostLabel(model.issuer))}</span>${icon('down')}</div>${accountBadge}</div>` : ''}</div></header><div class="page-content"><div class="notice-list">${modelNotices(model)}<div class="notice-panel" data-auth-status data-kind="info" role="status" aria-live="polite"></div></div>${pageContent}</div></main></div><span class="visually-hidden" id="auth-page-title">${copy.title}</span></body></html>`
}
