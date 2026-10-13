import type { AuthUser } from './model.js'

export const escape = (input: unknown): string => String(input ?? '').replace(/[&<>"']/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[char]!))

export const icon = (name: string, label?: string): string =>
  `<svg${label ? ` role="img" aria-label="${escape(label)}"` : ' aria-hidden="true"'} viewBox="0 0 24 24"><use href="#${escape(name)}"></use></svg>`

export const asArray = <T>(value: T[] | undefined | null): T[] => Array.isArray(value) ? value : []

export const dateValue = (value: unknown): Date | null => {
  if (typeof value === 'number' || (typeof value === 'string' && /^\d+(?:\.\d+)?$/.test(value))) {
    const number = Number(value)
    const date = new Date(number < 1_000_000_000_000 ? number * 1000 : number)
    return Number.isNaN(date.valueOf()) ? null : date
  }
  if (typeof value === 'string' && value.trim()) {
    const date = new Date(value)
    return Number.isNaN(date.valueOf()) ? null : date
  }
  return null
}

export const dateText = (value: unknown): string => {
  const date = dateValue(value)
  return date ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date) : 'Not recorded'
}

export const timeElement = (value: unknown): string => {
  const date = dateValue(value)
  return date
    ? `<time datetime="${date.toISOString()}">${escape(dateText(value))}</time>`
    : '<span class="muted">Not recorded</span>'
}

export const hostLabel = (issuer?: string): string => {
  if (!issuer) return 'Issuer host'
  try { return new URL(issuer).host } catch { return issuer }
}

export const localReturnTo = (value?: string): string => {
  if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\r\n]/.test(value)) return '/app/account'
  try {
    const target = new URL(value, 'https://auth.invalid')
    return target.origin === 'https://auth.invalid' ? `${target.pathname}${target.search}${target.hash}` : '/app/account'
  } catch { return '/app/account' }
}

export const csrfField = (csrf?: string): string => `<input type="hidden" name="csrf" value="${escape(csrf ?? '')}">`

export const fullName = (person: { name?: string | null; email: string }): string => person.name?.trim() || person.email

export const initials = (name?: string | null): string => {
  const words = (name ?? '').trim().split(/\s+/).filter(Boolean)
  if (!words.length) return ''
  return `${words[0][0]}${words.length > 1 ? words[words.length - 1][0] : ''}`.toLocaleUpperCase()
}

export const badge = (status: unknown): string => {
  const raw = typeof status === 'string' ? status.toLowerCase() : ''
  const state = raw === 'active' ? 'active' : raw === 'invited' ? 'invited' : raw === 'inactive' || raw === 'suspended' ? 'suspended' : 'unknown'
  const label = state === 'active' ? 'Active' : state === 'invited' ? 'Invited' : state === 'suspended' ? 'Suspended' : 'Status unavailable'
  return `<span class="status-pill ${state === 'unknown' ? '' : state}"><i class="status-dot"></i>${label}</span>`
}

export const emptyState = (message: string): string => `<div class="empty-state"><p>${escape(message)}</p></div>`

export const noticeBox = (message: string, kind = 'info'): string =>
  `<div class="notice-panel" data-kind="${escape(kind)}" role="${kind === 'error' ? 'alert' : 'status'}">${escape(message)}</div>`

export const safeRole = (role?: string): string => role ? role.replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase()) : 'Role unavailable'

export const hasAdminRole = (user: AuthUser): boolean => ['owner', 'admin'].includes(user.role ?? '')

export const actionUnavailable = (model: { unavailableActions?: string[] }, action: string): boolean => model.unavailableActions?.includes(action) ?? true
