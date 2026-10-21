import { domainPolicyPanel } from './domain-policy.js'
import { directoryPanels, editDialog, onboardDialog, personDetail } from './directory.js'
import type { AuthPageModel, AuthPerson, DirectoryPerson } from '../model.js'
import { asArray, badge, csrfField, emptyState, escape, fullName, icon, initials, safeRole } from '../helpers.js'

const personRows = (people: AuthPerson[], model: AuthPageModel): string => {
  const detail = new Map((model.directory?.people ?? []).map(p => [p.id, p] as [string, DirectoryPerson]))
  if (!people.length) return '<tr class="empty-row"><td colspan="5">No people are available for this issuer.</td></tr>'
  return people.map(person => {
    const name = fullName(person)
    const state = String(person.status ?? '').toLowerCase()
    const currentUser = model.user ?? model.me
    const canSuspend = person.role !== 'owner' && state !== 'inactive' && state !== 'suspended'
    const suspend = canSuspend
      ? `<form class="button-row" method="post" action="/api/auth/people/suspend" data-auth-action data-reload="true" data-confirm="Suspend access for ${escape(name)}?"><input type="hidden" name="personId" value="${escape(person.id)}">${csrfField(model.csrf)}<button class="danger-button" type="submit">Suspend</button></form>`
      : state === 'inactive' || state === 'suspended' ? '<span class="muted">Suspended</span>' : '<span class="muted">Owner</span>'
    const canChangeRole = Boolean(model.isAdmin && currentUser?.role === 'owner' && person.role !== 'owner' && state === 'active')
    const roleControl = canChangeRole
      ? `<form class="role-control" method="post" action="/api/auth/people/role" data-auth-action data-reload="true"><input type="hidden" name="id" value="${escape(person.id)}">${csrfField(model.csrf)}<label class="visually-hidden" for="person-role-${escape(person.id)}">Role for ${escape(person.email)}</label><select id="person-role-${escape(person.id)}" name="role"><option value="member"${person.role === 'member' ? ' selected' : ''}>Member</option><option value="admin"${person.role === 'admin' ? ' selected' : ''}>Administrator</option></select><button class="secondary-button" type="submit">Update role</button></form>`
      : ''
    const directoryPerson = detail.get(person.id)
    const search = `${name} ${person.email} ${person.role ?? ''} ${person.status ?? ''} ${Object.values(directoryPerson?.fields ?? {}).map(f => f.value).join(' ')}`.toLocaleLowerCase()
    const edit = directoryPerson ? `<button class="secondary-button" type="button" data-edit-person="${escape(person.id)}" data-person="${escape(JSON.stringify(directoryPerson))}" aria-label="Edit ${escape(name)}">Edit</button>` : ''
    const controls = [roleControl, edit, suspend].filter(Boolean).join('')
    return `<tr class="person-row" data-person-row data-search="${escape(search)}"><td><span class="initials">${escape(initials(person.name) || '•')}</span></td><td><div class="person"><strong class="person-name">${escape(name)}</strong><span class="person-role">${escape(safeRole(person.role))}</span>${personDetail(directoryPerson)}</div></td><td><span class="mobile-label">Email</span><span class="email-text">${escape(person.email)}</span></td><td><span class="mobile-label">Status</span>${badge(person.status)}</td><td class="actions-cell">${controls}</td></tr>`
  }).join('')
}

const dialog = (id: string, title: string, description: string, action: string, fields: string, csrf?: string): string =>
  `<dialog class="toolbar-dialog" id="${id}" aria-labelledby="${id}-title"><h2 id="${id}-title">${title}</h2><p>${description}</p><form method="post" action="${action}" data-auth-action data-reload="true">${csrfField(csrf)}${fields}<div class="dialog-actions"><button class="quiet-button" type="button" data-close-dialog>Cancel</button><button class="primary-button" type="submit">${title}</button></div></form></dialog>`

export function renderPeoplePage(model: AuthPageModel): string {
  const people = asArray<AuthPerson>(model.people)
  const domains = asArray(model.domains)
  const domainList = domains.length
    ? `<div class="domain-list">${domains.map(item => `<span class="domain-chip">${escape(item.domain)}</span>`).join('')}</div>`
    : emptyState('No sign-in domains have been allowed.')
  const inviteFields = `<label for="invite-name">Name</label><input id="invite-name" name="name" autocomplete="name" maxlength="160" required><label for="invite-email">Email</label><input id="invite-email" name="email" type="email" autocomplete="email" maxlength="254" required>`
  const domainFields = `<label for="allow-domain">Domain</label><input id="allow-domain" name="domain" type="text" inputmode="url" autocomplete="off" maxlength="253" placeholder="company.example" required>`
  return `<div class="toolbar"><label class="search"><span class="visually-hidden">Search people by name, email, role, or status</span>${icon('search')}<input type="search" data-people-search placeholder="Search by name or email…" aria-label="Search people by name or email"></label><button class="action" type="button" data-open-dialog="invite-dialog">${icon('invite')}Invite person</button><button class="action" type="button" data-open-dialog="domain-dialog">${icon('lock')}Allow a domain</button>${model.directory ? `<button class="action" type="button" data-open-dialog="onboard-dialog">${icon('people')}Onboard worker</button>` : ''}<a class="action" href="/app/move-in">${icon('people')}Move people in</a></div><section class="table-panel people-table" aria-label="People"><div class="table-scroll" tabindex="0" role="region" aria-label="People table"><table><colgroup><col class="people-initials"><col class="people-name"><col class="people-email"><col class="people-status"><col class="people-access"></colgroup><thead><tr><th scope="col" aria-label="Initials"></th><th scope="col">Name and role</th><th scope="col">Email</th><th scope="col">Status</th><th scope="col" class="actions-cell">Access</th></tr></thead><tbody>${personRows(people, model)}<tr data-search-empty hidden><td colspan="5">No matching people.</td></tr></tbody></table></div><footer class="table-footer"><span data-people-count>${people.length} ${people.length === 1 ? 'person' : 'people'}</span></footer></section><section class="panel" aria-labelledby="domains-heading"><div class="panel-header"><div><h2 id="domains-heading">Allowed domains</h2><p>People with an email at an allowed domain can request an account.</p></div></div>${domainList}</section>${directoryPanels(model)}${domainPolicyPanel(model)}${onboardDialog(model)}${editDialog(model)}${dialog('invite-dialog', 'Invite person', 'Send an email link invitation to a person. First choose Confirm my email in <a href="/app/methods#email-confirmation">Sign-in methods</a> and complete the link in this browser within ten minutes.', '/api/auth/people/invite', inviteFields, model.csrf)}${dialog('domain-dialog', 'Allow a domain', 'Allow people with addresses at this domain to request an account. First choose Confirm my email in <a href="/app/methods#email-confirmation">Sign-in methods</a> and complete the link in this browser within ten minutes.', '/api/auth/people/domain', domainFields, model.csrf)}`
}
