// The workforce directory on People: onboarding, editing a person with where each
// value came from, a previewed bulk edit, and groups with a rule and the reason
// for each member. Forms post to the directory doors; public/auth-assets/directory-ui.js drives them.
import type { AuthPageModel, DirectoryAttribute, DirectoryGroup, DirectoryPerson } from '../model.js'
import { asArray, csrfField, emptyState, escape } from '../helpers.js'

const KINDS = [['employee', 'Employee'], ['contractor', 'Contractor'], ['service', 'Service identity']]
const EMPLOYMENT = [['w2', 'W-2'], ['1099', '1099 contractor'], ['other', 'Other']]
const STATES = [['active', 'Active'], ['suspended', 'Suspended'], ['terminated', 'Terminated']]
const STATE_LABELS: Record<string, string> = { invited: 'Invited', active: 'Active', suspended: 'Suspended', terminated: 'Terminated' }

const options = (list: string[][], blank?: string): string => `${blank === undefined ? '' : `<option value="">${escape(blank)}</option>`}${list.map(([value, label]) => `<option value="${escape(value)}">${escape(label)}</option>`).join('')}`
const input = (id: string, name: string, label: string, type = 'text', extra = ''): string => `<div class="field"><label for="${id}">${escape(label)}</label><input id="${id}" name="${escape(name)}" type="${type}" maxlength="160" ${extra}></div>`
const select = (id: string, name: string, label: string, list: string[][], blank?: string): string => `<div class="field"><label for="${id}">${escape(label)}</label><select id="${id}" name="${escape(name)}">${options(list, blank)}</select></div>`

const customInput = (prefix: string, attribute: DirectoryAttribute): string => {
  const id = `${prefix}-${attribute.key.replace('.', '-')}`
  if (attribute.type === 'choice') return select(id, attribute.key, attribute.label, (attribute.choices ?? []).map(c => [c, c]), 'No change')
  if (attribute.type === 'boolean') return select(id, attribute.key, attribute.label, [['true', 'Yes'], ['false', 'No']], 'No change')
  return input(id, attribute.key, attribute.label, attribute.type === 'number' ? 'text' : attribute.type === 'date' ? 'date' : 'text')
}

const workerFields = (prefix: string, attributes: DirectoryAttribute[], people: DirectoryPerson[]): string =>
  `${select(`${prefix}-kind`, 'kind', 'Worker type', KINDS)}${select(`${prefix}-employment`, 'employment_type', 'Employment', EMPLOYMENT, 'Not set')}${input(`${prefix}-title`, 'title', 'Job title')}${input(`${prefix}-department`, 'department', 'Department')}${input(`${prefix}-location`, 'location', 'Location')}${select(`${prefix}-manager`, 'manager', 'Manager', people.map(p => [p.id, p.name || p.email]), 'No change')}${input(`${prefix}-start`, 'start_date', 'Start date', 'date')}${input(`${prefix}-end`, 'end_date', 'End date', 'date')}${attributes.filter(a => !a.standard).map(a => customInput(prefix, a)).join('')}`

export const onboardDialog = (model: AuthPageModel): string => {
  const directory = model.directory
  if (!directory) return ''
  const fields = `${input('onboard-name', 'name', 'Name', 'text', 'autocomplete="name" required')}${input('onboard-email', 'email', 'Work email', 'email', 'autocomplete="email" required')}${workerFields('onboard', directory.attributes, directory.people)}`
  return `<dialog class="toolbar-dialog directory-dialog" id="onboard-dialog" aria-labelledby="onboard-dialog-title"><h2 id="onboard-dialog-title">Onboard worker</h2><p>Add an employee, contractor or service identity with their directory values. They receive one invitation; their dynamic groups are evaluated at once.</p><form method="post" action="/api/auth/directory/onboard" data-auth-action data-reload="true">${csrfField(model.csrf)}<div class="directory-fields">${fields}</div><div class="dialog-actions"><button class="quiet-button" type="button" data-close-dialog>Cancel</button><button class="primary-button" type="submit">Onboard worker</button></div></form></dialog>`
}

export const editDialog = (model: AuthPageModel): string => {
  const directory = model.directory
  if (!directory) return ''
  const fields = `${input('edit-name', 'name', 'Name', 'text', 'required')}${input('edit-email', 'email', 'Work email', 'email', 'required')}${select('edit-state', 'state', 'State', STATES)}${workerFields('edit', directory.attributes, directory.people)}`
  return `<dialog class="toolbar-dialog directory-dialog" id="edit-dialog" aria-labelledby="edit-dialog-title"><h2 id="edit-dialog-title">Edit person</h2><p data-edit-sources>Values you change here override what a source sends; the source's value stays visible until you accept it.</p><form method="post" action="/api/auth/directory/edit" data-directory-edit>${csrfField(model.csrf)}<input type="hidden" name="personId"><div class="directory-fields">${fields}</div><div class="dialog-actions"><button class="quiet-button" type="button" data-close-dialog>Cancel</button><button class="primary-button" type="submit">Save changes</button></div></form></dialog>`
}

// The line under a person's name: type, department, location, and a flag when sources disagree.
export const personDetail = (person?: DirectoryPerson): string => {
  if (!person) return ''
  const value = (key: string) => person.fields[key]?.value
  const parts = [KINDS.find(([k]) => k === value('kind'))?.[1], value('department'), value('location')].filter(Boolean).map(escape).join(' · ')
  const conflict = person.conflicts.length ? `<span class="finding finding-conflict">Source conflict: ${escape(person.conflicts.map(c => c.field).join(', '))}</span>` : ''
  const state = person.state === 'terminated' ? ' <span class="muted">Terminated</span>' : ''
  return `<span class="person-detail">${parts}${state}</span>${conflict}`
}

const ruleText = (group: DirectoryGroup): string => group.rule
  ? `Members match ${group.rule.match === 'any' ? 'any' : 'all'} of: ${group.rule.conditions.map(c => c.op === 'present' ? `${c.field} is set` : c.op === 'absent' ? `${c.field} is not set` : c.op === 'in' ? `${c.field} is one of ${(c.values ?? []).join(', ')}` : `${c.field} ${c.op === 'eq' ? 'is' : 'is not'} ${c.value}`).join('; ')}`
  : 'Static group: members are added by an administrator.'

const groupRow = (group: DirectoryGroup): string => {
  const members = group.members.length
    ? `<ul class="member-reasons">${group.members.map(m => `<li><strong>${escape(m.email ?? m.id)}</strong> <span class="data-meta">${m.via === 'manual' ? 'Added by an administrator' : `Matches the rule: ${escape((m.why ?? []).join('; '))}`}</span></li>`).join('')}</ul>`
    : '<p class="muted">No members.</p>'
  const excluded = group.excluded.length ? `<p class="data-meta">Excluded from the rule: ${group.excluded.map(x => escape(x.email ?? x.id)).join(', ')}</p>` : ''
  const apps = group.apps.length ? `<p class="data-meta">Assigned: ${group.apps.map(a => `${escape(a.app)}${a.role ? ` as ${escape(a.role)}` : ''}`).join(', ')}</p>` : ''
  const owners = group.owners.length ? `<p class="data-meta">Owners: ${group.owners.map(o => escape(o.email ?? o.id)).join(', ')}</p>` : ''
  return `<div class="data-row group-row"><div><strong>${escape(group.name)}</strong><p class="data-meta">${escape(ruleText(group))}</p>${owners}${apps}${excluded}${members}</div></div>`
}

export function directoryPanels(model: AuthPageModel): string {
  const directory = model.directory
  if (!directory) return ''
  const fieldOptions = directory.attributes.filter(a => a.type !== 'person').map(a => [a.key, a.label])
  const groups = asArray(directory.groups)
  const groupList = groups.length ? `<div class="data-list">${groups.map(groupRow).join('')}</div>` : emptyState('No groups yet. Create one on Apps, then give it a rule here.')
  const bulk = `<section class="panel stacked directory-bulk" aria-labelledby="bulk-heading"><div class="panel-header"><div><h2 id="bulk-heading">Bulk edit</h2><p>Choose who, choose the change, and preview who is affected, which groups and apps they gain or lose, and what is refused. Nothing changes until you apply the exact preview.</p></div></div><form class="directory-form" data-directory-bulk>${csrfField(model.csrf)}<fieldset><legend>Who</legend><div class="directory-fields">${select('bulk-state', 'filterState', 'State', STATES, 'Any state')}${select('bulk-kind', 'filterKind', 'Worker type', KINDS, 'Any type')}${input('bulk-from-department', 'filterDepartment', 'Department is')}${input('bulk-from-location', 'filterLocation', 'Location is')}</div></fieldset><fieldset><legend>Change</legend><div class="directory-fields">${input('bulk-department', 'department', 'Move to department')}${input('bulk-location', 'location', 'Move to location')}${input('bulk-title', 'title', 'Set job title')}${select('bulk-set-state', 'state', 'Set state', STATES, 'Keep state')}</div></fieldset><div class="button-row"><button class="secondary-button" type="submit" data-bulk-preview>Preview</button><button class="primary-button" type="button" data-bulk-apply disabled>Apply preview</button></div></form><div class="bulk-result" data-bulk-result hidden aria-live="polite"></div></section>`
  const rule = `<form class="directory-form" data-group-rule>${csrfField(model.csrf)}<div class="directory-fields">${select('rule-group', 'groupId', 'Group', groups.map(g => [g.id, g.name]))}${select('rule-field', 'field', 'Where', fieldOptions)}${select('rule-op', 'op', 'Condition', [['eq', 'is'], ['neq', 'is not'], ['in', 'is one of (comma separated)'], ['present', 'is set'], ['absent', 'is not set']])}${input('rule-value', 'value', 'Value')}</div><div class="button-row"><button class="secondary-button" type="submit" data-rule-preview>Preview rule</button><button class="primary-button" type="button" data-rule-set disabled>Set rule</button><button class="quiet-button" type="button" data-rule-clear>Clear rule</button></div><div class="bulk-result" data-rule-result hidden aria-live="polite"></div></form>`
  const groupsPanel = `<section class="panel stacked directory-groups" aria-labelledby="directory-groups-heading"><div class="panel-header"><div><h2 id="directory-groups-heading">Groups and rules</h2><p>A rule adds everyone whose directory values match; people an administrator removed stay out. Each member shows why they are in.</p></div></div>${groups.length ? rule : ''}${groupList}</section>`
  return `${bulk}${groupsPanel}<script src="/auth-assets/directory-ui.js" defer></script>`
}
