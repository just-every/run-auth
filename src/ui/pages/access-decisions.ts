import { csrfField, emptyState, escape } from '../helpers.js'

export interface AccessDecisionPerson { id: string; email: string; name: string }
export interface AccessDecisionGroup {
  id: string
  name: string
  privileged: boolean
  owner: boolean
  members: AccessDecisionPerson[]
}
export interface AccessDecisionsModel {
  groups: AccessDecisionGroup[]
  people: AccessDecisionPerson[]
  canManage: boolean
  apps?: Array<{ id: string; name: string; privileged: boolean }>
}

const peopleOptions = (people: AccessDecisionPerson[]): string => people.map(person => `<option value="${escape(person.email)}">${escape(person.name || person.email)}</option>`).join('')

const privilegeForm = (kind: 'group' | 'app', target: { id: string; name: string; privileged: boolean }, csrf?: string): string =>
  `<form class="directory-form" method="post" action="/api/auth/decisions/privilege" data-access-form="privilege">${csrfField(csrf)}<input type="hidden" name="kind" value="${kind}"><input type="hidden" name="targetId" value="${escape(target.id)}"><label class="field">Access classification<select name="privileged" aria-label="Access classification for ${escape(target.name)}"><option value="false"${target.privileged ? '' : ' selected'}>Ordinary</option><option value="true"${target.privileged ? ' selected' : ''}>Privileged</option></select></label><button class="secondary-button" type="submit">Save classification</button><p data-access-result role="status"></p></form>`

export function decisionsPanel(model: { decisions?: AccessDecisionsModel; csrf?: string }): string {
  const data = model.decisions
  if (!data) return ''
  const groups = data.groups.map((group, index) => {
    const canDecide = data.canManage || (group.owner && !group.privileged)
    const members = group.members.length
      ? `<ul class="member-reasons">${group.members.map(person => `<li><strong>${escape(person.name || person.email)}</strong><span class="data-meta">${escape(person.email)}</span></li>`).join('')}</ul>`
      : '<p class="muted">No members.</p>'
    const form = canDecide ? `<form class="directory-form" method="post" action="/api/auth/decisions/options" data-access-decision="group">${csrfField(model.csrf)}<input type="hidden" name="targetId" value="${escape(group.id)}"><div class="directory-fields"><label class="field">Person's exact email or ID<input name="personId" list="decision-people-${index}" required autocomplete="off"><datalist id="decision-people-${index}">${peopleOptions(data.people)}</datalist></label><label class="field">Membership change<select name="operation" required><option value="add">Add to group</option><option value="remove">Remove from group</option></select></label><label class="field">Reason<input name="reason" required maxlength="500"></label></div><button class="primary-button" type="submit">Confirm membership with passkey</button><p data-access-result role="status"></p></form>` : ''
    return `<div class="data-row"><div><h3 class="issuer-host">${escape(group.name)}</h3><p>${group.owner ? 'You own this group. ' : ''}${group.privileged ? 'Privileged access: administrator approval required.' : 'Ordinary access.'}</p>${members}${form}${data.canManage ? privilegeForm('group', group, model.csrf) : ''}</div></div>`
  }).join('')
  const apps = data.canManage && data.apps?.length ? `<section class="panel stacked" data-access-classifications><h2>Privileged apps</h2><p>Groups assigned to a privileged app are protected too. Group owners cannot use ordinary membership decisions to grant or remove privileged access.</p><div class="data-list">${data.apps.map(app => `<div class="data-row"><div><h3 class="issuer-host">${escape(app.name)}</h3><p>${app.privileged ? 'Privileged' : 'Ordinary'} access</p>${privilegeForm('app', app, model.csrf)}</div></div>`).join('')}</div></section>` : ''
  return `<section class="panel stacked" data-access-decisions><div class="panel-header"><div><h2>Group access decisions</h2><p>Group owners decide ordinary membership with a reason and a passkey. Each confirmation applies only to that exact change. Privileged access requires an administrator.</p></div></div>${groups ? `<div class="data-list">${groups}</div>` : emptyState('No groups are available for access decisions.')}</section>${apps}<script src="/auth-assets/decisions-ui.js" defer></script>`
}
