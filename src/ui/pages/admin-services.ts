import type { AdminService, AuthPageModel, AuthPerson } from '../model.js'
import { asArray, csrfField, emptyState, escape, timeElement } from '../helpers.js'

const scopeGroups: Array<[string, string[]]> = [
  ['People', ['people.read', 'people.manage']], ['Groups', ['groups.read', 'groups.manage']],
  ['Apps', ['apps.read', 'apps.manage']], ['Assignments', ['assignments.read', 'assignments.manage']],
  ['Policies', ['policies.read', 'policies.manage']], ['Identity providers', ['idps.read', 'idps.manage']],
  ['Domains', ['domains.read']], ['Activity', ['logs.read']],
]
const ownerOptions = (people: AuthPerson[], selected = ''): string => people.map(person =>
  `<option value="${escape(person.id)}"${person.id === selected ? ' selected' : ''}>${escape(person.name && person.name !== person.email ? `${person.name} · ${person.email}` : person.email)} (${person.role === 'owner' ? 'Owner' : person.role === 'admin' ? 'Administrator' : 'Scoped custodian'})</option>`).join('')

const field = (id: string, label: string, input: string, hint = ''): string =>
  `<div class="field"><label for="${escape(id)}">${label}</label>${input}${hint ? `<p class="data-meta" id="${escape(id)}-hint">${hint}</p>` : ''}</div>`

const resourceList = (resources: AdminService['resources']): string => ['people', 'groups', 'apps'].map(kind => {
  const ids = resources[kind as keyof typeof resources]
  return `${kind}: ${ids.includes('*') ? 'all' : ids.length ? ids.join(', ') : 'none'}`
}).join('; ')

const serviceCard = (app: AdminService, people: AuthPerson[], model: AuthPageModel): string => {
  const statusLabels = { active: 'Active', suspended: 'Suspended', expired: 'Expired', revoked: 'Revoked' }
  const statusClass = app.status === 'active' ? 'active' : app.status === 'expired' ? 'invited' : 'suspended'
  const details: Array<[string, string]> = [
    ['Purpose', escape(app.purpose)], ['Client ID', `<code>${escape(app.clientId)}</code>`],
    ['Accountable owner', escape(app.ownerName && app.ownerEmail ? `${app.ownerName} · ${app.ownerEmail}` : app.ownerEmail ?? app.ownerId)],
    ['Scopes', escape(app.scopes.join(', '))], ['Resources', escape(resourceList(app.resources))],
    ['Allowed IPs', escape(app.allowedIps.join(', ') || 'Any IP address')],
    ['Created', timeElement(app.createdAt)], ['Expires', timeElement(app.expiresAt)],
    ['Last used', app.lastUsedAt ? timeElement(app.lastUsedAt) : 'Not used yet'],
  ]
  if (app.revokedAt) details.push(['Revoked', timeElement(app.revokedAt)])
  if (app.status === 'suspended') details.push(['Suspension', escape(app.suspensionReason?.replace(/_/g, ' ') || 'Its owner is no longer an active administrator or owner')])
  const canManage = app.status !== 'revoked'
  const reassign = canManage && model.isAdmin && people.length ? `<form class="inline-form" method="post" action="/api/auth/admin-service-apps/reassign" data-auth-action data-reload="true" data-confirm="${escape(`Reassign ${app.name}? Existing access tokens stop working. A suspended app resumes if its new owner is active and it has not expired.`)}">${csrfField(model.csrf)}<input type="hidden" name="id" value="${escape(app.id)}">${field(`service-owner-${app.id}`, 'Accountable owner', `<select id="service-owner-${escape(app.id)}" name="ownerId" required><option value="">Choose an administrator</option>${ownerOptions(people, app.ownerId)}</select>`)}<button type="submit" aria-label="Reassign ${escape(app.name)}">Reassign owner</button></form>` : ''
  const revoke = canManage ? `<form method="post" action="/api/auth/admin-service-apps/revoke" data-auth-action data-reload="true" data-confirm="${escape(`Revoke ${app.name}? This permanently stops the service app and its existing access tokens.`)}">${csrfField(model.csrf)}<input type="hidden" name="id" value="${escape(app.id)}"><button class="danger-button" type="submit" aria-label="Revoke ${escape(app.name)}">Revoke service app</button></form>` : ''
  return `<article class="panel" data-admin-service="${escape(app.id)}"><div class="panel-header"><div><h3 class="issuer-host">${escape(app.name)}</h3></div><span class="status-pill ${statusClass}">${statusLabels[app.status]}</span></div><dl class="effect-list">${details.map(([label, value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`).join('')}</dl>${reassign}${revoke ? `<div class="button-row">${revoke}</div>` : ''}</article>`
}

const createForm = (people: AuthPerson[], model: AuthPageModel): string => {
  const scoped=!model.isAdmin,allowed=model.adminServiceCustody?.scopes
  const scopes = scopeGroups.map(([label, values]) => [label,values.filter(scope=>!allowed||allowed.includes(scope))] as [string,string[]]).filter(([,values])=>values.length).map(([label, values]) => `<div class="field"><strong>${label}</strong>${values.map(scope => `<label class="checkbox"><input type="checkbox" name="scopes" value="${scope}"> ${scope.endsWith('.manage') ? 'Manage' : 'Read'} <span class="data-meta">${scope}</span></label>`).join('')}</div>`).join('')
  return `<section class="panel" aria-labelledby="admin-service-create-heading"><div class="panel-header"><div><h3 id="admin-service-create-heading">Create a service app</h3><p>Generate the signing key in your service and paste only its public JWKS here. Auth registers the client ID; the private key stays with your service. Authentication uses <code>private_key_jwt</code>.</p></div></div>
    <form class="inline-form directory-form" method="post" action="/api/auth/admin-service-apps/create" data-auth-action data-admin-service-create data-reload="true">${csrfField(model.csrf)}
      <div class="field-grid">
        ${field('admin-service-name', 'App name', '<input id="admin-service-name" name="name" maxlength="80" required autocomplete="off">')}
        ${field('admin-service-owner', 'Accountable owner', `<select id="admin-service-owner" name="ownerId" required><option value="">${scoped?'Your scoped account':'Choose an administrator'}</option>${ownerOptions(people, (model.user ?? model.me)?.id)}</select>`)}
      </div>
      ${field('admin-service-purpose', 'Purpose', '<textarea id="admin-service-purpose" name="purpose" rows="2" maxlength="1000" required aria-describedby="admin-service-purpose-hint"></textarea>', 'Describe the work this service is allowed to do.')}
      ${field('admin-service-jwks', 'Public signing keys (JWKS JSON)', '<textarea id="admin-service-jwks" name="jwks" rows="5" required spellcheck="false" autocomplete="off" aria-describedby="admin-service-jwks-hint"></textarea>', 'Use one to five public RS256 or ES256 keys. Never paste a private key. Multiple keys need distinct key IDs (kid).')}
      <fieldset aria-describedby="admin-service-scopes-hint"><legend>Granted scopes</legend><p class="data-meta" id="admin-service-scopes-hint">Select at least one. Grant only what this service needs.</p><div class="field-grid">${scopes}</div></fieldset>
      <div class="field-grid">
        ${field('admin-service-resources', scoped?'Resource limits (JSON)':'Resource limits (optional JSON)', `<textarea id="admin-service-resources" name="resources" rows="4" spellcheck="false" aria-describedby="admin-service-resources-hint"${scoped?' required':''}>${scoped?escape(JSON.stringify({people:[],groups:[],apps:[]},null,2)):''}</textarea>`, scoped?'List explicit IDs under <code>people</code>, <code>groups</code>, and <code>apps</code>; <code>[]</code> allows none. One held role grant must cover every selected scope and resource. All-resource wildcards are refused.':'Keys: <code>people</code>, <code>groups</code>, <code>apps</code>; values are arrays of IDs. <code>["*"]</code> allows all; <code>[]</code> allows none. A blank field or omitted category allows all resources in that category.')}
        ${field('admin-service-ips', 'Allowed IP addresses (optional)', '<textarea id="admin-service-ips" name="allowedIps" rows="4" spellcheck="false" aria-describedby="admin-service-ips-hint"></textarea>', 'One exact IPv4/IPv6 address or CIDR range per line. Blank allows any IP address.')}
      </div>
      ${field('admin-service-expiry', 'Expires (your local time)', '<input id="admin-service-expiry" name="expiresAt" type="datetime-local" required aria-describedby="admin-service-expiry-hint">', 'Choose a future date within 365 days. After expiry, create a new service app.')}
      <button class="primary-button" type="submit"${people.length&&(!scoped||allowed?.length)?'':' disabled'}>Create service app</button>
      ${people.length ? '' : '<p class="data-meta">An active administrator or owner is required before a service app can be created.</p>'}
      ${scoped&&!allowed?.length?'<p class="data-meta">Your current role grants do not cover any service scopes.</p>':''}
    </form></section>`
}

export function adminServicesPanel(model: AuthPageModel): string {
  if (!model.isAdmin&&!model.adminServiceCustody) return ''
  const apps = asArray(model.adminServices)
  const current=model.user ?? model.me
  const people = model.isAdmin?asArray(model.people).filter(person => person.status === 'active' && ['admin', 'owner'].includes(person.role ?? '')):current?[current]:[]
  const confirmation = model.localEmailConfirmed
    ? 'Your email is confirmed in this browser. Creating or managing a service app requires a passkey sign-in and email confirmation within the last ten minutes.'
    : 'Before creating or managing a service app, sign in with your passkey and confirm your email in this browser. Complete the email link, then retry within ten minutes.'
  return `<section class="panel" aria-labelledby="admin-services-heading"><div class="panel-header"><div><h2 id="admin-services-heading">Admin service apps</h2><p>Give a service direct access to the Auth Admin API with explicit scopes, resource limits, expiry and an accountable administrator. Service apps use their own signing keys and receive no client secret.</p></div><span class="pill">${apps.filter(app => app.status === 'active').length} active</span></div><p>${confirmation} <a href="/app/methods#email-confirmation">Sign-in methods</a></p>${apps.length ? `<div class="directory-form">${apps.map(app => serviceCard(app, people, model)).join('')}</div>` : emptyState('No Admin service apps have been created.')}${createForm(people, model)}</section>`
}
