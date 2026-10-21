import type { AuthPageModel } from '../model.js'
import { escape } from '../helpers.js'

export function renderOrganizationsPage(model: AuthPageModel): string {
 const organizations = model.organizations
 if (!organizations) return '<section class="availability">Sign in to choose an organization.</section>'
 const rows = organizations.memberships.map(member => `<div class="data-row"><div><strong>${escape(member.name)}</strong><p>${escape(member.role)}${member.active ? ' · Active organization' : ''}</p></div>${member.active ? '' : `<form class="directory-form" action="/api/auth/organizations/switch" method="post" data-auth-action data-organization-switch><input type="hidden" name="organizationId" value="${escape(member.id)}"><button class="secondary-button">Switch to ${escape(member.name)}</button></form>`}</div>`).join('')
 const create = organizations.canCreate ? `<section class="panel"><div class="panel-header"><div><h2>Create an organization</h2><p>Start an isolated employer directory. Confirm your email and enroll a passkey there before administering it.</p></div></div><form class="directory-form" action="/api/auth/organizations/create" method="post" data-auth-action data-organization-create><label class="field">Organization name<input name="name" required maxlength="100" autocomplete="organization"></label><button class="primary-button">Create organization</button><p data-organization-result role="status"></p></form></section>` : ''
 return `<section class="panel"><div class="panel-header"><div><h2>Your memberships</h2><p>Each employer has its own directory, permissions, apps and sign-in proofs. Only memberships signed in in this browser appear here.</p></div></div><div class="data-list">${rows}</div></section>${create}`
}
