// My account: the employee's own profile, with who holds each value they cannot
// change, and the sign-in providers connected to the account.
import type { AuthPageModel, ProfileField } from '../model.js'
import { csrfField, escape } from '../helpers.js'

const HOLDERS: Record<string, string> = {
  hr: 'Managed by your HR system',
  directory: 'Managed by your company directory',
  manual: 'Set by an administrator',
}

// An editable field saves as it changes; its quiet state sits beside the label.
const labelRow = (id: string, text: string): string => `<div class="label-row"><label for="${id}">${escape(text)}</label><span class="save-state" data-save-state role="status"></span></div>`

const control = (field: ProfileField): string => {
  const id = `profile-${field.key.replace('.', '-')}`
  const value = field.value ?? ''
  if (!field.editable) return `<div class="field"><span class="form-label">${escape(field.label)}</span><span class="field-value">${escape(value) || '<span class="muted">Not set</span>'}</span>${HOLDERS[field.protectedBy ?? ''] ? `<span class="data-meta">${escape(HOLDERS[field.protectedBy ?? ''])}</span>` : ''}</div>`
  if (field.type === 'choice') return `<div class="field">${labelRow(id, field.label)}<select id="${id}" name="${escape(field.key)}"><option value="">Not set</option>${(field.choices ?? []).map(c => `<option value="${escape(c)}"${c === value ? ' selected' : ''}>${escape(c)}</option>`).join('')}</select></div>`
  if (field.type === 'boolean') return `<div class="field">${labelRow(id, field.label)}<select id="${id}" name="${escape(field.key)}"><option value="">Not set</option><option value="true"${value === 'true' ? ' selected' : ''}>Yes</option><option value="false"${value === 'false' ? ' selected' : ''}>No</option></select></div>`
  return `<div class="field">${labelRow(id, field.label)}<input id="${id}" name="${escape(field.key)}" type="${field.type === 'date' ? 'date' : 'text'}" maxlength="160" value="${escape(value)}"></div>`
}

export function profilePanels(model: AuthPageModel): string {
  const profile = model.profile
  if (!profile) return ''
  const shown = profile.fields.filter(f => f.editable || f.value)
  const form = `<form class="directory-form" method="post" action="/api/auth/profile/update" data-profile-autosave>${csrfField(model.csrf)}<div class="directory-fields">${shown.map(control).join('')}</div></form>`
  const rows = profile.providers.map(p => p.linked
    ? `<div class="data-row"><strong>${escape(p.label)}</strong><span class="pill accent">Connected</span><form class="button-row" method="post" action="/api/auth/profile/links/unlink" data-auth-action data-reload="true" data-confirm="Disconnect ${escape(p.label)} from your account? You can still sign in the other ways listed here.">${csrfField(model.csrf)}<input type="hidden" name="providerId" value="${escape(p.id)}"><input type="hidden" name="confirm" value="true"><button class="danger-button" type="submit" aria-label="Disconnect ${escape(p.label)}">Disconnect</button></form></div>`
    : `<div class="data-row"><strong>${escape(p.label)}</strong><span class="pill">Not connected</span><button class="secondary-button" type="button" data-link-start="${escape(p.id)}" data-confirm="Connect ${escape(p.label)} to your account? You will sign in with it now to prove it is yours." aria-label="Connect ${escape(p.label)}">Connect</button></div>`).join('')
  const providers = profile.providers.length
    ? `<section class="panel row-panel stacked" aria-labelledby="providers-heading"><div class="panel-header"><div><h2 id="providers-heading">Connected sign-in providers</h2><p>Connect another provider you already use at work. Auth asks you to confirm your email in this browser, then to sign in with the provider; an address that belongs to another person, or an identity already connected elsewhere, is refused.</p></div></div><div class="data-list">${rows}</div></section>`
    : ''
  return `<section class="panel stacked" aria-labelledby="profile-heading"><div class="panel-header"><div><h2 id="profile-heading">Profile</h2><p>Change the details you may change. Details your company manages show who holds them.</p></div></div>${form}</section>${providers}<script src="/auth-assets/profile-ui.js" defer></script>`
}
