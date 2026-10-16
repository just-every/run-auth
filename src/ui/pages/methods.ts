import { domainPolicyPanel } from './domain-policy.js'
import type { AuthPageModel, AuthPasskey, RerTrustKey } from '../model.js'
import { asArray, dateText, emptyState, escape, csrfField } from '../helpers.js'

const passkeyRows = (passkeys: AuthPasskey[]): string => passkeys.length
  ? `<div class="data-list">${passkeys.map((passkey, index) => `<div class="data-row"><strong>Passkey ${index + 1}</strong><span class="data-meta">Added ${escape(dateText(passkey.created_at ?? passkey.createdAt))}</span><span class="data-meta">${passkey.last_used_at ?? passkey.lastUsedAt ? `Last used ${escape(dateText(passkey.last_used_at ?? passkey.lastUsedAt))}` : 'Not used yet'}</span></div>`).join('')}</div>`
  : emptyState('No passkeys are registered for this account.')

// RER Managed trust: who may sign link approvals for this install, and how to withdraw it.
const rerTrustPanel = (model: AuthPageModel): string => {
  if (!model.isAdmin) return ''
  const keys = asArray<RerTrustKey>(model.rerTrust)
  const rows = keys.length ? `<div class="data-list">${keys.map(key => `<div class="data-row"><strong>${escape(key.kid)}</strong><span class="data-meta">${key.source === 'provisioned' ? 'Set by RER when it installed Auth' : `Added ${escape(dateText(key.added_at))}`}</span>${key.withdrawn_at ? `<span class="pill">Withdrawn ${escape(dateText(key.withdrawn_at))}</span>` : `<form class="button-row" method="post" action="/api/auth/rer-trust/withdraw" data-auth-action data-reload="true" data-confirm="Withdraw RER's trust? RER will no longer be able to link apps to this issuer."><input type="hidden" name="kid" value="${escape(key.kid)}">${csrfField(model.csrf)}<button class="danger-button" type="submit">Withdraw trust</button></form>`}</div>`).join('')}</div>` : emptyState('RER cannot link apps to this issuer.')
  return `<section class="panel stacked rer-trust" aria-labelledby="rer-trust-heading"><div class="panel-header"><div><h2 id="rer-trust-heading">RER Managed</h2><p>A trusted RER account key can link the apps it admits to this issuer, without anyone typing a token. Each link is flagged on Apps and announced to administrators. Withdraw it at any time; leaving Managed withdraws it too.</p></div></div>${rows}<form class="inline-form" method="post" action="/api/auth/rer-trust/add" data-auth-action data-reload="true">${csrfField(model.csrf)}<div class="field"><label for="rer-trust-key">RER account key (JSON from RER)</label><textarea id="rer-trust-key" name="key" rows="3" required></textarea></div><button class="secondary-button" type="submit">Trust this RER key</button></form></section>`
}

export function renderMethodsPage(model: AuthPageModel): string {
  const passkeys = asArray<AuthPasskey>(model.passkeys ?? model.methods)
  const amr = model.user?.amr ?? model.me?.amr ?? []
  const canEnroll = amr.includes('hwk') || (passkeys.length === 0 && amr.includes('email'))
  const enrollment = canEnroll
    ? '<button class="primary-button" type="button" data-passkey-enroll>Register a passkey</button>'
    : `<p>${passkeys.length ? 'Sign in with your existing passkey to register another.' : 'Confirm your email in this browser before registering your first passkey.'}</p><a class="primary-button" href="/signin?returnTo=%2Fapp%2Fmethods">${passkeys.length ? 'Sign in with your passkey' : 'Confirm your email'}</a>`
  const currentUser = model.user ?? model.me
  const confirmEmail = `<form method="post" action="/auth/identity/email/request" data-auth-action data-email-request>${csrfField(model.csrf)}<input type="hidden" name="email" value="${escape(currentUser?.email)}"><input type="hidden" name="returnTo" value="/app/methods"><button class="secondary-button" type="submit">Confirm my email</button></form>`
  const authenticate = passkeys.length && !amr.includes('hwk') ? '<button class="secondary-button" type="button" data-passkey-authenticate data-return-to="/app/methods">Continue with a passkey</button>' : ''
  const providers = asArray(model.providers).filter(provider => provider.visible === true && ['google', 'microsoft', 'okta'].includes(provider.preset))
  const providerState = providers.length
    ? `<div class="data-list">${providers.map(provider => `<div class="data-row"><strong>${escape(provider.label)}</strong><span></span><span class="pill accent">Available</span></div>`).join('')}</div>`
    : emptyState('No upstream provider configuration is available for this issuer.')
  return `<div class="section-grid"><section class="panel method-panel" id="email-confirmation"><img class="method-door" src="/brand/door-small.webp" alt="" width="60" height="88"><div class="panel-header"><div><h2>Email links</h2><p>Domain rules apply to email sign-in.</p></div></div><p>Confirm your email in this browser before your first passkey. If your domain requires a provider, sign in with that provider first.</p><p>Registering a passkey, completing or approving a recovery, and every administrator change (people, roles, domains, provider rules and signing keys) need a confirmation here within the last ten minutes. Complete the email link in this browser; your active passkey session stays available.</p>${confirmEmail}</section><section class="panel method-panel"><img class="method-door" src="/brand/door-small.webp" alt="" width="60" height="88"><div class="panel-header"><div><h2>Passkeys</h2><p>Passkeys are bound to this issuer host.</p></div><span class="pill accent">${passkeys.length} registered</span></div><div class="button-row">${enrollment}${authenticate}</div></section></div><section class="panel"><div class="panel-header"><div><h2>Registered passkeys</h2><p>Passkey sign-in must be re-confirmed by email every 30 days.</p></div></div>${passkeyRows(passkeys)}</section><section class="panel stacked"><div class="panel-header"><div><h2>Upstream providers</h2><p>Optional identity providers connected to this issuer.</p></div></div>${providerState}</section>${domainPolicyPanel(model)}${rerTrustPanel(model)}`
}
