import type { AuthProvider, SignInPageModel } from '../model.js'
import { csrfField, escape, hostLabel, localReturnTo, noticeBox } from '../helpers.js'
import { brandLockup, documentHead } from '../shell.js'

const providerAction = (provider: AuthProvider): string | null => {
  if (!['google', 'microsoft', 'okta', 'oidc', 'saml'].includes(provider.preset)) return null
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(provider.id)) return null
  const expected = `/auth/${provider.preset === 'saml' ? 'saml' : 'oidc'}/${provider.id}/start`
  return provider.startPath === expected ? expected : null
}

export function renderSignInPage(model: SignInPageModel): string {
  const returnTo = localReturnTo(model.returnTo)
  const notice = model.notice ? noticeBox(model.notice) : ''
  const providers = (model.providers ?? []).flatMap(provider => {
    if (provider.visible !== true) return []
    const action = providerAction(provider)
    return action ? [{ provider, action }] : []
  })
  const providerForms = providers.map(({ provider, action }) => `<form class="provider-form" method="post" action="${escape(action)}"><input type="hidden" name="returnTo" value="${escape(returnTo)}">${csrfField(model.csrf)}<button class="secondary-button" type="submit">Continue with ${escape(provider.label)}</button></form>`).join('')
  const providerContent = providerForms ? `<div class="provider-list" role="group" aria-label="Configured sign-in providers">${providerForms}</div><div class="signin-divider"><span>or</span></div>` : ''
  return `<!doctype html><html lang="en"><head>${documentHead('Sign in — Auth')}</head><body><main class="app-signin"><img class="signin-door" src="/brand/door.webp" alt="" width="620" height="910"><section class="signin-card" aria-labelledby="signin-title">${brandLockup()}<h1 id="signin-title">Sign in to Auth</h1><p>Use your email address or a passkey for ${escape(hostLabel(model.issuer))}.</p>${notice}<div class="notice-list"><div class="notice-panel" data-auth-status data-kind="info" role="status" aria-live="polite"></div></div>${providerContent}<form method="post" action="/auth/identity/email/request" data-auth-action data-email-request><input type="hidden" name="returnTo" value="${escape(returnTo)}">${csrfField(model.csrf)}<label for="signin-email">Email address</label><input id="signin-email" type="email" name="email" autocomplete="email" maxlength="254" required><button class="primary-button" type="submit">Email me a sign-in link</button></form><details><summary>Use a temporary access pass</summary><form method="post" action="/auth/identity/temporary-pass" data-auth-action data-redirect="/app/methods"><label for="temporary-pass">Temporary access pass</label><input id="temporary-pass" name="pass" type="password" autocomplete="off" required><button class="secondary-button">Continue to enrollment</button></form></details><div class="signin-divider"><span>or</span></div><button class="secondary-button" type="button" data-passkey-authenticate data-return-to="${escape(returnTo)}">Continue with a passkey</button><p class="signin-host">To ask for erasure of an employer membership, contact that employer’s Auth owner. Each employer holds its memberships separately.</p><div class="signin-host">Issuer host<br><strong>${escape(hostLabel(model.issuer))}</strong></div></section></main></body></html>`
}
