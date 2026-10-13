import type { AuthProvider, SignInPageModel } from '../model.js'
import { csrfField, escape, hostLabel, localReturnTo, noticeBox } from '../helpers.js'
import { iconDefinitions } from '../icons.js'

const providerAction = (provider: AuthProvider): string | null => {
  if (!['google', 'microsoft', 'okta'].includes(provider.preset)) return null
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(provider.id)) return null
  const expected = `/auth/oidc/${provider.id}/start`
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
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Sign in — Auth</title><link rel="stylesheet" href="/auth-assets/auth.css"><script src="/auth-assets/auth-ui.js" defer></script></head><body>${iconDefinitions}<main class="app-signin"><section class="signin-card" aria-labelledby="signin-title"><div class="signin-brand"><svg viewBox="0 0 32 36" aria-hidden="true"><use href="#shield"></use></svg><div><strong>Auth</strong><p>Identity for your business</p></div></div><h1 id="signin-title">Sign in to Auth</h1><p>Use your email address or a passkey for ${escape(hostLabel(model.issuer))}.</p>${notice}<div class="notice-list"><div class="notice-panel" data-auth-status data-kind="info" role="status" aria-live="polite"></div></div>${providerContent}<form method="post" action="/auth/identity/email/request" data-auth-action data-email-request><input type="hidden" name="returnTo" value="${escape(returnTo)}">${csrfField(model.csrf)}<label for="signin-email">Email address</label><input id="signin-email" type="email" name="email" autocomplete="email" maxlength="254" required><button class="primary-button" type="submit">Email me a sign-in link</button></form><div class="signin-divider"><span>or</span></div><button class="secondary-button" type="button" data-passkey-authenticate data-return-to="${escape(returnTo)}">Continue with a passkey</button><div class="signin-host">Issuer host<br><strong>${escape(hostLabel(model.issuer))}</strong></div></section></main></body></html>`
}
