// My account: start connecting a provider. The provider's own sign-in follows.
(() => {
  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-link-start]')
    if (!button) return
    if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return
    button.disabled = true
    const show = (message, kind) => { for (const el of document.querySelectorAll('[data-auth-status]')) { el.textContent = message; el.dataset.kind = kind; el.hidden = false; el.setAttribute('role', kind === 'error' ? 'alert' : 'status') } }
    try {
      const response = await fetch('/api/auth/profile/links/start', { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ providerId: button.dataset.linkStart, confirm: true }) })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error === 'local_email_step_up_required' ? 'Open Sign-in methods, choose Confirm my email, and complete the link in this browser. Then connect again within ten minutes.' : 'Auth could not start connecting that provider.')
      window.location.assign(body.redirect)
    } catch (error) {
      show(error.message, 'error')
      button.disabled = false
    }
  })
})()
