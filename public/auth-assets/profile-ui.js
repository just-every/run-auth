// My account: start connecting a provider. The provider's own sign-in follows.
(() => {
  const organizationPrefix = window.location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
  const organizationPath = path => {
    const url = new URL(path, window.location.origin)
    if (url.origin !== window.location.origin || !organizationPrefix || url.pathname.startsWith('/org/')) return path
    return organizationPrefix + url.pathname + url.search + url.hash
  }
  document.addEventListener('click', async event => {
    const button = event.target.closest('[data-link-start]')
    if (!button) return
    if (button.dataset.confirm && !window.confirm(button.dataset.confirm)) return
    button.disabled = true
    const show = (message, kind) => { for (const el of document.querySelectorAll('[data-auth-status]')) { el.textContent = message; el.dataset.kind = kind; el.hidden = false; el.setAttribute('role', kind === 'error' ? 'alert' : 'status') } }
    try {
      const response = await fetch(organizationPath('/api/auth/profile/links/start'), { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ providerId: button.dataset.linkStart, confirm: true }) })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error === 'local_email_step_up_required' ? 'Open Sign-in methods, choose Confirm my email, and complete the link in this browser. Then connect again within ten minutes.' : 'Auth could not start connecting that provider.')
      window.location.assign(body.redirect)
    } catch (error) {
      show(error.message, 'error')
      button.disabled = false
    }
  })

  // The profile saves as it changes; each field says Saved beside its label.
  const form = document.querySelector('form[data-profile-autosave]')
  if (!form) return
  let timer, saving = false, dirty = false, fieldOfSave
  const note = field => field?.closest('.field')?.querySelector('[data-save-state]')
  const save = async () => {
    clearTimeout(timer)
    if (saving || !dirty || !form.checkValidity()) return
    saving = true
    const field = fieldOfSave
    try {
      while (dirty) {
        dirty = false
        const values = Object.fromEntries(new FormData(form))
        const response = await fetch(organizationPath(form.getAttribute('action')), { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(values) })
        if (!response.ok) throw new Error('Not saved')
        for (const label of document.querySelectorAll('[data-person-name]')) if (values.name?.trim()) label.textContent = values.name.trim()
      }
      if (note(field)) note(field).textContent = 'Saved'
    } catch {
      dirty = true
      if (note(field)) note(field).textContent = 'Not saved. Edit to try again.'
    } finally { saving = false }
  }
  form.addEventListener('input', event => {
    dirty = true; fieldOfSave = event.target
    for (const state of form.querySelectorAll('[data-save-state]')) state.textContent = ''
    clearTimeout(timer); timer = setTimeout(save, 700)
  })
  form.addEventListener('change', event => { dirty = true; fieldOfSave = event.target; void save() })
  form.addEventListener('submit', event => { event.preventDefault(); void save() })
})()
