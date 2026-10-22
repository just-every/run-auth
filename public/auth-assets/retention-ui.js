(() => {
  const prefix = location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
  const organizationPath = path => {
    const url = new URL(path, location.origin)
    return prefix && url.origin === location.origin && !url.pathname.startsWith('/org/') ? prefix + url.pathname + url.search : path
  }
  const errors = {
    local_email_step_up_required: 'Open Sign-in methods, choose Confirm my email, and complete the email link in this browser. Then retry within ten minutes.',
    retention_explicit_confirmation_required: 'Confirm the retention periods before saving.',
    retention_period_out_of_bounds: 'Choose 90–2,555 days, 4–84 months, or 1–7 years for every class.',
    retention_policy_changed: 'The retention policy changed. Reload before trying again.',
    retention_hold_unavailable: 'This hold is no longer available. Reload to see its state.',
    retention_export_unavailable: 'This export is no longer available. Reload to see the current expiry runs.',
  }
  const request = async (path, payload) => {
    const response = await fetch(organizationPath(path), { method: payload === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', ...(payload === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) }) })
    let body = null
    try { body = await response.json() } catch {}
    if (!response.ok) throw new Error(errors[body?.error] || body?.message || body?.error || 'Auth could not complete this retention request.')
    return body
  }
  const timestamp = value => {
    const at = new Date(value).getTime()
    if (!Number.isSafeInteger(at)) throw new Error('Enter a valid hold period.')
    return at
  }
  for (const row of document.querySelectorAll('[data-retention-period]')) {
    const unit = row.querySelector('[data-retention-unit]'), value = row.querySelector('[data-retention-value]')
    unit.addEventListener('change', () => {
      const [min, max] = unit.value === 'days' ? [90, 2555] : unit.value === 'months' ? [4, 84] : [1, 7]
      value.min = String(min)
      value.max = String(max)
    })
  }
  for (const form of document.querySelectorAll('[data-retention-form]')) form.addEventListener('submit', async event => {
    event.preventDefault()
    const button = event.submitter, output = form.querySelector('[data-retention-result]'), fields = new FormData(form)
    if (button) button.disabled = true
    try {
      let payload = {}
      if (form.dataset.retentionForm === 'settings') {
        const classes = {}
        for (const [name, value] of fields) if (name.endsWith('.unit')) {
          const key = name.slice(0, -5)
          classes[key] = { unit: value, value: Number(fields.get(key + '.value')) }
        }
        payload = { classes, confirm: fields.has('confirm') }
      }
      if (form.dataset.retentionForm === 'hold') {
        payload = { kind: fields.get('kind'), periodStart: timestamp(fields.get('periodStart')), periodEnd: timestamp(fields.get('periodEnd')), reason: String(fields.get('reason') || '').trim(), classes: fields.getAll('classes') }
        if (!payload.classes.length) throw new Error('Choose at least one class for the hold.')
        if (payload.periodEnd < payload.periodStart) throw new Error('The hold period must end on or after its start.')
      }
      if (form.dataset.retentionForm === 'release') payload = { id: fields.get('id'), release: true }
      output.setAttribute('role', 'status')
      output.textContent = 'Saving…'
      const result = await request(form.action, payload)
      if (form.dataset.retentionForm === 'queue' && !result.run) {
        output.textContent = 'No records are eligible for expiry under the current policy and holds.'
        if (button) button.disabled = false
        return
      }
      output.textContent = 'Saved. Refreshing…'
      window.setTimeout(() => location.reload(), 350)
    } catch (error) {
      output.textContent = error.message
      output.setAttribute('role', 'alert')
      if (button) button.disabled = false
    }
  })
  document.querySelector('[data-retention-preview]')?.addEventListener('click', async event => {
    const button = event.currentTarget, output = document.querySelector('[data-retention-preview-result]')
    button.disabled = true
    output.hidden = false
    output.setAttribute('role', 'status')
    output.textContent = 'Loading eligible records…'
    try {
      const { preview } = await request('/api/auth/retention/preview')
      output.replaceChildren()
      const summary = document.createElement('p')
      summary.textContent = `${preview.total} eligible records in this preview (up to ${preview.limit}). No records have been queued by this preview.`
      output.append(summary)
      const list = document.createElement('ul')
      for (const [name, value] of Object.entries(preview.summary)) if (value.count) {
        const item = document.createElement('li')
        item.textContent = `${name.replace(/([a-z])([A-Z])/g, '$1 $2')}: ${value.count} records`
        list.append(item)
      }
      output.append(list)
    } catch (error) {
      output.textContent = error.message
      output.setAttribute('role', 'alert')
    } finally { button.disabled = false }
  })
})()
