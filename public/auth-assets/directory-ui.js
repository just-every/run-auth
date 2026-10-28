// People: the edit dialog, the previewed bulk edit and the group rule editor.
(() => {
  const organizationPrefix = window.location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
  const organizationPath = path => {
    const url = new URL(path, window.location.origin)
    if (url.origin !== window.location.origin || !organizationPrefix || url.pathname.startsWith('/org/')) return path
    return organizationPrefix + url.pathname + url.search + url.hash
  }
  const status = (message, kind = 'info') => {
    for (const el of document.querySelectorAll('[data-auth-status]')) {
      el.textContent = message
      el.dataset.kind = kind
      el.hidden = false
      el.setAttribute('role', kind === 'error' ? 'alert' : 'status')
    }
  }
  const post = async (path, payload) => {
    const response = await fetch(organizationPath(path), { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
    let body = null
    try { body = await response.json() } catch {}
    if (!response.ok) {
      const refusals = Array.isArray(body?.refusals) ? body.refusals.join('; ') : ''
      const message = body?.error === 'local_email_step_up_required'
        ? 'Open Sign-in methods, choose Confirm my email, and complete the email link in this browser. Then retry within ten minutes.'
        : body?.error === 'preview_changed' ? 'The directory changed since this preview. Preview again.' : refusals || body?.error || 'Auth could not complete that request.'
      throw new Error(message)
    }
    return body
  }
  const text = (tag, value, className) => { const el = document.createElement(tag); el.textContent = value; if (className) el.className = className; return el }
  const names = list => list.map(item => item.name ?? item.app ?? item.email).join(', ')

  // Edit dialog: filled from the row, sends only what the administrator changed.
  const editDialog = document.getElementById('edit-dialog')
  const initial = { current: null }; let leaverApproval = null
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-edit-person]')
    if (!button || !editDialog) return
    const person = JSON.parse(button.dataset.person)
    const form = editDialog.querySelector('form')
    initial.current = { name: person.name, email: person.email, state: person.state === 'invited' ? '' : person.state }
    form.reset()
    leaverApproval = null
    editDialog.querySelector('[data-leaver-preview]').hidden = true
    editDialog.querySelector('[data-confirm-leaver]').hidden = true
    form.elements.personId.value = person.id
    form.elements.name.value = person.name
    form.elements.email.value = person.email
    form.elements.state.value = initial.current.state
    for (const [key, field] of Object.entries(person.fields)) {
      const control = form.elements[key]
      if (control && control.name !== 'name') { control.value = field.value; initial.current[key] = field.value }
    }
    const notes = editDialog.querySelector('[data-edit-sources]')
    const overrides = Object.entries(person.fields).filter(([, f]) => f.also.length).map(([key, f]) => `${key}: ${f.source} ${f.value} over ${f.also.map(a => `${a.source} ${a.value}`).join(', ')}`)
    notes.textContent = overrides.length ? `Sources disagree — ${overrides.join('; ')}.` : "Values you change here override what a source sends; the source's value stays visible until you accept it."
    form.querySelector('[name=state]').disabled = person.role === 'owner' || person.state === 'invited'
    editDialog.showModal()
  })
  editDialog?.querySelector('form').addEventListener('submit', async event => {
    event.preventDefault()
    const form = event.target, data = new FormData(form), set = {}, body = { personId: data.get('personId'), set }
    for (const [key, value] of data.entries()) {
      if (['personId', 'csrf'].includes(key) || value === '' || value === (initial.current?.[key] ?? '')) continue
      if (key === 'email' || key === 'state') body[key] = value
      else set[key] = value
    }
    if (!Object.keys(set).length && !body.email && !body.state) { editDialog.close(); return }
    event.submitter && (event.submitter.disabled = true)
    try {
      if (body.state === 'terminated') {
        const { plan } = await post('/api/auth/directory/preview', { edits: [body] })
        render(editDialog.querySelector('[data-leaver-preview]'), plan)
        leaverApproval = plan.ok ? { edits: [body], digest: plan.digest } : null
        editDialog.querySelector('[data-confirm-leaver]').hidden = !leaverApproval
        event.submitter && (event.submitter.disabled = false)
        return
      }
      await post(form.action, body)
      status('Saved. Refreshing current data…', 'success')
      window.setTimeout(() => window.location.reload(), 350)
    } catch (error) {
      editDialog.close()
      status(error.message, 'error')
      event.submitter && (event.submitter.disabled = false)
    }
  })

  editDialog?.querySelector('form').addEventListener('input', () => {
    leaverApproval = null
    editDialog.querySelector('[data-confirm-leaver]').hidden = true
    editDialog.querySelector('[data-leaver-preview]').hidden = true
  })
  editDialog?.querySelector('[data-confirm-leaver]').addEventListener('click', async event => {
    if (!leaverApproval) return
    event.target.disabled = true
    try {
      await post('/api/auth/directory/apply', leaverApproval)
      status('Approved. Refreshing plan history…', 'success')
      window.location.reload()
    } catch (error) {
      leaverApproval = null; event.target.hidden = true; event.target.disabled = false
      status(error.message, 'error')
    }
  })

  // A plan, as the rows an administrator reads before applying it.
  const render = (target, plan) => {
    target.replaceChildren()
    const s = plan.summary
    target.append(text('p', `${s.people} ${s.people === 1 ? 'person' : 'people'}: ${s.changed} changed, ${s.refused} refused, ${s.groupsGained} group ${s.groupsGained === 1 ? 'membership' : 'memberships'} gained, ${s.groupsLost} lost${s.destructive ? `, ${s.destructive} lose access` : ''}.`, 'bulk-summary'))
    const list = document.createElement('ul')
    list.className = 'bulk-entries'
    for (const e of plan.entries) {
      const item = document.createElement('li')
      item.append(text('strong', e.email ?? e.personId))
      const lines = [
        ...e.changes.map(c => `${c.field}: ${c.from ?? 'none'} → ${c.to ?? 'none'}${c.source ? ` (${c.source})` : ''}`),
        ...(e.state ? [`state: ${e.state.from} → ${e.state.to}`] : []),
        ...(e.emailChange ? [`email: ${e.emailChange.from} → ${e.emailChange.to}`] : []),
        ...(e.groups?.added.length ? [`joins ${names(e.groups.added)}`] : []),
        ...(e.groups?.removed.length ? [`leaves ${names(e.groups.removed)}`] : []),
        ...(e.apps?.gained.length ? [`gains ${names(e.apps.gained)}`] : []),
        ...(e.apps?.lost.length ? [`loses ${names(e.apps.lost)}`] : []),
        ...(e.conflicts ?? []).filter(c => c.introduced).map(c => `source conflict on ${c.field}`),
        ...(e.lifecycle ? ['Plan custodian: approving administrator', ...e.lifecycle.credentialActions, ...e.lifecycle.steps.map(step => `${step.app}: ${step.operation}${step.kind === 'unsupported' ? ' (unverified)' : ''}${step.within ? `; deadline ${step.within / 1000} seconds after approval` : ''}`)] : []),
        ...e.refusals.map(r => `refused: ${r}`),
      ]
      item.append(text('span', lines.length ? lines.join('; ') : 'no change', 'data-meta'))
      list.append(item)
    }
    target.append(list)
    target.hidden = false
  }

  const bulk = document.querySelector('[data-directory-bulk]')
  if (bulk) {
    const result = document.querySelector('[data-bulk-result]'), apply = bulk.querySelector('[data-bulk-apply]')
    let planned = null
    const request = () => {
      const data = new FormData(bulk), fields = {}, set = {}
      for (const [from, field] of [['filterDepartment', 'department'], ['filterLocation', 'location'], ['filterKind', 'kind']]) if (data.get(from)) fields[field] = data.get(from)
      for (const key of ['department', 'location', 'title']) if (data.get(key)) set[key] = data.get(key)
      return { filter: { ...(data.get('filterState') ? { state: data.get('filterState') } : {}), fields }, set, ...(data.get('state') ? { state: data.get('state') } : {}) }
    }
    bulk.addEventListener('submit', async event => {
      event.preventDefault()
      apply.disabled = true
      try {
        const body = request(), { plan } = await post('/api/auth/directory/preview', body)
        planned = { body, digest: plan.digest, ok: plan.ok }
        render(result, plan)
        apply.disabled = !plan.ok || !plan.summary.changed
        status(plan.ok ? 'Preview ready. Nothing has changed yet.' : 'Some people are refused; fix the filter or the change.', plan.ok ? 'info' : 'error')
      } catch (error) { status(error.message, 'error') }
    })
    for (const control of bulk.querySelectorAll('input, select')) control.addEventListener('input', () => { planned = null; apply.disabled = true })
    apply.addEventListener('click', async () => {
      if (!planned?.ok) return
      apply.disabled = true
      try {
        await post('/api/auth/directory/apply', { ...planned.body, digest: planned.digest })
        status('Applied. Refreshing current data…', 'success')
        window.setTimeout(() => window.location.reload(), 350)
      } catch (error) { status(error.message, 'error'); apply.disabled = false }
    })
  }

  const ruleForm = document.querySelector('[data-group-rule]')
  if (ruleForm) {
    const result = ruleForm.querySelector('[data-rule-result]'), set = ruleForm.querySelector('[data-rule-set]'), clear = ruleForm.querySelector('[data-rule-clear]')
    const body = () => {
      const data = new FormData(ruleForm), op = data.get('op'), condition = { field: data.get('field'), op }
      if (op === 'in') condition.values = String(data.get('value')).split(',').map(v => v.trim()).filter(Boolean)
      else if (!['present', 'absent'].includes(op)) condition.value = data.get('value')
      return { groupId: data.get('groupId'), rule: { match: 'all', conditions: [condition] } }
    }
    const show = changes => {
      result.replaceChildren(text('p', `Joins: ${changes.added.map(p => p.email).join(', ') || 'no one'}. Leaves: ${changes.removed.map(p => p.email).join(', ') || 'no one'}.`))
      result.hidden = false
    }
    ruleForm.addEventListener('submit', async event => {
      event.preventDefault()
      set.disabled = true
      try { show(await post('/api/auth/groups/rule', { ...body(), preview: true })); set.disabled = false; status('Preview ready. Nothing has changed yet.') } catch (error) { status(error.message, 'error') }
    })
    for (const control of ruleForm.querySelectorAll('input, select')) control.addEventListener('input', () => { set.disabled = true })
    const send = async payload => {
      try { await post('/api/auth/groups/rule', payload); status('Rule saved. Refreshing current data…', 'success'); window.setTimeout(() => window.location.reload(), 350) } catch (error) { status(error.message, 'error') }
    }
    set.addEventListener('click', () => send(body()))
    clear.addEventListener('click', () => send({ groupId: new FormData(ruleForm).get('groupId'), rule: null }))
  }
})()
