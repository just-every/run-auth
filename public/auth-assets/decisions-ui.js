// Group owners, request deciders and access reviewers confirm one exact decision with a passkey.
(() => {
  if (document.documentElement.dataset.accessDecisionsReady) return
  document.documentElement.dataset.accessDecisionsReady = 'true'
  const prefix = location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
  const organizationPath = path => {
    const url = new URL(path, location.origin)
    return prefix && url.origin === location.origin && !url.pathname.startsWith('/org/') ? prefix + url.pathname + url.search : path
  }
  const errors = {
    local_email_step_up_required: 'Open Sign-in methods, choose Confirm my email, and complete the email link in this browser. Then retry within ten minutes.',
    passkey_required: 'Sign in with a passkey before making an access decision.',
    passkey_admin_required: 'Sign in with an administrator passkey for this action.',
    sign_in_required: 'Your session has ended. Sign in and try again.',
    invalid_passkey: 'That passkey could not confirm this decision.',
    decision_stale: 'This access or your authority changed. Reload and review the current state.',
    review_incomplete: 'Finish every decision and remediation before closing this review.',
    self_review_forbidden: 'Another reviewer must decide your own access.',
    employee_passkey_required: 'Sign in with your employee passkey before requesting or cancelling access.',
    invalid_request_duration: 'Choose a whole number of minutes within this app’s permitted duration.',
    request_state_changed: 'This request or its policy changed. Reload before deciding again.',
    request_decider_required: 'Only the current designated decider can decide this request.',
    self_approval_refused: 'Another person must decide your access request.',
    existing_access_requires_review: 'This person already has a standing assignment. Review that access before granting temporary access.',
  }
  const post = async (path, payload) => {
    const response = await fetch(organizationPath(path), { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })
    let body = null
    try { body = await response.json() } catch {}
    if (!response.ok) throw new Error(errors[body?.error] || body?.message || body?.error || 'Auth could not complete that request.')
    return body
  }
  const decode = value => {
    const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/')
    return Uint8Array.from(atob(normalized + '='.repeat((4 - normalized.length % 4) % 4)), character => character.charCodeAt(0))
  }
  const encode = value => {
    let binary = ''
    for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  }
  const credentialJSON = credential => ({
    id: credential.id,
    rawId: encode(credential.rawId),
    type: credential.type,
    ...(credential.authenticatorAttachment ? { authenticatorAttachment: credential.authenticatorAttachment } : {}),
    response: {
      clientDataJSON: encode(credential.response.clientDataJSON),
      authenticatorData: encode(credential.response.authenticatorData),
      signature: encode(credential.response.signature),
      userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
    },
    clientExtensionResults: credential.getClientExtensionResults?.() || {},
  })
  // The server binds every membership, request or review field to its transaction.
  const decide = async payload => {
    if (!navigator.credentials?.get || !window.PublicKeyCredential) throw new Error('This browser does not support passkeys.')
    const started = await post('/api/auth/decisions/options', payload)
    const options = { ...started.options, challenge: decode(started.options.challenge), allowCredentials: (started.options.allowCredentials || []).map(item => ({ ...item, id: decode(item.id) })) }
    const credential = await navigator.credentials.get({ publicKey: options })
    if (!credential) throw new Error('No passkey was selected.')
    return post('/api/auth/decisions/commit', { transaction: started.transaction, response: credentialJSON(credential) })
  }
  const dateISO = value => {
    const date = new Date(value)
    if (Number.isNaN(date.valueOf())) throw new Error('Enter valid review dates.')
    return date.toISOString()
  }
  const durationMs = value => {
    const minutes = Number(value)
    if (!Number.isSafeInteger(minutes) || minutes < 1 || !Number.isSafeInteger(minutes * 60000)) throw new Error('Choose a whole number of minutes greater than zero.')
    return minutes * 60000
  }
  for (const form of document.querySelectorAll('[data-access-form="request-create"]')) {
    const app = form.querySelector('[name="appId"]'), duration = form.querySelector('[name="durationMinutes"]')
    app.addEventListener('change', () => {
      const maximum = Number(app.selectedOptions[0].dataset.maxDurationMinutes)
      duration.max = String(maximum)
      if (Number(duration.value) > maximum) duration.value = String(maximum)
    })
  }
  document.addEventListener('submit', async event => {
    const form = event.target.closest('form[data-access-decision], form[data-access-form]')
    if (!form) return
    event.preventDefault()
    if (form.dataset.busy) return
    const fields = new FormData(form), output = form.querySelector('[data-access-result]')
    const buttons = [...form.querySelectorAll('button[type="submit"]')]
    const setStatus = (message, error = false) => {
      output.textContent = message
      output.setAttribute('role', error ? 'alert' : 'status')
    }
    form.dataset.busy = 'true'
    buttons.forEach(button => { button.disabled = true })
    try {
      if (form.dataset.accessDecision) {
        const payload = { kind: form.dataset.accessDecision, targetId: fields.get('targetId'), operation: event.submitter?.name === 'operation' ? event.submitter.value : fields.get('operation'), reason: String(fields.get('reason') || '').trim() }
        if (payload.kind === 'group') payload.personId = fields.get('personId')
        if (payload.kind === 'review' && payload.operation === 'reduce') payload.newRole = fields.get('newRole')
        setStatus('Waiting for your passkey…')
        await decide(payload)
      } else {
        let payload
        if (form.dataset.accessForm === 'role-order') payload = { appId: fields.get('appId'), roles: String(fields.get('roles') || '').split(/\r?\n/).map(role => role.trim()).filter(Boolean).map((role, level) => ({role,level})) }
        if (form.dataset.accessForm === 'privilege') payload = { kind: fields.get('kind'), targetId: fields.get('targetId'), role: fields.get('role'), privileged: fields.get('privileged') === 'true' }
        if (form.dataset.accessForm === 'review-create') payload = { name: fields.get('name'), reviewerId: fields.get('reviewerId'), dueAt: dateISO(fields.get('dueAt')), periodStart: dateISO(fields.get('periodStart')), periodEnd: dateISO(fields.get('periodEnd')), intervalMonths: 3, includeAdministrators: fields.get('includeAdministrators') === 'on' }
        if (form.dataset.accessForm === 'review-delegate') payload = { itemId: fields.get('itemId'), reviewerId: fields.get('reviewerId'), reason: String(fields.get('reason') || '').trim() }
        if (form.dataset.accessForm === 'review-close') payload = { id: fields.get('id') }
        if (form.dataset.accessForm === 'request-create') payload = { appId: fields.get('appId'), role: String(fields.get('role') || '').trim() || null, purpose: String(fields.get('purpose') || '').trim(), durationMs: durationMs(fields.get('durationMinutes')) }
        if (form.dataset.accessForm === 'request-cancel') payload = { id: fields.get('id') }
        if (form.dataset.accessForm === 'request-policy') payload = { appId: fields.get('appId'), deciderId: fields.get('deciderId'), maxDurationMs: durationMs(fields.get('maxDurationMinutes')) }
        setStatus('Saving…')
        if (form.dataset.accessForm === 'request-create') {
          setStatus('Waiting for your passkey…')
          await decide({kind:'request_submit',targetId:payload.appId,operation:'request',reason:payload.purpose,role:payload.role,durationMs:payload.durationMs})
        } else await post(form.action, payload)
      }
      setStatus('Saved. Refreshing…')
      window.setTimeout(() => location.reload(), 350)
    } catch (error) {
      setStatus(error?.name === 'NotAllowedError' ? 'The passkey request was canceled or no credential was selected.' : error.message, true)
      delete form.dataset.busy
      buttons.forEach(button => { button.disabled = false })
    }
  })
})()
