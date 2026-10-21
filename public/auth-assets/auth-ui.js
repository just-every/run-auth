(() => {
  const root = document.documentElement
  const statuses = () => Array.from(document.querySelectorAll('[data-auth-status]'))
  const showStatus = (message, kind = 'info') => {
    for (const status of statuses()) {
      status.textContent = message
      status.dataset.kind = kind
      status.hidden = false
      status.setAttribute('role', kind === 'error' ? 'alert' : 'status')
    }
  }
  const friendlyErrors = {
    account_unavailable: 'This account cannot sign in right now.',
    required_provider: 'Sign in with the provider required by your email domain first.',
    unknown_provider: 'Choose a provider configured for this Auth install.',
    upstream_proof_expired: 'Sign in with your provider again, then continue.',
    email_proof_required: 'Confirm your email in this browser first.',
    local_email_step_up_required: 'Open Sign-in methods, choose Confirm my email, and complete the email link in this browser. Then retry within ten minutes.',
    enrollment_session_changed: 'This passkey request belongs to another sign-in. Start the registration again.',
    passkey_session_expired: 'Your passkey session has ended. Sign in with your passkey, then request a new email confirmation.',
    session_authority_changed: 'Your sign-in changed during this request. Sign in again, then request a new email confirmation.',
    invalid_domain: 'Enter a valid domain name.',
    invalid_email: 'Enter a valid email address.',
    no_passkeys: 'Register a passkey before requesting recovery.',
    passkey_admin_required: 'Sign in with a passkey to use administrator actions.',
    passkey_required: 'Sign in with a passkey before adding another passkey.',
    recovery_already_pending: 'A recovery request is already pending for this account.',
    recovery_unavailable: 'That recovery request is no longer available.',
    sign_in_required: 'Your session has ended. Sign in and try again.',
    file_too_large: 'This file is larger than 1 MB. Export fewer columns or split it, then stage each part.',
    batch_unavailable: 'That staged export is no longer open.',
    proposal_stale: 'The target changed after the agent filed this, so it was rejected as stale.',
    proposal_expired: 'This proposal expired before it was approved.',
    proposal_decided: 'This proposal has already been decided.',
    second_administrator_required: 'Another administrator must approve a change to your own account.',
    invalid_passkey: 'That passkey could not approve this proposal.',
    invalid_label: 'Enter a label of up to 80 characters.',
  }
  const requestJSON = async (path, payload) => {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    })
    let body = null
    try { body = await response.json() } catch {}
    if (!response.ok) {
      const code = typeof body?.error === 'string' ? body.error : ''
      throw Object.assign(new Error(friendlyErrors[code] || (typeof body?.message === 'string' ? body.message : 'Auth could not complete that request. Try again.')), { code })
    }
    return body || {}
  }
  const localPath = value => typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !/[\\\r\n]/.test(value) ? value : '/app/account'
  const decodeBase64Url = value => {
    const normalized = String(value).replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4)
    return Uint8Array.from(atob(padded), char => char.charCodeAt(0))
  }
  const encodeBase64Url = value => {
    const bytes = new Uint8Array(value)
    let binary = ''
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  }
  const credentialJSON = credential => {
    const response = credential.response
    const serialized = {
      id: credential.id,
      rawId: encodeBase64Url(credential.rawId),
      type: credential.type,
      response: { clientDataJSON: encodeBase64Url(response.clientDataJSON) },
      clientExtensionResults: credential.getClientExtensionResults?.() || {},
    }
    if (credential.authenticatorAttachment) serialized.authenticatorAttachment = credential.authenticatorAttachment
    if ('attestationObject' in response) {
      serialized.response.attestationObject = encodeBase64Url(response.attestationObject)
      if (typeof response.getTransports === 'function') serialized.response.transports = response.getTransports()
    }
    if ('authenticatorData' in response) serialized.response.authenticatorData = encodeBase64Url(response.authenticatorData)
    if ('signature' in response) serialized.response.signature = encodeBase64Url(response.signature)
    if ('userHandle' in response) serialized.response.userHandle = response.userHandle ? encodeBase64Url(response.userHandle) : null
    return serialized
  }
  const creationOptions = options => ({
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map(item => ({ ...item, id: decodeBase64Url(item.id) })),
  })
  const requestOptions = options => ({
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(item => ({ ...item, id: decodeBase64Url(item.id) })),
  })
  const passkeyError = error => {
    if (error?.name === 'NotAllowedError') return 'The passkey request was canceled or no credential was selected.'
    if (error?.name === 'NotSupportedError') return 'This browser does not support passkey sign-in.'
    return error instanceof Error ? error.message : 'Auth could not complete the passkey request.'
  }
  const enrollPasskey = async button => {
    if (!navigator.credentials?.create || !window.PublicKeyCredential) {
      showStatus('This browser does not support passkey registration.', 'error')
      return
    }
    button.disabled = true
    showStatus('Waiting for your passkey…')
    try {
      const started = await requestJSON('/auth/identity/passkeys/register/options', {})
      const credential = await navigator.credentials.create({ publicKey: creationOptions(started.options) })
      if (!credential) throw new Error('No passkey was created.')
      await requestJSON('/auth/identity/passkeys/register/verify', {
        response: credentialJSON(credential),
        transaction: started.transaction,
      })
      showStatus('Passkey registered. Refreshing account details…', 'success')
      window.setTimeout(() => window.location.reload(), 350)
    } catch (error) {
      showStatus(passkeyError(error), 'error')
      button.disabled = false
    }
  }
  const authenticatePasskey = async button => {
    if (!navigator.credentials?.get || !window.PublicKeyCredential) {
      showStatus('This browser does not support passkey sign-in.', 'error')
      return
    }
    button.disabled = true
    showStatus('Waiting for your passkey…')
    try {
      const returnTo = localPath(button.dataset.returnTo)
      const started = await requestJSON('/auth/identity/passkeys/authenticate/options', { returnTo })
      const credential = await navigator.credentials.get({ publicKey: requestOptions(started.options) })
      if (!credential) throw new Error('No passkey was selected.')
      const result = await requestJSON('/auth/identity/passkeys/authenticate/verify', {
        response: credentialJSON(credential),
        transaction: started.transaction,
      })
      if (result.reproof) {
        showStatus('A recent email confirmation is required. Check your email and open its link in this browser.', 'success')
        button.disabled = false
        return
      }
      window.location.assign(localPath(result.returnTo || returnTo))
    } catch (error) {
      showStatus(passkeyError(error), 'error')
      button.disabled = false
    }
  }

  // One exact approval: a passkey signature over a challenge naming this proposal.
  const approveProposal = async button => {
    if (!navigator.credentials?.get || !window.PublicKeyCredential) {
      showStatus('This browser does not support passkeys.', 'error')
      return
    }
    button.disabled = true
    showStatus('Waiting for your passkey…')
    try {
      const started = await requestJSON('/api/auth/agents/approve/options', { proposalId: button.dataset.proposalApprove })
      const credential = await navigator.credentials.get({ publicKey: requestOptions(started.options) })
      if (!credential) throw new Error('No passkey was selected.')
      await requestJSON('/api/auth/agents/approve', { transaction: started.transaction, response: credentialJSON(credential) })
      showStatus('Approved and done. Refreshing…', 'success')
      window.setTimeout(() => window.location.reload(), 350)
    } catch (error) {
      showStatus(passkeyError(error), 'error')
      if (['proposal_stale', 'proposal_expired', 'proposal_decided'].includes(error?.code)) window.setTimeout(() => window.location.reload(), 1500)
      else button.disabled = false
    }
  }

  const storedTheme = (() => {
    try { return localStorage.getItem('auth-theme') } catch { return null }
  })()
  if (storedTheme === 'light' || storedTheme === 'dark') root.dataset.theme = storedTheme
  const resolvedTheme = () => root.dataset.theme || (window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  const updateThemeButton = () => {
    const dark = resolvedTheme() === 'dark'
    for (const button of document.querySelectorAll('[data-theme-toggle]')) {
      button.setAttribute('aria-pressed', String(dark))
      button.title = dark ? 'Dark theme' : 'Light theme'
    }
  }
  updateThemeButton()
  // On a phone the nav is one scrolling row: bring the current page's link into view.
  document.querySelector('.sidebar nav a.active')?.scrollIntoView({ block: 'nearest', inline: 'center' })
  document.addEventListener('click', event => {
    const themeButton = event.target.closest('[data-theme-toggle]')
    if (themeButton) {
      const next = resolvedTheme() === 'dark' ? 'light' : 'dark'
      root.dataset.theme = next
      try { localStorage.setItem('auth-theme', next) } catch {}
      updateThemeButton()
      return
    }
    const openButton = event.target.closest('[data-open-dialog]')
    if (openButton) {
      const dialog = document.getElementById(openButton.dataset.openDialog)
      if (dialog?.showModal) dialog.showModal()
      dialog?.querySelector('input:not([type=hidden])')?.focus()
      return
    }
    const closeButton = event.target.closest('[data-close-dialog]')
    if (closeButton) {
      closeButton.closest('dialog')?.close()
      return
    }
    const enrollButton = event.target.closest('[data-passkey-enroll]')
    if (enrollButton) void enrollPasskey(enrollButton)
    const loginButton = event.target.closest('[data-passkey-authenticate]')
    if (loginButton) void authenticatePasskey(loginButton)
    const approveButton = event.target.closest('[data-proposal-approve]')
    if (approveButton) void approveProposal(approveButton)
  })

  document.addEventListener('submit', async event => {
    const upload = event.target.closest('form[data-move-in-upload]')
    if (upload) {
      event.preventDefault()
      const file = upload.querySelector('input[type=file]')?.files?.[0]
      if (!file) return
      const submitter = event.submitter
      if (submitter) submitter.disabled = true
      showStatus('Reading and staging the file…')
      try {
        if (file.size > 1048576) throw new Error(friendlyErrors.file_too_large)
        const result = await requestJSON(upload.action, { fileName: file.name, exportDate: new FormData(upload).get('exportDate'), text: await file.text() })
        window.location.assign(`/app/move-in?batch=${encodeURIComponent(result.batchId)}`)
      } catch (error) {
        showStatus(error instanceof Error ? error.message : 'Auth could not stage that file.', 'error')
        if (submitter) submitter.disabled = false
      }
      return
    }
    const mint = event.target.closest('form[data-agent-mint]')
    if (mint) {
      event.preventDefault()
      const submitter = event.submitter
      if (submitter) submitter.disabled = true
      try {
        const result = await requestJSON(mint.action, { label: new FormData(mint).get('label') })
        // Shown here once; reloading the page clears it.
        const panel = document.querySelector('[data-agent-secret]'), field = document.querySelector('[data-agent-secret-value]')
        field.value = result.key
        panel.hidden = false
        field.focus()
        field.select()
        mint.reset()
        showStatus(`Key “${result.label}” minted. Copy it now: it is not shown again. Reload to see it in the list.`, 'success')
      } catch (error) {
        showStatus(error instanceof Error ? error.message : 'Auth could not mint a key.', 'error')
      }
      if (submitter) submitter.disabled = false
      return
    }
    const linkToken = event.target.closest('form[data-link-token]')
    if (linkToken) {
      event.preventDefault()
      const submitter = event.submitter
      if (submitter) submitter.disabled = true
      try {
        const result = await requestJSON(linkToken.action, { origin: new FormData(linkToken).get('origin') })
        // The envelope rer setup reads; shown here once.
        const panel = document.querySelector('[data-link-token-output]'), field = document.querySelector('[data-link-token-value]')
        field.value = JSON.stringify(result, null, 2)
        panel.hidden = false
        field.focus()
        field.select()
        showStatus(`Link token for ${result.origin} created. Copy it now: it is not shown again.`, 'success')
      } catch (error) {
        showStatus(error instanceof Error ? error.message : 'Auth could not create a link token.', 'error')
      }
      if (submitter) submitter.disabled = false
      return
    }
    const mapping = event.target.closest('form[data-mapping-form]')
    if (mapping) {
      event.preventDefault()
      const payload = Object.fromEntries(new FormData(mapping))
      payload.personIds = new FormData(mapping).getAll('personIds')
      const result = mapping.querySelector('[data-mapping-result]'), save = mapping.querySelector('[data-mapping-save]')
      save.disabled = true
      try {
        const preview = await requestJSON(mapping.action, payload)
        result.textContent = preview.message
        save.disabled = false
        save.onclick = async () => {
          save.disabled = true
          try { await requestJSON('/api/auth/mapping/save', { ...payload, version: preview.version, digest: preview.digest }); window.location.reload() }
          catch (error) { result.textContent = error.message }
        }
      } catch (error) { result.textContent = error.message }
      return
    }
    const form = event.target.closest('form[data-auth-action]')
    if (!form) return
    event.preventDefault()
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) return
    const submitter = event.submitter
    if (submitter) submitter.disabled = true
    // A repeated field, such as the selected move-in rows, is sent as a list.
    const payload = {}
    for (const [key, value] of new FormData(form).entries()) payload[key] = key in payload ? [payload[key], value].flat() : value
    showStatus('Sending request…')
    try {
      const result = await requestJSON(form.action, payload)
      const isEmailRequest = form.hasAttribute('data-email-request')
      if (isEmailRequest) {
        showStatus(result.message || 'If this address can sign in, a link has been sent.', 'success')
        form.reset()
        if (submitter) submitter.disabled = false
        return
      }
      if (form.dataset.redirect) {
        window.location.assign(localPath(form.dataset.redirect))
        return
      }
      if (form.dataset.reload === 'true') {
        showStatus('Request completed. Refreshing current data…', 'success')
        window.setTimeout(() => window.location.reload(), 350)
        return
      }
      showStatus(typeof result.message === 'string' ? result.message : 'Request completed.', 'success')
    } catch (error) {
      if (error?.code === 'local_email_step_up_required') form.closest('dialog')?.close()
      showStatus(error instanceof Error ? error.message : 'Auth could not complete that request.', 'error')
      if (submitter) submitter.disabled = false
    }
  })

  document.querySelectorAll('[data-mapping-form]').forEach(form => form.addEventListener('input', () => { form.querySelector('[data-mapping-save]').disabled = true }))

  const search = document.querySelector('[data-people-search]')
  if (search) {
    const rows = Array.from(document.querySelectorAll('[data-person-row]'))
    const empty = document.querySelector('[data-search-empty]')
    const count = document.querySelector('[data-people-count]')
    const update = () => {
      const query = search.value.trim().toLocaleLowerCase()
      let visible = 0
      for (const row of rows) {
        const match = !query || row.dataset.search.includes(query)
        row.hidden = !match
        if (match) visible += 1
      }
      if (empty) empty.hidden = visible > 0
      if (count) count.textContent = query ? `${visible} ${visible === 1 ? 'match' : 'matches'}` : `${visible} ${visible === 1 ? 'person' : 'people'}`
    }
    search.addEventListener('input', update)
  }
})()
