(() => {
  const organizationPrefix = window.location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
  const organizationPath = path => {
    const url = new URL(path, window.location.origin)
    if (url.origin !== window.location.origin || !organizationPrefix || url.pathname.startsWith('/org/')) return path
    return organizationPrefix + url.pathname + url.search + url.hash
  }
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
    domain_not_verified: 'Prove ownership of this exact domain on Sign-in methods first.',
    domain_already_claimed: 'Another employer holds this domain. Contact your installation owner.',
    domain_challenge_incorrect: 'The TXT record does not match yet. Check its exact name and value, then try again.',
    domain_challenge_expired_or_used: 'This ownership challenge expired or was already used. Start a new challenge.',
    domain_dns_unavailable: 'DNS could not be read. Retry when your DNS service is available.',
    domain_claim_changed: 'Ownership changed during verification. Reload and review the current claim.',
    mandatory_notification_required: 'Recovery, factor reset or removal, and administrator role notices cannot be turned off.',
    notification_explicit_consent_required: 'Confirm the notification recipients and report response before saving.',
    notification_security_owner_required: 'Choose an active security owner.',
    notification_slack_not_configured: 'Configure a security Slack destination before enabling escalation.',

    diagnostic_consent_required: 'Approve sending this precise redacted snapshot before requesting a diagnosis.',
    diagnostic_model_not_configured: 'The owner must configure the diagnosis model before preparing a repair.',
    diagnostic_model_unavailable: 'The diagnosis model is unavailable. Configuration has not changed.',
    diagnostic_model_invalid: 'The model returned an unsupported diagnosis. Inspect the approved facts and prepare again.',
    assigned_test_identity_required: 'Choose an active employee assigned to this company app.',
    callback_query_not_supported: 'Choose a callback without a query string for this scoped repair.',
    replacement_certificate_unavailable: 'The published replacement certificate is no longer valid. Prepare a new diagnosis.',
    untrusted_diagnostic_fields: 'Raw traces, credentials and additional instructions are not accepted by diagnostics.',
    invalid_followup_timezone: 'Choose a valid timezone, such as America/New_York or Australia/Brisbane.',
    invalid_followup_calendar: 'Choose business days, a local reminder time and valid holiday dates.',
    invalid_followup_policy: 'Choose reminder and deadline intervals from 1 to 90 business days.',
    invalid_followup_schedule: 'Choose a deadline at least as far away as the next reminder.',
    followup_explicit_consent_required: 'Confirm the reminder policy and approved recipients before saving.',
    followup_approved_recipient_required: 'Choose an employee, holding help desk or active administrator to receive reminders.',
    followup_escalation_recipient_required: 'Choose an active administrator to receive repeated escalation.',
    followup_recipient_requires_admin: 'Reminder recipients must be active owners or administrators.',
    followup_owner_requires_admin: 'Choose an active owner or administrator for this follow-up.',
    followup_changed: 'This follow-up changed during your request. Reload and review its current state.',
    followup_holder_required: 'Only the person currently holding this follow-up can send its reminder early.',
    followup_policy_disabled: 'An authorized person must enable the reminder policy before a reminder can be sent.',
    followup_unavailable: 'This follow-up is no longer open. Reload to see its result.', 
    hook_timeout: 'An inline sign-in hook timed out. Try signing in again.',
    hook_refused: 'Your employer’s sign-in hook refused this request.',
    hook_invalid_response: 'The hook tried to change a protected or unapproved field.',
    invalid_hook_url: 'Use an HTTPS endpoint that resolves only to public addresses.',
    invalid_hook_scope: 'Choose an OpenID Connect app for token hooks or a SAML app for assertion hooks. Registration and import hooks use no app.',
    invalid_hook_fields: 'Choose custom claim or attribute names; identity, roles and MFA fields are protected.',
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
    person_already_exists: 'This person already exists. Review their People entry. If suspended, prepare a Restore person proposal on Agents before inviting again.',
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
    invalid_admin_service_name: 'Enter a service app name of up to 80 characters.',
    invalid_admin_service_purpose: 'Describe the service app’s purpose in up to 1,000 characters.',
    invalid_admin_service_owner: 'Choose an active administrator or owner for this service app.',
    invalid_admin_service_scopes: 'Select at least one supported Admin API scope.',
    invalid_admin_service_jwks: 'Paste a public JWKS containing one to five RS256 or ES256 signing keys. Do not include private key material.',
    invalid_admin_service_resources: 'Enter resource limits as a JSON object with people, groups or apps arrays of IDs. Use ["*"] for all, or [] for none.',
    invalid_admin_service_ips: 'Enter exact IPv4/IPv6 addresses or CIDR ranges, one per line.',
    invalid_admin_service_expiry: 'Choose an expiry in the future, within 365 days.',
    admin_service_conflict: 'This service app or your authority changed. Refresh the page before trying again.',
    admin_service_not_found: 'This service app is no longer available. Refresh the page.',
  }
  const requestJSON = async (path, payload) => {
    const response = await fetch(organizationPath(path), {
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
      window.location.assign(organizationPath(localPath(result.returnTo || returnTo)))
    } catch (error) {
      showStatus(error?.code === 'invalid_passkey' ? 'That passkey cannot sign in. Try another registered passkey, or request an email link.' : passkeyError(error), 'error')
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

  const confirmDelegatedTask = async (button, action) => {
    if (!navigator.credentials?.get || !window.PublicKeyCredential) return showStatus('This browser does not support passkeys.', 'error')
    button.disabled = true
    try {
      const task = { grantId: button.dataset.delegationApprove || button.dataset.delegationConsent, effectDigest: button.dataset.effectDigest }
      const started = await requestJSON(action === 'consent' ? '/api/auth/delegations/consent/options' : '/api/auth/delegations/approval/options', task)
      const credential = await navigator.credentials.get({ publicKey: requestOptions(started.options) })
      if (!credential) throw new Error('No passkey was selected.')
      await requestJSON('/api/auth/delegations/' + action, { ...task, ...(action === 'consent' ? {decision:'consent'} : {}), transaction: started.transaction, response: credentialJSON(credential) })
      window.location.reload()
    } catch (error) { showStatus(passkeyError(error), 'error'); button.disabled = false }
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
    const delegationButton = event.target.closest('[data-delegation-approve]')
    if (delegationButton) void confirmDelegatedTask(delegationButton, 'approve')
    const consentButton = event.target.closest('[data-delegation-consent]')
    if (consentButton) void confirmDelegatedTask(consentButton, 'consent')
    const approveButton = event.target.closest('[data-proposal-approve]')
    if (approveButton) void approveProposal(approveButton)
  })

  document.addEventListener('change', event => {
    if (!event.target.matches('[data-diagnostic-issue]')) return
    const form = event.target.closest('[data-diagnostic-form]')
    for (const field of form.querySelectorAll('[data-diagnostic-field]')) {
      const active = field.dataset.diagnosticField === event.target.value
      field.hidden = !active
      field.querySelector('input').required = active
    }
  })

  document.addEventListener('submit', async event => {
    const setup = event.target.closest('form[data-source-create],form[data-federation-create]')
    if (setup) {
      event.preventDefault()
      const button = setup.querySelector('button[type=submit],button:not([type])')
      const fields = new FormData(setup), source = setup.hasAttribute('data-source-create')
      const output = setup.querySelector(source ? '[data-source-result]' : '[data-federation-result]')
      if (button) button.disabled = true
      try {
        let payload
        if (source) {
          payload = Object.fromEntries(fields)
          payload.fields = fields.getAll('fields')
          payload.confirm = fields.has('confirm')
          if (!payload.baseUrl) delete payload.baseUrl
          if (!payload.credential) delete payload.credential
        } else payload = {domain: fields.get('domain'), provider: JSON.parse(fields.get('provider')), confirm: fields.has('confirm')}
        const result = await requestJSON(setup.action, payload)
        if (source && result.ingressToken) {
          output.replaceChildren()
          const explanation = document.createElement('p')
          explanation.textContent = 'Copy this scoped SCIM credential now. It is shown once. Endpoint: ' + result.scimBase
          const label = document.createElement('label')
          label.textContent = 'One-time SCIM credential'
          const credential = document.createElement('textarea')
          credential.readOnly = true
          credential.value = result.ingressToken
          label.append(credential)
          const link = document.createElement('a')
          link.href = organizationPath('/app/move-in')
          link.textContent = 'Open source dashboard'
          output.append(explanation, label, link)
          setup.reset()
        } else window.location.assign(organizationPath('/app/move-in' + (source && result.snapshotId ? '?sourceSnapshot=' + encodeURIComponent(result.snapshotId) : !source ? '?federation=' + encodeURIComponent(result.id) : '')))
      } catch (error) { output.textContent = error.message; if (button) button.disabled = false }
      return
    }

    const registration = event.target.closest('form[data-delegated-agent-register]')
    if (registration) {
      event.preventDefault()
      const button = registration.querySelector('button[type=submit],button:not([type])')
      if (button) button.disabled = true
      const output = registration.querySelector('[data-task-agent-result]')
      try {
        const fields = new FormData(registration)
        const payload = Object.fromEntries(fields)
        payload.appIds = fields.getAll('appIds')
        payload.personIds = fields.getAll('personIds')
        payload.jwks = JSON.parse(payload.jwks)
        payload.expiresAt = new Date(payload.expiresAt).valueOf()
        await requestJSON('/api/auth/delegations/agents/register', payload)
        window.location.reload()
      } catch (error) { output.textContent = error.message; if (button) button.disabled = false }
      return
    }

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
        window.location.assign(organizationPath(`/app/move-in?batch=${encodeURIComponent(result.batchId)}`))
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
    if (form.hasAttribute('data-notification-settings')) {
      const values = new FormData(form)
      for (const key of ['emailEnabled', 'newDevice', 'factorEnrolled', 'slackEnabled', 'endSessionsOnReport', 'confirm']) payload[key] = values.has(key)
    }
    if (form.hasAttribute('data-notification-resolve')) payload.confirm = payload.confirm === 'true'
    if (form.hasAttribute('data-source-approve')) {
      const values = new FormData(form)
      payload.confirm = values.has('confirm')
      payload.confirmHeld = values.has('confirmHeld')
    }
    if (form.hasAttribute('data-source-disable')) payload.confirm = payload.confirm === 'true'
    if (form.hasAttribute('data-federation-confirm')) {
      payload.confirm = payload.confirm === 'true' || payload.confirm === 'on'
      payload.revision = Number(payload.revision)
    }
    if (form.hasAttribute('data-campaign-create')) {
      const values = new FormData(form)
      for (const key of ['confirm', 'employeeConsent', 'managerConsent', 'administratorConsent']) payload[key] = values.has(key)
      for (const key of ['startsAt', 'deadlineAt', 'cutoverAt']) payload[key] = new Date(payload[key]).getTime()
      payload.rows = values.getAll('rows').map(Number)
    }
    if (form.hasAttribute('data-campaign-exempt')) payload.confirm = new FormData(form).has('confirm')
    if (form.hasAttribute('data-hook-register')) {
      const target = payload.target || '', colon = target.indexOf(':')
      if (colon > 0) payload[target.slice(0, colon) === 'app' ? 'appId' : 'clientId'] = target.slice(colon + 1)
      delete payload.target
      payload.allowedFields = String(payload.allowedFields || '').split(/[\s,]+/).filter(Boolean)
      payload.timeoutMs = Number(payload.timeoutMs)
      payload.failClosed = payload.failClosed !== 'false'
    }
    showStatus('Sending request…')
    try {
      if (form.hasAttribute('data-admin-service-create')) {
        payload.scopes = new FormData(form).getAll('scopes')
        if (!payload.scopes.length) throw new Error(friendlyErrors.invalid_admin_service_scopes)
        try { payload.jwks = JSON.parse(payload.jwks) }
        catch { throw new Error('Public signing keys must be valid JWKS JSON.') }
        if (!Array.isArray(payload.jwks?.keys) || !payload.jwks.keys.length || payload.jwks.keys.some(key => !key || typeof key !== 'object' || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(part => Object.hasOwn(key, part)))) throw new Error(friendlyErrors.invalid_admin_service_jwks)
        if (String(payload.resources || '').trim()) {
          try { payload.resources = JSON.parse(payload.resources) }
          catch { throw new Error('Resource limits must be valid JSON, or leave the field blank for unrestricted resources.') }
        } else delete payload.resources
        payload.allowedIps = String(payload.allowedIps || '').split(/[\s,]+/).filter(Boolean)
        const expiry = new Date(payload.expiresAt).getTime(), now = Date.now()
        if (!Number.isFinite(expiry) || expiry <= now || expiry > now + 365 * 86400000) throw new Error(friendlyErrors.invalid_admin_service_expiry)
        payload.expiresAt = new Date(expiry).toISOString()
      }
      if (form.hasAttribute('data-followup-settings')) {
        const values = new FormData(form)
        payload.enabled = values.has('enabled')
        payload.confirm = values.has('confirm')
        payload.calendar = {timezone: payload.timezone, at: payload.at, weekdays: values.getAll('weekdays').map(Number), holidays: String(payload.holidays || '').split(/[\s,]+/).filter(Boolean)}
        payload.recipients = values.getAll('recipients')
        payload.escalationRecipients = values.getAll('escalationRecipients')
        payload.reminderBusinessDays = Number(payload.reminderBusinessDays)
        payload.deadlineBusinessDays = Number(payload.deadlineBusinessDays)
      }
      if (form.hasAttribute('data-followup-schedule')) {
        payload.dueBusinessDays = Number(payload.dueBusinessDays)
        payload.deadlineBusinessDays = Number(payload.deadlineBusinessDays)
      }
      const result = await requestJSON(form.action, payload)
      if (form.hasAttribute('data-diagnostic-form')) { window.location.assign(organizationPath(localPath(result.redirect))); return }
      if (form.hasAttribute('data-refresh-consent')) { window.location.assign(result.redirect); return }
      if (form.hasAttribute('data-organization-switch')) { window.location.assign(result.redirect); return }
      if (form.hasAttribute('data-organization-create')) {
        const output = form.querySelector('[data-organization-result]')
        output.replaceChildren(Object.assign(document.createElement('a'), { href: result.signInPath, textContent: `Sign in to ${result.name} and enroll its passkey` }))
        showStatus('Organization created. Confirm your email in its sign-in page to establish your membership.', 'success')
        return
      }
      const isEmailRequest = form.hasAttribute('data-email-request')
      if (isEmailRequest) {
        showStatus(result.message || 'If this address can sign in, a link has been sent.', 'success')
        form.reset()
        if (submitter) submitter.disabled = false
        return
      }
      if (form.dataset.redirect) {
        window.location.assign(organizationPath(localPath(form.dataset.redirect)))
        return
      }
      if (form.dataset.reload === 'true') {
        showStatus('Request completed. Refreshing current data…', 'success')
        window.setTimeout(() => window.location.reload(), 350)
        return
      }
      showStatus(typeof result.message === 'string' ? result.message : 'Request completed.', 'success')
    } catch (error) {
      if (['local_email_step_up_required', 'person_already_exists'].includes(error?.code)) form.closest('dialog')?.close()
      showStatus(error instanceof Error ? error.message : 'Auth could not complete that request.', 'error')
      if (submitter) submitter.disabled = false
    }
  })

  document.querySelectorAll('[data-mapping-form]').forEach(form => form.addEventListener('input', () => { form.querySelector('[data-mapping-save]').disabled = true }))

  const countdowns = Array.from(document.querySelectorAll('[data-campaign-cutover]'))
  if (countdowns.length) {
    const update = () => { for (const item of countdowns) {
      const minutes = Math.max(0, Math.ceil((Number(item.dataset.campaignCutover) - Date.now()) / 60000))
      item.textContent = minutes ? `${Math.floor(minutes / 1440)} days, ${Math.floor(minutes % 1440 / 60)} hours, ${minutes % 60} minutes until cutover` : 'Campaign window closed'
    } }
    update()
    window.setInterval(update, 60000)
  }

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
