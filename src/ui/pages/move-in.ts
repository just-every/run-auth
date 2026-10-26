import { directorySourcePanels } from './move-in-sources.js'
import { federationPanels } from './move-in-federation.js'
import type { AuthPageModel, MoveInBatch, MoveInRow } from '../model.js'
import { asArray, csrfField, emptyState, escape, timeElement } from '../helpers.js'
import { campaignPanels } from './move-in-campaigns.js'

const sources: Record<string, string> = { custom: 'Custom directory', google: 'Google Workspace', microsoft: 'Microsoft Entra', auth0: 'Auth0', okta: 'Okta', jumpcloud: 'JumpCloud' }
const sourceName = (value?: string): string => sources[value ?? ''] ?? 'Unknown source'

const findings: Record<string, string> = {
  new: 'New person',
  owner_address: 'Owner’s own address: nothing changes',
  existing_person: 'Already a person: nothing changes',
  refused_domain: 'Email domain Auth refuses',
  invalid_email: 'No valid email address',
  duplicate_in_file: 'Same address appears more than once in this file',
  disabled_at_source: 'Disabled at source',
  formula_text: 'Name starts with a spreadsheet formula character',
}
const summaryOrder = ['new', 'existing_person', 'duplicate_in_file', 'disabled_at_source', 'refused_domain', 'owner_address', 'invalid_email']
const keptReasons: Record<string, string> = { signed_in: 'signed in', passkey: 'holds a passkey', app_grant: 'has an app grant', status_changed: 'status or role changed', later_activity: 'later activity', removed_elsewhere: 'already removed', changed_during_undo: 'changed during undo' }

const rowStatus = (row: MoveInRow): string => row.status === 'admitted'
  ? `<span class="status-pill invited" data-row-status="${row.invitedAt ? 'invited' : 'admitted'}">${row.invitedAt ? 'Invitation sent' : 'Admitted, not yet sent'}</span>`
  : row.status === 'undone' ? '<span class="status-pill suspended" data-row-status="undone">Removed by undo</span>' : ''

const findingText = (row: MoveInRow): string => {
  const list = row.reasons.length ? row.reasons : ['new']
  return list.map(reason => `<span class="finding finding-${escape(reason)}">${escape(findings[reason] ?? reason)}</span>`).join('')
}

const reviewRows = (rows: MoveInRow[], open: boolean): string => rows.map(row => {
  const email = row.email ?? ''
  const label = row.displayName || email || `Row ${row.idx + 1}`
  const choosable = open && row.status === 'staged' && row.admittable
  const select = row.status === 'staged'
    ? `<input type="checkbox" name="rows" value="${row.idx}" id="move-in-row-${row.idx}"${row.selected ? ' checked' : ''}${choosable ? '' : ' disabled'}><label class="visually-hidden" for="move-in-row-${row.idx}">Admit ${escape(label)}</label>`
    : ''
  return `<tr class="move-in-row" data-move-in-row data-reasons="${escape(row.reasons.join(' '))}"><td class="move-in-select">${select}</td><td><strong class="person-name">${escape(label)}</strong><span class="move-in-meta"><span class="mobile-label">Source id</span>${escape(row.sourceId ?? 'None in this export')}</span></td><td><span class="mobile-label">Email</span><span class="email-text">${escape(email || 'Missing')}</span></td><td><span class="mobile-label">Context, not permissions</span>${row.groups.length ? escape(row.groups.join(', ')) : '<span class="muted">None</span>'}</td><td><span class="mobile-label">Finding</span><span class="finding-list">${row.status === 'staged' ? findingText(row) : rowStatus(row)}</span></td></tr>`
}).join('')

const batchRows = (batches: MoveInBatch[], current?: string): string => batches.length
  ? batches.map(batch => `<tr${batch.id === current ? ' aria-current="true"' : ''}><td><a href="/app/move-in?batch=${encodeURIComponent(batch.id)}">${escape(batch.file_name)}</a></td><td>${escape(sourceName(batch.source_system))}</td><td>${escape(batch.export_date)}</td><td>${batch.row_count}</td><td>${batch.admitted}</td><td>${batch.undone_at ? 'Undone' : 'Open'}</td></tr>`).join('')
  : '<tr><td colspan="6">No exports have been staged.</td></tr>'

const undoReport = (batch: MoveInBatch): string => {
  const report = batch.undo_report
  if (!report) return ''
  const kept = report.kept.map(item => `<li data-kept="${escape(item.email)}" data-kept-reasons="${escape(item.reasons.join(' '))}">${escape(item.email)}: ${escape(item.reasons.map(r => keptReasons[r] ?? r).join(', '))}</li>`).join('')
  return `<section class="panel" aria-labelledby="undo-heading"><h2 id="undo-heading" data-undone>Undone</h2><p>Undone ${timeElement(batch.undone_at)}. Removed ${report.removed.length}: ${escape(report.removed.join(', ') || 'nobody')}.</p>${kept ? `<p>Kept ${report.kept.length}, with the reason:</p><ul class="kept-list">${kept}</ul>` : ''}</section>`
}

const review = (model: AuthPageModel, batch: MoveInBatch, rows: MoveInRow[]): string => {
  const open = !batch.undone_at
  const counts = new Map<string, number>()
  for (const row of rows.filter(item => item.status === 'staged')) for (const reason of row.reasons.length ? row.reasons : ['new']) counts.set(reason, (counts.get(reason) ?? 0) + 1)
  const summary = summaryOrder.filter(key => counts.get(key)).map(key => `<span class="pill">${escape(findings[key])}: <strong>${counts.get(key)}</strong></span>`).join('')
  const admitted = rows.filter(row => row.status === 'admitted')
  const unsent = admitted.filter(row => !row.invitedAt).length
  const staged = rows.filter(row => row.status === 'staged').length
  const next = open ? `<section class="panel" aria-labelledby="next-heading"><h2 id="next-heading">After admission</h2><div class="data-list">
<div class="data-row"><div><strong>Send invitations</strong><p>Admission sends no mail. This sends the ordinary invitation email to the ${unsent} ${unsent === 1 ? 'person' : 'people'} admitted from this file who have not been sent one.</p></div><form method="post" action="/api/auth/move-in/invite" data-auth-action data-reload="true"><input type="hidden" name="batchId" value="${escape(batch.id)}">${csrfField(model.csrf)}<button class="secondary-button" type="submit"${unsent ? '' : ' disabled'}>Send invitations</button></form></div>
<div class="data-row"><div><strong>Undo this batch</strong><p>Removes the people this file admitted who have never signed in and hold no passkey, app grant or later activity. Everyone else stays and is listed with the reason.</p></div><form method="post" action="/api/auth/move-in/undo" data-auth-action data-reload="true" data-confirm="Undo this batch? Untouched people it admitted are removed."><input type="hidden" name="batchId" value="${escape(batch.id)}">${csrfField(model.csrf)}<button class="danger-button" type="submit"${admitted.length ? '' : ' disabled'}>Undo this batch</button></form></div>
${batch.source_system === 'auth0' ? `<div class="data-row"><div><strong>Former Auth0 subjects</strong><p>A reviewed list of old Auth0 user ids and the Auth email each was admitted as, for app owners who choose to rebind. Auth never accepts a former subject as a credential.</p></div><a class="secondary-button" href="/api/auth/move-in/subjects.csv?batch=${encodeURIComponent(batch.id)}" download>Download CSV (${batch.former_subjects})</a></div>` : ''}
</div></section>` : undoReport(batch)
  return `<section class="panel move-in-review" aria-labelledby="review-heading"><div class="panel-header"><div><h2 id="review-heading">Review ${escape(batch.file_name)}</h2><p>${escape(sourceName(batch.source_system))} export dated ${escape(batch.export_date)}, staged ${timeElement(batch.created_at)}. ${rows.length} ${rows.length === 1 ? 'row' : 'rows'}.</p></div></div><div class="notice-panel" role="note" data-batch-proof-notice><strong>Every row: email not yet proven.</strong> A matching address never proves ownership. Admission creates invitations only: no password, factor, administrator right, app role, group permission or session is carried, and each person must open the email link in their own browser to sign in. Context labels are not permissions.</div><div class="domain-list move-in-summary">${summary || '<span class="muted">No rows are waiting for review.</span>'}</div></section>
<form method="post" action="/api/auth/move-in/admit" data-auth-action data-reload="true"><input type="hidden" name="batchId" value="${escape(batch.id)}">${csrfField(model.csrf)}<section class="table-panel move-in-table" aria-label="Staged people"><div class="table-scroll" tabindex="0" role="region" aria-label="Staged people table"><table><colgroup><col class="move-in-check"><col class="move-in-name"><col class="move-in-email"><col class="move-in-context"><col class="move-in-finding"></colgroup><thead><tr><th scope="col">Admit</th><th scope="col">Name and source id</th><th scope="col">Email</th><th scope="col">Context</th><th scope="col">Finding</th></tr></thead><tbody>${reviewRows(rows, open)}</tbody></table></div><footer class="table-footer"><span>Disabled-at-source and duplicate rows start unselected. ${staged} waiting.</span>${open && staged ? '<button class="primary-button" type="submit">Admit selected</button>' : ''}</footer></section></form>${next}`
}

export function renderMoveInPage(model: AuthPageModel): string {
  const moveIn = model.moveIn ?? { batches: [], batch: null, rows: [] }
  const batches = asArray<MoveInBatch>(moveIn.batches)
  const today = new Date().toISOString().slice(0, 10)
  const stage = `<section class="panel" aria-labelledby="stage-heading"><div class="panel-header"><div><h2 id="stage-heading">Stage an export</h2><p>Choose a user list exported from Google Workspace (CSV or JSON), Microsoft Entra (CSV), Auth0 (CSV or NDJSON), Okta (Users API JSON) or JumpCloud (CSV or JSON). Staged rows cannot sign in, receive no mail and appear only on this page. First choose Confirm my email in <a href="/app/methods#email-confirmation">Sign-in methods</a> and complete the link in this browser within ten minutes. See MOVE-IN.md for what moves and what does not.</p></div></div><form class="inline-form" method="post" action="/api/auth/move-in/stage" data-move-in-upload><div class="field"><label for="move-in-file">Export file</label><input id="move-in-file" name="file" type="file" accept=".csv,.json,.ndjson,.txt,text/csv,application/json" required></div><div class="field"><label for="move-in-date">Exported on</label><input id="move-in-date" name="exportDate" type="date" value="${today}" required></div><button type="submit">Stage file</button></form></section>`
  const list = `<section class="table-panel move-in-batches" aria-label="Staged exports"><div class="table-scroll" tabindex="0" role="region" aria-label="Staged exports table"><table><thead><tr><th scope="col">File</th><th scope="col">Source</th><th scope="col">Exported</th><th scope="col">Rows</th><th scope="col">Admitted</th><th scope="col">State</th></tr></thead><tbody>${batchRows(batches, moveIn.batch?.id)}</tbody></table></div></section>`
  const body = moveIn.batch ? review(model, moveIn.batch, asArray<MoveInRow>(moveIn.rows)) : batches.length ? '' : emptyState('Stage an export to review it here.')
  const toolbar = '<div class="toolbar"><a class="action" href="/app/people">Back to People</a></div>'
  const campaigns=campaignPanels(model)+federationPanels(model)+directorySourcePanels(model)
  return moveIn.batch ? `${toolbar}${body}${campaigns}${list}${stage}` : `${toolbar}${campaigns}${stage}${list}${body}`
}
