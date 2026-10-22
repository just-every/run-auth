import { csrfField, emptyState, escape, timeElement } from '../helpers.js'

export interface RetentionPeriod { unit: 'days' | 'months' | 'years'; value: number }
export interface RetentionHold {
  id: string
  kind: string
  source: string
  period_start: number
  period_end: number
  classes: string[]
  reason?: string
}
export interface RetentionRun {
  id: string
  status: string
  policyRevision: number
  createdAt: number
  deleteAfter: number
  completedAt: number | null
  summary: Record<string, { count: number; stores: Record<string, number> }>
  result: Record<string, number>
  canExport: boolean
}
export interface RetentionModel {
  canManage: boolean
  policy: { classes: Record<string, RetentionPeriod>; revision: number; configured: boolean; updatedAt?: number }
  classes: string[]
  holds: RetentionHold[]
  runs: RetentionRun[]
  previewWindowMs: number
  storage: { controller: string; configuration: string; choices: string[]; verifiedRegion: string | null }
  secretCustody: Record<string, string>
  limitations: string[]
}

const labels: Record<string, string> = {
  profiles: 'Profiles', sourceSnapshots: 'Source snapshots', authentication: 'Authentication history',
  decisions: 'Access decisions', provisioning: 'Provisioning evidence', audit: 'Audit records',
  modelTraces: 'Model traces', erasureReceipts: 'Erasure receipts',
}
const label = (name: string): string => labels[name] ?? name.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/_/g, ' ')
const limits = (unit: RetentionPeriod['unit']): [number, number] => unit === 'days' ? [90, 2555] : unit === 'months' ? [4, 84] : [1, 7]
const periodControls = (name: string, period: RetentionPeriod): string => {
  const [min, max] = limits(period.unit)
  return `<fieldset data-retention-period><legend>${escape(label(name))}</legend><div class="directory-fields"><label class="field">Keep for<input type="number" name="${escape(name)}.value" min="${min}" max="${max}" value="${period.value}" required data-retention-value></label><label class="field">Unit<select name="${escape(name)}.unit" data-retention-unit>${['days', 'months', 'years'].map(unit => `<option value="${unit}"${period.unit === unit ? ' selected' : ''}>${unit}</option>`).join('')}</select></label></div></fieldset>`
}

export function retentionPanel(model: { retention?: RetentionModel; csrf?: string }): string {
  const data = model.retention
  if (!data) return ''
  const policy = data.policy
  const settings = data.canManage ? `<form class="directory-form" method="post" action="/api/auth/retention/settings" data-retention-form="settings">${csrfField(model.csrf)}${data.classes.map(name => periodControls(name, policy.classes[name])).join('')}<p>Choose 90–2,555 days, 4–84 calendar months, or 1–7 calendar years per class. Calendar months and years retain their calendar meaning.</p><label><input type="checkbox" name="confirm" required> I confirm these periods and the expiry they authorize.</label><button class="primary-button" type="submit">Save retention policy</button><p data-retention-result role="status"></p></form>` : `<dl class="effect-list">${data.classes.map(name => `<div><dt>${escape(label(name))}</dt><dd>${policy.classes[name].value} ${escape(policy.classes[name].unit)}</dd></div>`).join('')}</dl>`
  const holdRows = data.holds.map(hold => `<div class="data-row"><div><h3>${escape(label(hold.kind))} hold</h3><p>${hold.period_start === 0 && hold.period_end === 8640000000000000 ? 'All retained dates' : `${timeElement(hold.period_start)} – ${timeElement(hold.period_end)}`}</p><p>${escape(hold.classes.map(label).join(', '))}</p>${hold.reason ? `<p class="issuer-host">${escape(hold.reason)}</p>` : ''}<p class="data-meta">Source: ${escape(hold.source)}</p>${data.canManage && hold.source === 'retention' ? `<form method="post" action="/api/auth/retention/hold" data-retention-form="release">${csrfField(model.csrf)}<input type="hidden" name="id" value="${escape(hold.id)}"><button class="secondary-button" type="submit">Release hold</button><p data-retention-result role="status"></p></form>` : '<p class="data-meta">This hold is managed by its source.</p>'}</div></div>`).join('')
  const createHold = data.canManage ? `<details><summary>Create a retention hold</summary><form class="directory-form" method="post" action="/api/auth/retention/hold" data-retention-form="hold">${csrfField(model.csrf)}<div class="directory-fields"><label class="field">Hold kind<select name="kind">${['review', 'request', 'investigation', 'legal'].map(kind => `<option value="${kind}">${escape(label(kind))}</option>`).join('')}</select></label><label class="field">Period start<input name="periodStart" type="datetime-local" required></label><label class="field">Period end<input name="periodEnd" type="datetime-local" required></label><label class="field">Reason<input name="reason" required maxlength="500"></label></div><fieldset><legend>Classes protected by this hold</legend><div class="directory-fields">${data.classes.map(name => `<label><input type="checkbox" name="classes" value="${escape(name)}" checked> ${escape(label(name))}</label>`).join('')}</div></fieldset><button class="primary-button" type="submit">Create hold</button><p data-retention-result role="status"></p></form></details>` : ''
  const runs = data.runs.map(run => `<div class="data-row"><div><h3>Expiry ${escape(run.status)}</h3><p>Created ${timeElement(run.createdAt)} · Policy revision ${run.policyRevision}</p><p>${run.status === 'queued' ? 'Eligible for cleanup after' : 'Preview window ended'} ${timeElement(run.deleteAfter)}${run.completedAt ? ` · Finished ${timeElement(run.completedAt)}` : ''}</p><dl class="effect-list">${Object.entries(run.summary).map(([name, summary]) => `<div><dt>${escape(label(name))}</dt><dd>${summary.count} records in the preview</dd></div>`).join('')}</dl>${Object.keys(run.result).length ? `<details><summary>Cleanup counts by store</summary><dl class="effect-list">${Object.entries(run.result).map(([name, count]) => `<div><dt>${escape(name)}</dt><dd>${count}</dd></div>`).join('')}</dl></details>` : ''}${run.canExport ? `<p><a class="secondary-button" href="/api/auth/retention/export?runId=${encodeURIComponent(run.id)}">Download expiry export</a></p>` : ''}</div></div>`).join('')
  const queue = data.canManage ? `<form method="post" action="/api/auth/retention/preview" data-retention-form="queue">${csrfField(model.csrf)}<button class="secondary-button" type="submit">Queue deletion preview</button><p data-retention-result role="status"></p></form>` : ''
  const storage = `<section class="panel stacked"><h2>Storage and secret custody</h2><p>Data controller: ${escape(data.storage.controller)}. Region and processors are selected in the ${escape(data.storage.configuration)} configuration.</p><p>${data.storage.verifiedRegion ? `Verified region: ${escape(data.storage.verifiedRegion)}` : 'The deployment region is not verified here.'}</p><ul>${data.storage.choices.map(choice => `<li>${escape(choice)}</li>`).join('')}</ul><dl class="effect-list">${Object.entries(data.secretCustody).map(([name, value]) => `<div><dt>${escape(label(name))}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl></section>`
  return `<section class="panel stacked" data-retention><div class="panel-header"><div><h2>Data retention</h2><p>${policy.configured ? `Configured policy · Revision ${policy.revision}` : 'Default policy: 13 calendar months for every class.'}${policy.updatedAt ? ` · Updated ${timeElement(policy.updatedAt)}` : ''}</p><p>Expired records receive a ${Math.round(data.previewWindowMs / 86400000)}-day preview before cleanup. Holds and unfinished work protect evidence. Changing the policy cancels previews made under an earlier revision.</p></div></div>${settings}</section><section class="panel stacked"><h2>Retention holds</h2>${holdRows ? `<div class="data-list">${holdRows}</div>` : emptyState('No active retention holds.')}${createHold}</section><section class="panel stacked" data-retention-previews><h2>Deletion previews and exports</h2><p>Inspect eligible records before queuing a preview. Queued records can be downloaded until cleanup. The scheduled cleanup rechecks holds and unfinished work before removing unchanged records.</p><div class="button-row"><button class="secondary-button" type="button" data-retention-preview>Preview eligible records</button>${queue}</div><div data-retention-preview-result aria-live="polite" hidden></div>${runs ? `<div class="data-list">${runs}</div>` : emptyState('No expiry runs yet.')}</section>${storage}<section class="panel stacked"><h2>Retention scope and limits</h2><ul>${data.limitations.map(value => `<li>${escape(value)}</li>`).join('')}</ul></section><script src="/auth-assets/retention-ui.js" defer></script>`
}
