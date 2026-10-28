import {one, json, fail, requireSession} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {assertPermission, permitted, requireHardware, roleGuard} from '../roles/policy.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {commit} from '../roles/commit.mjs';
import {appsFor} from '../workforce/people/load.mjs';
import {timingPeriod,episodeProjection,timingSummary} from '../timing/report.mjs';

export const REPORTS = '/api/auth/reports';
const COLUMNS = {
 'mfa-enrollment':['mfaCompliant','factorTypes','factors','passwordOnly','policy'],
 'terminated-people':['episodeId','terminationEffectiveAt','leaverEventAt','localDenialAt','dispatchedAt','fullDeprovisionAt','observedDeprovisionAt','remoteVerifiedAt','inventoryCoverage','apps','unresolvedApps','unresolvedOutsideScope','sourceObservedAt','timingQualification'],
 'joiner-leaver-timeliness':['episodeId','terminationEffectiveAt','leaverEventAt','localDenialAt','dispatchedAt','fullDeprovisionAt','observedDeprovisionAt','remoteVerifiedAt','inventoryCoverage','apps','unresolvedApps','unresolvedOutsideScope','sourceObservedAt','timingQualification'],
 'administrators':['grants'],
 'dormant-accounts':['lastSignInAt','lastSignInDoor','dormantDays','observation','apps'],
 'connector-health':['appId','app','kind','lastSuccessfulSyncAt','lastReconciledAt','status','openFailures','observation'],
};
const PERSON_COLUMNS=['personId','email','name','workerType','department','status'];
const NAMES = ['mfa-enrollment', 'terminated-people', 'administrators', 'dormant-accounts', 'joiner-leaver-timeliness', 'connector-health'];
const unknown = 'unknown';
const iso = value => value === null || value === undefined ? unknown : new Date(value).toISOString();
const csvCell = value => {
  const raw = typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
  const safe = /^[=+\-@\t\r]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replaceAll('"', '""') + '"';
};
function csv(result) {
  const columns = result.columns;
  return [columns.map(csvCell).join(','), ...result.rows.map(row => columns.map(key => csvCell(key === 'asOf' ? result.asOf : key === 'summary' ? result.summary : row[key])).join(','))].join('\r\n') + '\r\n';
}
async function assertRead(ctx, s, epoch) {
  const held = await one(ctx, `SELECT 1 FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id JOIN auth_role_epoch e ON e.id=1
    WHERE s.id=? AND s.person_id=? AND s.amr=? AND s.person_version=p.version AND p.status='active' AND s.revoked_at IS NULL AND s.expires_at>? AND e.epoch=?`, s.id, s.person_id, s.amr, ctx.now(), epoch);
  if (!held) fail('report_authority_changed', 409);
}

export async function reportsRead(ctx, request, path) {
  const s = await requireSession(ctx, request); requireHardware(s);
  const query = new URL(request.url).searchParams;
  if ([...query.keys()].some(key => !['report', 'format', 'export', 'group', 'workerType', 'department', 'dormantDays','start','end','asOf'].includes(key)) ||
      [...new Set(query.keys())].some(key => query.getAll(key).length !== 1)) fail('invalid_report_filter');
  const name = path === REPORTS ? query.get('report') : path.slice(REPORTS.length + 1);
  if (name !== null && !NAMES.includes(name)) fail('report_not_found', 404);
  if(name!=='joiner-leaver-timeliness'&&['start','end','asOf'].some(key=>query.has(key)))fail('invalid_report_filter');
  const period=name==='joiner-leaver-timeliness'?timingPeriod(query,ctx.now()):null;
  const format = query.get('format') ?? 'json'; if (!['json', 'csv'].includes(format)) fail('invalid_report_format');
  const exporting = format === 'csv' || query.get('export') === '1';
  const permission = exporting ? 'audit.export' : 'audit.view';
  const state = await roleState(ctx, s); assertPermission(state, permission, {write: false});
  if (exporting) requireLocalEmail(ctx, s);
  if (name === null) { await assertRead(ctx, s, state.epoch); return json({reports: NAMES, coverage: 'Native passkey, directory and SCIM facts; unknown values stay explicit.'}); }
  const group = query.get('group'), workerType = query.get('workerType'), department = query.get('department');
  if (group && !permitted(state, permission, {groupId: group, write: false})) fail('role_permission_required', 403);
  if (workerType && !['employee', 'contractor', 'service'].includes(workerType)) fail('invalid_report_filter');
  const dormantDays = query.get('dormantDays') ?? '90';
  if (!/^[1-9]\d{0,3}$/.test(dormantDays) || Number(dormantDays) > 3650) fail('invalid_report_filter');
  // All additional facts are read in one D1 transaction. The role/directory
  // epoch fences the previously authorized roster and every field/group edit.
  const statements = [
    'SELECT person_id,created_at,last_used_at FROM auth_passkeys ORDER BY created_at',
    'SELECT person_id,created_at,amr FROM auth_sessions ORDER BY created_at DESC,id DESC',
    "SELECT p.app_id,p.subject_id,p.reason,p.event_at,p.dispatched_at,p.verified_at,p.state,a.name FROM auth_provisioning p JOIN auth_apps a ON a.id=p.app_id WHERE p.subject_type='person' ORDER BY p.event_at DESC,p.id DESC",
    'SELECT c.app_id,a.name,c.last_success_at,c.last_error,c.last_reconciled_at FROM auth_scim_connectors c JOIN auth_apps a ON a.id=c.app_id',
    'SELECT app_id,role,privileged FROM auth_privileged_app_roles',
    "SELECT target_id AS app_id,privileged FROM auth_privileged_resources WHERE kind='app'",
    'SELECT * FROM auth_timing_episodes ORDER BY event_at,id',
    'SELECT * FROM auth_timing_apps ORDER BY episode_id,app_id,channel',
  ];
  const [keys, sessions, provisioning, connectors, privilege, appPolicy,episodes,inventory] = (await ctx.db.batch(statements.map(sql => ctx.db.prepare(sql)))).map(result => result.results);
  await assertRead(ctx, s, state.epoch);
  const asOf = period?.asOf??ctx.now();
  const inScope = person => permitted(state, permission, {personId: person.id, write: false});
  const visibleApp = id => permitted(state, permission, {appId: id, write: false});
  const people = [...state.dir.people.values()].filter(person => {
    const fields = state.dir.values(person);
    return inScope(person) && (!group || state.memberships.get(person.id)?.has(group)) &&
      (!workerType || fields.kind === workerType) && (!department || fields.department === department);
  });
  const common = person => ({personId: person.id, email: person.email, name: state.dir.values(person).name ?? person.name,
    workerType: state.dir.values(person).kind, department: state.dir.values(person).department ?? unknown, status: person.state});
  const heldApps = person => [...appsFor(state.dir, person.id, state.memberships.get(person.id) ?? new Set()).values()].filter(app => visibleApp(app.appId));
  const last = person => sessions.find(session => session.person_id === person.id);
  const resourceSet = resources => Object.fromEntries(Object.entries(resources).map(([mode, kinds]) => [mode, Object.fromEntries(Object.entries(kinds).map(([kind, ids]) => [kind,
    ids.filter(id => id === '*' ? state.entries.some(entry => entry.role.permissions.includes(permission) && entry.resources.view[kind]?.includes('*')) :
      permitted(state, permission, {[{people:'personId',groups:'groupId',apps:'appId',cases:'caseId'}[kind]]: id, write: false}))]))]));
  let rows = [], directoryCount = people.length,summary;
  const gaps = ['Password/push and configurable MFA-policy qualification, historical timing audit reconciliation, scheduled delivery and compliance/Evidence connectors are not complete.'];
  if (name === 'mfa-enrollment') rows = people.map(person => {
    const factors = keys.filter(key => key.person_id === person.id).map(key => ({type: 'passkey', enrolledAt: iso(key.created_at), lastUsedAt: iso(key.last_used_at)}));
    return {...common(person), mfaCompliant: factors.length ? unknown : false, factorTypes: factors.length ? ['passkey'] : [], factors,
      passwordOnly: unknown, policy: 'Factor enrollment observed; employer MFA-policy qualification unknown'};
  });
  if (name === 'terminated-people' || name === 'joiner-leaver-timeliness') {
    const terminated = people.filter(person => person.state === 'terminated');
    const legacy=person=>{
      const byApp=new Map();
      for(const row of provisioning.filter(row=>row.subject_id===person.id&&row.event_at>=(person.terminatedAt??Infinity)&&row.state!=='superseded')){
        const prior=byApp.get(row.app_id);
        if(!prior||prior.state==='verified'&&(row.state!=='verified'||row.verified_at>prior.verified_at))byApp.set(row.app_id,row);
      }
      const work=[...byApp.values()];
      const unresolved = work.filter(row => !['verified', 'superseded'].includes(row.state));
      const hidden = unresolved.some(row => !visibleApp(row.app_id));
      return {...common(person), terminationEffectiveAt: iso(person.terminatedAt), leaverEventAt: work.length ? iso(Math.min(...work.map(row => row.event_at))) : unknown,
        episodeId:unknown,localDenialAt: unknown, fullDeprovisionAt: unknown,dispatchedAt:unknown,observedDeprovisionAt:unknown,inventoryCoverage:unknown,apps:[],
        remoteVerifiedAt: work.length && work.every(row=>row.state==='verified'&&row.verified_at!==null) ? iso(Math.max(...work.map(row => row.verified_at))) : unknown,
        unresolvedApps: [...new Set(unresolved.filter(row => visibleApp(row.app_id)).map(row => row.name))],
        unresolvedOutsideScope: hidden ? unknown : false, sourceObservedAt: unknown, timingQualification: 'unmeasured'};
    };
    if(name==='terminated-people'){
      rows=terminated.map(person=>{
        const episode=episodes.find(row=>row.person_id===person.id&&row.ended_at===null&&row.event_at===person.terminatedAt);
        return episode?{...common(person),terminationEffectiveAt:iso(episode.event_at),...episodeProjection(episode,inventory,visibleApp,asOf)}:legacy(person);
      });
    }else{
      const inPeriod=at=>at>=period.start&&at<period.end;
      rows=episodes.filter(row=>inPeriod(row.event_at)&&people.some(person=>person.id===row.person_id)).map(episode=>{
        const person=people.find(person=>person.id===episode.person_id);
        return {...common(person),terminationEffectiveAt:iso(episode.event_at),...episodeProjection(episode,inventory,visibleApp,asOf)};
      });
      rows.push(...terminated.filter(person=>inPeriod(person.terminatedAt)&&!episodes.some(row=>row.person_id===person.id&&row.event_at===person.terminatedAt)).map(legacy));
      summary=timingSummary(rows,period);
    }
    directoryCount=new Set(rows.map(row=>row.personId)).size;
  }
  if (name === 'administrators') {
    rows = people.flatMap(person => {
      const grants = state.activeGrants.filter(grant => grant.person_id === person.id && grant.role.rank > 0)
        .map(grant => ({role: grant.role.name, resources: resourceSet(grant.resources), grantedBy: inScope(state.dir.people.get(grant.granted_by) ?? {}) ? grant.granted_by : unknown,
          grantedAt: iso(grant.created_at), lastUsedAt: unknown}));
      if (['owner', 'admin'].includes(person.role)) grants.unshift({role: person.role, resources: 'organization', grantedBy: unknown, grantedAt: unknown, lastUsedAt: unknown});
      for (const app of heldApps(person)) {
        const exact = privilege.find(row => row.app_id === app.appId && row.role === (app.role ?? ''));
        const privileged = exact ? Boolean(exact.privileged) : appPolicy.find(row => row.app_id === app.appId)?.privileged !== 0;
        if (privileged) grants.push({role: app.role ?? 'default', resources: {app: app.appId, name: app.app}, grantedBy: unknown, grantedAt: unknown, lastUsedAt: unknown});
      }
      return grants.length ? [{...common(person), grants}] : [];
    }); directoryCount = rows.length;
  }
  if (name === 'dormant-accounts') {
    rows = people.filter(person => person.status === 'active' && (!last(person) || last(person).created_at <= asOf - Number(dormantDays) * 86400000)).map(person => {
      const signIn = last(person);
      return {...common(person), lastSignInAt: iso(signIn?.created_at), lastSignInDoor: signIn ? JSON.parse(signIn.amr).filter(method => method !== 'dev').join(',') || unknown : unknown,
        dormantDays: Number(dormantDays), observation: signIn ? 'last retained successful Auth session' : 'no retained successful sign-in; history unknown',
        apps: heldApps(person).map(app => app.app)};
    }); directoryCount = rows.length;
  }
  if (name === 'connector-health') {
    // Connector health is organization/app-scoped, never inferred from an empty
    // or person-filtered data set. A filter cannot silently widen that scope.
    if (group || workerType || department) fail('connector_report_has_no_person_filter');
    rows = connectors.filter(row => visibleApp(row.app_id)).map(row => ({appId: row.app_id, app: row.name, kind: 'SCIM',
      lastSuccessfulSyncAt: iso(row.last_success_at), lastReconciledAt: iso(row.last_reconciled_at),
      status: !row.last_success_at ? unknown : row.last_error || row.last_success_at + 2 * 3600000 <= asOf ? 'unhealthy' : 'observed',
      openFailures: provisioning.filter(work => work.app_id === row.app_id && people.some(person => person.id === work.subject_id) && ['pending','failed','blocked'].includes(work.state)).length,
      observation: 'Native SCIM only; upstream/compliance/other connectors unqualified'}));
    directoryCount = null;
  }
  const result = {report: name, asOf: iso(asOf), employer: ctx.organizationId ?? 'root', filters: {group, workerType, department,...(period?{start:iso(period.start),end:iso(period.end)}:{})},
    rowCount: rows.length, directoryCount, columns:['asOf',...(summary?['summary']:[]),...(name==='connector-health'?[]:PERSON_COLUMNS),...COLUMNS[name]], rows, gaps, epoch: state.epoch,...(summary?{summary}:{}),
    ...(period?{scopeAsOf:iso(ctx.now()),scopeQualification:'Current authorized directory filters; historical membership and profile reconstruction unknown'}:{})};
  await assertRead(ctx, s, state.epoch);
  if (exporting) await commit(ctx, s, roleGuard(ctx, s, state), 'reports.export', null, {report: name, asOf, rowCount: rows.length, filters: result.filters,...(summary?{summary}:{})});
  const headers = {'cache-control':'no-store', 'x-auth-report-count': String(rows.length), 'x-auth-report-as-of': iso(asOf),...(summary?{'x-auth-timing-summary':JSON.stringify(summary)}:{})};
  if (format === 'csv') return new Response(csv(result), {headers: {...headers, 'content-type':'text/csv; charset=utf-8', 'content-disposition': `attachment; filename="auth-${name}.csv"`}});
  return json(result, 200, {...headers, ...(exporting ? {'content-disposition': `attachment; filename="auth-${name}.json"`} : {})});
}
