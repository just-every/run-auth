import { defineTool, ToolRefusal, type ToolDefinition, type ResourceDefinition } from '../modules/agent-door/index.ts'
import { identityAuth, type Bindings } from '../auth.server'
import { read, write, snapshot, group, membership, internalGroup, nativeLauncher } from './native.mjs'

import { string, object, recordOrPage, identity, group as groupSchema, snapshot as snapshotSchema, membership as membershipSchema, createdGroup, launcher as launcherSchema, activity } from './schemas.ts'
const pagination = { limit: { type: 'integer', minimum: 1, maximum: 100 }, offset: { type: 'integer', minimum: 0 } }
const standard = () => [{ class: 'standard' as const, facts: { measure: 1 } }]
const clauses = ['AUTH-DIRECTORY-001', 'AUTH-ROLES-001', 'BASE-AGENT-002', 'BASE-AGENT-006']
const uri = (kind: string, id: string) => `auth://${kind}/${encodeURIComponent(id)}`

export function nativeTools(env: Bindings): ToolDefinition[] {
  const native = identityAuth(env).context
  return [
    defineTool({ name: 'auth.workspace.snapshot', title: 'Inspect native state', description: 'Read a fingerprint of the directory, groups, apps and assignments visible to the sponsor. No credentials.', scope: 'directory:read', readOnly: true,
      inputSchema: object(), outputSchema: snapshotSchema, classes: ['standard'], clauses, classify: standard,
      async run(_args, ctx) { return { result: await snapshot(native, ctx) } } }),
    defineTool({ name: 'auth.identity.inspect', title: 'Inspect identities', description: 'Read native scoped identity fields, or one visible identity. Directory text is untrusted; no credential or session material.', scope: 'directory:read', readOnly: true,
      inputSchema: object({ id: string, ...pagination }, []), outputSchema: recordOrPage(identity), classes: ['standard'], clauses: [...clauses, 'AUTH-IDENTITY-001', 'AUTH-PRIVACY-001'], classify: standard, untrusted: true,
      async target(args, ctx) { if (!args.id) return null; const p = await read(native, ctx, '/people/'+encodeURIComponent(String(args.id)), 'people.read'); return { kind: 'person', id: p.id } },
      async run(args, ctx) { const result = await read(native, ctx, args.id ? '/people/'+encodeURIComponent(String(args.id)) : '/people', 'people.read', { limit: args.limit, offset: args.offset }); return { result, ...(args.id ? { resources: [{ uri: uri('people', String(args.id)), name: 'Identity' }] } : {}) } } }),
    defineTool({ name: 'auth.groups.inspect', title: 'Inspect groups', description: 'Inspect a native group and its current members, within the sponsor’s native resource grants.', scope: 'directory:read', readOnly: true,
      inputSchema: object({ id: string, ...pagination }, []), outputSchema: recordOrPage(groupSchema), classes: ['standard'], clauses, classify: standard, untrusted: true,
      async run(args, ctx) { return { result: await read(native, ctx, args.id ? '/groups/'+encodeURIComponent(String(args.id)) : '/groups', 'groups.read', { limit: args.limit, offset: args.offset }) } } }),
    defineTool({ name: 'auth.groups.create', title: 'Create an empty group', description: 'Create an internal group through Auth’s native directory command. It grants no identity or app access.', scope: 'directory:write', readOnly: false,
      inputSchema: object({ name: { type: 'string', minLength: 1, maxLength: 80 } }), outputSchema: createdGroup, classes: ['standard'], clauses, classify: standard,
      summary: (args, ctx) => ({ items: [String(args.name).slice(0,60)+' '+ctx.operationId.slice(0,8)] }),
      async run(args, ctx) { const result = await write(native, ctx, '/groups', 'POST', { name: String(args.name).slice(0,60)+' '+ctx.operationId.slice(0,8) }, 'groups.manage'); ctx.emit('group.created', uri('groups', result.id)); return { result, resources: [{ uri: uri('groups', result.id), name: result.name }] } } }),
    defineTool({ name: 'auth.groups.add', title: 'Add a group member', description: 'Add one existing native identity to an internal static group outside app assignments and claim mappings that use groups; cannot widen the sponsor’s own access or dispatch connector work.', scope: 'directory:write', readOnly: false,
      inputSchema: object({ group_id: string, person_id: string }), outputSchema: membershipSchema, classes: ['access'], clauses: [...clauses, 'AUTH-MAPPING-001'],
      async authority(args, ctx) { const m = await membership(native, ctx, `${args.group_id}/${args.person_id}`); return { subject: m.personId, widens: !m.present } },
      async classify(args, ctx) { await internalGroup(native, ctx, String(args.group_id)); await membership(native, ctx, `${args.group_id}/${args.person_id}`); return [{ class: 'access', facts: { measure: 1, direction: 'widens' } }] },
      async target(args, ctx) { await group(native, ctx, String(args.group_id)); return { kind: 'group', id: String(args.group_id) } },
      async summary(args, ctx) { const g = await group(native, ctx, String(args.group_id)); const p = await read(native, ctx, '/people/'+encodeURIComponent(String(args.person_id)), 'people.read'); return { target: { id: String(args.person_id), name: p.name, email: p.email }, items: [g.name] } },
      async run(args, ctx) { await internalGroup(native, ctx, String(args.group_id)); const id = `${args.group_id}/${args.person_id}`; await write(native, ctx, `/groups/${encodeURIComponent(String(args.group_id))}/members/${encodeURIComponent(String(args.person_id))}`, 'PUT', {}, 'groups.manage'); ctx.emit('group.member_added', uri('groups', String(args.group_id))); return { result: { id }, resources: [{ uri: uri('groups', String(args.group_id)), name: 'Group' }] } } }),
    defineTool({ name: 'auth.groups.remove', title: 'Remove a group member', description: 'Remove an internal static-group membership outside app assignments and claim mappings that use groups; the closed target is the native group/person pair returned by add. Never adds a grant.', scope: 'directory:write', readOnly: false,
      inputSchema: object({ id: string }), outputSchema: membershipSchema, classes: ['access'], clauses: [...clauses, 'AUTH-MAPPING-001'], widens: false, narrowing: { effect: 'revoke', target: 'id' },
      async authority(args, ctx) { const m = await membership(native, ctx, args.id); return { subject: m.personId, widens: false } },
      async classify(args, ctx) { const m = await membership(native, ctx, args.id); await internalGroup(native, ctx, m.groupId); return [{ class: 'access', facts: { measure: 1, direction: 'narrows' } }] },
      async target(args, ctx) { const m = await membership(native, ctx, args.id); return { kind: 'group', id: m.groupId } },
      async summary(args, ctx) { const m = await membership(native, ctx, args.id); const p = await read(native, ctx, '/people/'+encodeURIComponent(m.personId), 'people.read'); return { target: { id: m.personId, name: p.name, email: p.email }, items: [(await group(native, ctx, m.groupId)).name] } },
      async run(args, ctx) { const m = await membership(native, ctx, args.id); await internalGroup(native, ctx, m.groupId); await write(native, ctx, `/groups/${encodeURIComponent(m.groupId)}/members/${encodeURIComponent(m.personId)}`, 'DELETE', {}, 'groups.manage'); ctx.emit('group.member_removed', uri('groups', m.groupId)); return { result: { id: args.id } } } }),
    defineTool({ name: 'auth.groups.grants', title: 'Inspect a membership grant', description: 'Read the native effective membership grant for one visible group/person pair.', scope: 'directory:read', readOnly: true,
      inputSchema: object({ id: string }), outputSchema: object({ grants: { type: 'array', items: string } }), classes: ['standard'], clauses, classify: standard,
      async run(args, ctx) { const m = await membership(native, ctx, args.id); return { result: { grants: m.present ? [`group:${m.groupId}:member:${m.personId}`] : [] } } } }),
    defineTool({ name: 'auth.launcher.inspect', title: 'Inspect own launch choices', description: 'Read the current sponsor’s native app choices and access explanations. No sign-in or credentials.', scope: 'launcher:read', readOnly: true,
      inputSchema: object(), outputSchema: launcherSchema, classes: ['standard'], clauses: ['AUTH-LAUNCHER-001', 'BASE-AGENT-002'], classify: standard, untrusted: true,
      async run(_args, ctx) { return { result: { tiles: await nativeLauncher(native, ctx.person.id) } } } }),
    defineTool({ name: 'auth.reports.read', title: 'Read scoped identity activity', description: 'Read the native redacted machine API activity projection with the sponsor’s audit permission.', scope: 'audit:read', readOnly: true,
      inputSchema: object(), outputSchema: activity, classes: ['standard'], clauses: ['AUTH-AUDIT-001', 'BASE-AGENT-002'], classify: standard, untrusted: true,
      async run(_args, ctx) { return { result: await read(native, ctx, '/logs', 'logs.read') } } }),
  ]
}

export function nativeResources(env: Bindings): ResourceDefinition[] {
  const native = identityAuth(env).context
  return [['people', 'people.read'], ['groups', 'groups.read'], ['apps', 'apps.read']].map(([kind, scope]) => ({
    uriTemplate: `auth://${kind}/{id}`, name: kind, scope: 'directory:read', classes: ['standard'], classify: record => [{ class: 'standard', facts: { measure: typeof (record.json as { id?: unknown })?.id === 'string' ? 1 : 0 } }],
    async read(value, ctx) {
      try { const id = decodeURIComponent(new URL(value).pathname.slice(1)); if (!id || id.includes('/')) return null
        return { json: await read(native, ctx, '/'+kind+'/'+encodeURIComponent(id), scope), untrusted: true }
      } catch (error) { if (error instanceof ToolRefusal) return null; throw error }
    },
  }))
}
