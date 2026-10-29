import { createBusinessSettings } from '../modules/business-settings/index.ts'
import { SettingsError, type TeamAdapter, type ManagedMember } from '../modules/business-settings/types.ts'
import { authPeople } from './people.ts'
import type { Bindings } from '../auth.server'

export const business = { settings: 1 as const, values: ['display_name' as const], team: { roles: { admin: 'admin', member: 'member' } } }
/** Bind a signed roster to already admitted identities. This door cannot create,
 * activate, promote, demote or invite an Auth identity; native admission owns it. */
function team(env: Bindings): TeamAdapter {
  return {
    ownerEmail: async () => (await env.DB.prepare("SELECT p.email FROM oa_bootstrap b JOIN oa_operators p ON p.id=b.claim_id WHERE p.role='owner'").first<{ email: string }>())?.email ?? null,
    async prepare({ members, managed }) {
      const rows: ManagedMember[] = []
      for (const member of members) {
        const prior = managed.find(row => member.id && row.businessId === member.id)
        const row = prior?.operatorId
          ? await env.DB.prepare('SELECT id,role,email FROM oa_operators WHERE id=?').bind(prior.operatorId).first<{ id: string; role: string; email: string }>()
          : await env.DB.prepare('SELECT id,role,email FROM oa_operators WHERE email=?').bind(member.email).first<{ id: string; role: string; email: string }>()
        if (row && managed.some(prior => prior.operatorId === row.id && prior.businessId && member.id && prior.businessId !== member.id)) throw new SettingsError('business_member_binding_mismatch')
        const person = row && await authPeople(env).person(row.id)
        if (row?.role === 'owner') throw new SettingsError('business_member_binding_mismatch')
        const valid = person && row?.role === member.role
        rows.push({ email: member.email, operatorId: row?.id ?? prior?.operatorId ?? null, invite: member.invite,
          state: valid ? 'active' as const : 'conflict' as const, businessId: member.id ?? prior?.businessId ?? null, businessRole: member.role })
      }
      for (const prior of managed) if (!rows.some(row => row.email === prior.email)) rows.push({ ...prior, state: 'inactive' })
      return { rows, statements: [], async afterCommit() {} }
    },
  }
}
export function authBusiness(env: Bindings) {
  return createBusinessSettings({ db: env.DB, business, trust: env.RER_BUSINESS_TRUST, team: team(env) })
}
