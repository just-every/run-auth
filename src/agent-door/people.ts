import type { PeopleAdapter, Person } from '../modules/agent-door/index.ts'
import { session } from '../auth/core.mjs'
import { nativeAdmission } from './native.mjs'
import type { Bindings } from '../auth.server'
import { identityAuth } from '../auth.server'

/** Auth's identity admission is authoritative; a Base bootstrap cookie is never a session here. */
export function authPeople(env: Bindings): PeopleAdapter {
  const native = identityAuth(env).context
  const policyRoles = new WeakMap<Person, 'owner' | 'editor' | null>()
  async function person(id: string): Promise<Person | null> {
    const row = await env.DB.prepare('SELECT id,email,display_name AS name,role,status FROM oa_operators WHERE id=?').bind(id).first<Person & { status: string }>()
    if (!row || row.status !== 'active' || !await nativeAdmission(native, row)) return null
    const proof = await env.DB.prepare('SELECT verified_at FROM auth_emails WHERE person_id=?').bind(id).first<{ verified_at: number }>()
    if (!proof || proof.verified_at + 30 * 86400000 <= Date.now() || !await env.DB.prepare('SELECT 1 FROM auth_passkeys WHERE person_id=?').bind(id).first()) return null
    // Business credentials do not supply the proof of a required upstream IdP.
    if (row.role !== 'owner' && await env.DB.prepare('SELECT 1 FROM oa_domain_rules WHERE domain=?').bind(row.email.split('@')[1]).first()) return null
    const current = { id: row.id, email: row.email, name: row.name, role: row.role, active: true }
    policyRoles.set(current, (await member(current))?.role ?? null)
    return current
  }
  const owner = () => env.DB.prepare("SELECT p.id FROM oa_bootstrap b JOIN oa_operators p ON p.id=b.claim_id WHERE p.role='owner'").first<{ id: string }>()
  async function member(p: Person) {
    const settings = await env.DB.prepare('SELECT owner_id FROM bs_settings WHERE singleton=1 AND stopped=0').first<{ owner_id: string | null }>()
    if (!settings) return null
    if (settings.owner_id && (await owner())?.id === p.id) return { id: settings.owner_id, role: 'owner' as const }
    const row = await env.DB.prepare("SELECT business_id,business_role FROM bs_team WHERE operator_id=? AND state='active' AND business_id IS NOT NULL").bind(p.id).first<{ business_id: string; business_role: string }>()
    return row ? { id: row.business_id, role: row.business_role === 'admin' ? 'editor' as const : null } : null
  }
  return {
    person, businessMember: member,
    businessRole: p => policyRoles.get(p) ?? (p.role === 'owner' ? 'owner' : null),
    async sponsor({ sub }) {
      const settings = await env.DB.prepare('SELECT owner_id FROM bs_settings WHERE singleton=1 AND stopped=0').first<{ owner_id: string | null }>()
      if (!settings) return null
      if (settings.owner_id === sub) { const row = await owner(); return row ? person(row.id) : null }
      const row = await env.DB.prepare("SELECT operator_id FROM bs_team WHERE business_id=? AND state='active'").bind(sub).first<{ operator_id: string | null }>()
      return row?.operator_id ? person(row.operator_id) : null
    },
    async session(request) {
      const url = new URL(request.url)
      if (url.origin !== env.AUTH_ORIGIN || request.headers.has('host') && request.headers.get('host')?.toLowerCase() !== url.host.toLowerCase()) return null
      const current = await session(native, request)
      if (!current || !JSON.parse(current.amr).includes('hwk')) return null
      return person(current.person_id)
    },
  }
}
