import { createAgentDoor, type Trust } from '../modules/agent-door/index.ts'
import { authPeople } from './people.ts'
import { nativeTools, nativeResources } from './tools.ts'
import type { Bindings } from '../auth.server'

export const notTools = [
  { clauses: ['AUTH-MOVEIN-001'], reason: 'import-door' as const },
  { clauses: ['AUTH-HOST-001', 'CMD-001', 'AUTH-OPS-001'], reason: 'installation' as const },
  { clauses: ['AUTH-PROTOCOL-001', 'AUTH-AUTHENTICATOR-001'], reason: 'screen' as const },
  { clauses: ['AUTH-SWA-001', 'AUTH-DESKTOP-001', 'AUTH-MOBILE-001'], reason: 'device' as const },
  { clauses: ['AUTH-LEGACY-001', 'AUTH-GATEWAY-001', 'AUTH-DEVELOPER-001'], reason: 'connector' as const },
]
function trust(env: Bindings): Trust | null {
  const issuer = env.RER_OWNER_CLAIM_ISSUER, installationId = env.RER_OWNER_CLAIM_INSTALLATION_ID
  const appOrigin = env.RER_OWNER_CLAIM_APP_ORIGIN, publicKeys = env.RER_OWNER_CLAIM_PUBLIC_KEYS
  if (![issuer, installationId, appOrigin, publicKeys].some(Boolean)) return null
  if (!issuer || !installationId || !appOrigin || !publicKeys || appOrigin !== env.AUTH_ORIGIN) throw new Error('Incomplete agent door trust')
  return { issuer, installationId, appOrigin, publicKeys: JSON.parse(publicKeys) }
}
export function authAgentDoor(env: Bindings) {
  const people = authPeople(env), configuredTrust = trust(env)
  return createAgentDoor({ seed: 'auth', name: 'Auth', specialist: 'identity steward', origin: env.AUTH_ORIGIN, db: env.DB,
    capabilities: ['tools', 'policy', 'pause', 'audit', 'idempotency'],
    trust: configuredTrust, people,
    currentScopes: async principal => !configuredTrust || await people.businessMember?.(principal.person) ? [...principal.scopes] : [],
    tools: nativeTools(env), resources: nativeResources(env), notTools,
  })
}
