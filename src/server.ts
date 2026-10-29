import start from '@tanstack/react-start/server-entry'
import { Hono } from 'hono'
import { dispatch } from './base/dispatch'
import { staticAssetResponse } from './base/static-assets'
import { deploymentHealth } from './base/deployment-health'
import { authResponse, identityAuth, notFoundDocument, openSessionResponse, runtimeBindings, type Bindings } from './auth.server'
import { ownerClaimResponse } from './owner-claim.server'
import { isPrivatePath } from './private-paths'

import { maintainAuth } from './auth/index.mjs'
import { lobbyResponse } from './base/lobby'
import { setupStateResponse } from './base/setup-state'
import { identity } from './identity'
import { authAgentDoor } from './agent-door/index.ts'
import { authBusiness } from './agent-door/business.ts'

const api = new Hono<{ Bindings: Bindings }>()
api.get('/health', (context) => context.json({ status: 'ok', ...deploymentHealth(context.env) }))

export function createWorker(options: { allowDevSession?: (request: Request, env: Bindings) => Promise<boolean> } = {}) { return {
  async fetch(request: Request, env: Bindings, execution: ExecutionContext) {
    if (isPrivatePath(request)) return new Response(null, { status: 404, headers: { 'cache-control': 'no-store' } })
    // A hosted deploy runs this Worker before its static assets; built files come from ASSETS.
    const asset = await staticAssetResponse(request, env)
    if (asset) return asset
    // The installed homepage: Base's Lobby at / and the public claim state it reads.
    const bindings = runtimeBindings(env)
    const businessResponse = await authBusiness(bindings).handle(request)
    if (businessResponse) return businessResponse
    const agentResponse = await authAgentDoor(bindings).handle(request)
    if (agentResponse) return agentResponse
    const state = await setupStateResponse(request, bindings)
    if (state) return state
    const open = new URL(request.url).pathname === '/' && await openSessionResponse(request, env, execution, options.allowDevSession ? r => options.allowDevSession!(r, env) : undefined)
    if (open) return open
    const deployment = await authBusiness(bindings).resolve('display_name', identity.deployment)
    const lobby = await lobbyResponse(request, bindings, { ...identity, deployment: String(deployment) })
    if (lobby) return lobby
    const claim = await ownerClaimResponse(request, env)
    if (claim) return claim
    const auth = await authResponse(request, env, execution, options.allowDevSession ? r => options.allowDevSession!(r, env) : undefined)
    if (auth) return auth
    return notFoundDocument(request, await dispatch(request, () => api.fetch(request, env, execution), () => start.fetch(request)))
  },
  async scheduled(_controller, env) { await maintainAuth(identityAuth(env).context) },
} satisfies ExportedHandler<Bindings> }
export default createWorker()
