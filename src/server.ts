import start from '@tanstack/react-start/server-entry'
import { Hono } from 'hono'
import { dispatch } from './base/dispatch'
import { authResponse, identityAuth, type Bindings } from './auth.server'
import { isPrivatePath } from './private-paths'

import { maintainAuth } from './auth/index.mjs'

const api = new Hono()
api.get('/health', (context) => context.json({ status: 'ok' }))

export function createWorker(options: { allowDevSession?: (request: Request, env: Bindings) => Promise<boolean> } = {}) { return {
  async fetch(request: Request, env: Bindings, execution: ExecutionContext) {
    if (isPrivatePath(request)) return new Response(null, { status: 404, headers: { 'cache-control': 'no-store' } })
    const auth = await authResponse(request, env, execution, options.allowDevSession ? r => options.allowDevSession!(r, env) : undefined)
    if (auth) return auth
    return dispatch(request, () => api.fetch(request, env, execution), () => start.fetch(request))
  },
  async scheduled(_controller, env) { await maintainAuth(identityAuth(env).context) },
} satisfies ExportedHandler<Bindings> }
export default createWorker()
