// This bridge is bundled only by Vite dev. The production entry never imports it.
import { createWorker } from './server'
import { withDevIdentity } from './modules/operator-auth/dev/index.mjs'
import { devGate, devNotFound } from './modules/operator-auth/index.mjs'
import { authConfig, runtimeBindings, operatorAuth, identityAuth, type Bindings } from './auth.server'
import { createSession, session, cookie, cookieName } from './auth/core.mjs'
import { devPersonas } from './dev-personas'

const allowDevSession = async (request: Request, original: Bindings) => {
 const env = runtimeBindings(original)
 const gate = devGate({ key: env.RER_DEV_KEY, origin: env.AUTH_ORIGIN, local: env.AUTH_LOCAL === 'true' })
 return env.RER_DEV_IDENTITY !== 'off' && Boolean(gate && await gate.admits(request))
}
const production = createWorker({ allowDevSession })
const worker = { ...production, async fetch(request: Request, env: Bindings, execution: ExecutionContext) {
 const response = await production.fetch(request, env, execution)
 // The Base dev-key fragment exchanger needs an HTML document at its root.
 // Serve the real sign-in document there until a session is established.
 if (new URL(request.url).pathname === '/' && response.status === 303 && response.headers.get('location')?.startsWith('/signin')) {
  return production.fetch(new Request(new URL('/signin?returnTo=%2Fsetup', request.url), request), env, execution)
 }
 return response
} }
const baseDev = withDevIdentity<Bindings, typeof worker>(worker, { bindings: runtimeBindings, config: authConfig, personas: devPersonas })
export default {
 ...baseDev,
 async fetch(request, original, execution) {
  const env = runtimeBindings(original)
  const gate = devGate({ key: env.RER_DEV_KEY, origin: env.AUTH_ORIGIN, local: env.AUTH_LOCAL === 'true' })
  const path = new URL(request.url).pathname
  const response = await baseDev.fetch(request, original, execution)
  if (path !== '/auth/dev/enter' || response.status !== 303) return response
  if (!gate || !await gate.admits(request)) return devNotFound()
  const auth = identityAuth(env, r => allowDevSession(r, env)), headers = new Headers(response.headers)
  const existing = await session(auth.context, request)
  if (existing) await env.DB.prepare('UPDATE auth_sessions SET revoked_at=? WHERE id=?').bind(Date.now(), existing.id).run()
  const combined = new Headers(request.headers)
  const jar = new Map((request.headers.get('cookie') ?? '').split(';').filter(Boolean).map(value => value.trim().split('=') as [string, string]))
  for (const value of response.headers.getSetCookie()) { const [name, token] = value.split(';')[0].split('='); jar.set(name, token) }
  combined.set('cookie', [...jar].map(([name, token]) => `${name}=${token}`).join('; '))
  const signedOut = new URL(request.url).searchParams.get('as') === 'signed-out'
  const native = signedOut ? null : await operatorAuth(env).getSession(new Request(request, { headers: combined }))
  if (native?.kind === 'dev') headers.append('set-cookie', (await createSession(auth.context, native.operator.id, [])).header)
  else headers.append('set-cookie', cookie(auth.context, cookieName(auth.context), '', 0))
  return new Response(response.body, { status: response.status, headers })
 },
} satisfies ExportedHandler<Bindings>
