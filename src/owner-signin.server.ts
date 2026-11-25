import { createOperatorAuth, createAuthHandler } from '@runeditrun/rer/modules/operator-auth'
import { FRAME_SOURCES, framedPage } from './auth/page-frame.mjs'
import type { Bindings } from './auth.server'

export const OWNER_SIGNIN_PATH = '/auth/owner-signin'

export async function mailOffOwnerSignIn(request: Request, env: Bindings, config: Parameters<typeof createOperatorAuth>[0]['config']): Promise<Response> {
 const auth = createOperatorAuth({ db: env.DB, config, clientIp: request => request.headers.get('CF-Connecting-IP') ?? '' })
 if (['GET', 'HEAD'].includes(request.method) && !new URL(request.url).searchParams.has('token')) {
  const session = await auth.getSession(request)
  if (session?.operator.role === 'owner') {
   return new Response(request.method === 'HEAD' ? null : framedPage('Installation owner signed in — Auth',
    '<h1>Installation owner signed in</h1><p>Outbound email is off. Connect a mail provider to sign in to Auth, enroll a passkey, and administer identities.</p>'),
   { headers: {
    'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
    'content-security-policy': `default-src 'none'; ${FRAME_SOURCES}; frame-ancestors 'none'; base-uri 'none'`,
   } })
  }
 }
 const response = await createAuthHandler(auth)(request)
 if (!response) return new Response(null, { status: 404, headers: { 'cache-control': 'no-store' } })
 if (request.method === 'POST' && response.status === 303 && response.headers.has('set-cookie')) {
  const headers = new Headers(response.headers)
  headers.set('location', OWNER_SIGNIN_PATH)
  return new Response(null, { status: 303, headers })
 }
 return response
}
