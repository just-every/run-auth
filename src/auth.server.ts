import { organizationDatabase } from './auth/tenancy/storage.mjs'
import { organizationRequest, organizationResponse } from './auth/tenancy/context.mjs'
import { firstRunResponse } from './base/setup'
import { fontDocumentResponse } from './base/font-response'
import { createOperatorAuth, createAuthHandler, devGate, devNotFound, type AuthConfig } from './modules/operator-auth/index.mjs'
import { operatorMail } from './mail.server.mjs'
import { createD1DevelopmentOutbox, createDevelopmentOutboxHandler } from './modules/mail/src/development/index.mjs'
import { createAuthRuntime, type AuthRuntimeOptions } from './auth/index.mjs'
import { renderAuthPage, renderSignInPage, type AuthPage } from './ui/index'
import branding from './branding.json'

const theme = { href: '/rer-theme.css', productName: branding.name, accentColor: branding.primaryColor }
export interface Bindings {
 ASSETS?: Fetcher
 RER_DEPLOY_SOURCE?: string
 RER_DEPLOY_FINGERPRINT?: string
 RER_VERSION?: { id: string }
 AUTH_ORGANIZATION_ID?: string
 DB: D1Database
 AUTH_ORIGIN: string
 AUTH_LOCAL?: string
 RER_DEV_ORIGIN?: string
 RER_DEV_KEY?: string
 RER_DEV_IDENTITY?: string
 RER_INSTALLATION_ID?: string
 RER_MANAGEMENT_ORIGIN?: string
 OWNER_EMAIL: string
 AUTH_UPSTREAM_PROVIDERS?: string
 // RER Managed: public keys (JSON object kid -> JWK) whose signed link approvals this install accepts.
 RER_LINK_APPROVAL_KEYS?: string
 RER_OWNER_CLAIM_ISSUER?: string
 RER_OWNER_CLAIM_INSTALLATION_ID?: string
 RER_OWNER_CLAIM_APP_ORIGIN?: string
 RER_OWNER_CLAIM_PUBLIC_KEYS?: string
 AUTH_AGENT_MODEL_WORKSPACE?: string
 AUTH_AGENT_MODEL_KEY?: string
 AUTH_NOTIFICATION_SLACK_WEBHOOK?: string
 AUTH_ENCRYPTION_KEY: string
 SESSION_SECRET: string
 SETUP_TOKEN?: string
 MAIL_PROVIDER?: 'development' | 'rer' | 'resend' | 'sendgrid' | 'cloudflare'
 MAIL_SENDGRID_WEBHOOK_KEY?: string
 MAIL_FROM?: string
 MAIL_RELAY_URL?: string
 MAIL_API_KEY?: string
 MAIL_ACCOUNT_ID?: string
}
export const runtimeBindings = (env: Bindings): Bindings => env.RER_DEV_ORIGIN && env.AUTH_LOCAL === 'true' ? { ...env, AUTH_ORIGIN: env.RER_DEV_ORIGIN } : env
export const authConfig = (env: Bindings): AuthConfig => ({ origin: env.AUTH_ORIGIN, local: env.AUTH_LOCAL === 'true', OWNER_EMAIL: env.OWNER_EMAIL, SESSION_SECRET: env.SESSION_SECRET, SETUP_TOKEN: env.SETUP_TOKEN, MAIL_FROM: env.MAIL_FROM, branding: { productName: branding.name, accentColor: branding.primaryColor, signInPath: '/signin', theme: theme.href } })
export function operatorAuth(env: Bindings) {
 return createOperatorAuth({ db: env.DB, config: authConfig(env), mailSender: operatorMail(env), clientIp: request => request.headers.get('CF-Connecting-IP') ?? '' })
}
export function identityAuth(original: Bindings, allowDevSession?: AuthRuntimeOptions['allowDevSession'], waitUntil?: (work: Promise<unknown>) => void) {
 const env = runtimeBindings(original)
 return createAuthRuntime({ mailProvider: env.MAIL_PROVIDER, mailEventInstallationId: env.RER_INSTALLATION_ID, sendgridWebhookKey: env.MAIL_SENDGRID_WEBHOOK_KEY, notificationSlackWebhook: env.AUTH_NOTIFICATION_SLACK_WEBHOOK, agentModelKey: env.AUTH_AGENT_MODEL_KEY, agentModelWorkspace: env.AUTH_AGENT_MODEL_WORKSPACE, organizationId: env.AUTH_ORGANIZATION_ID, db: env.DB, origin: env.AUTH_ORIGIN, secret: env.AUTH_ENCRYPTION_KEY, local: env.AUTH_LOCAL === 'true', allowDevSession, waitUntil, rerTrustKeys: env.RER_LINK_APPROVAL_KEYS, upstreamProviders: env.AUTH_UPSTREAM_PROVIDERS ? JSON.parse(env.AUTH_UPSTREAM_PROVIDERS) : undefined, mail: async (message, store) => {
  const sender = operatorMail({ ...env, DB: store?.db ?? env.DB })
  if (!sender || !env.MAIL_FROM) throw new Error('Auth mail is not configured')
  return sender.send({ ...message, deliveryId: message.deliveryId, from: env.MAIL_FROM, to: [message.to], headers: {} })
 } })
}
const privateHeaders = { 'cache-control': 'no-store', 'referrer-policy': 'strict-origin', 'x-content-type-options': 'nosniff', 'x-robots-tag': 'noindex, nofollow' }
const redirect = (location: string) => new Response(null, { status: 303, headers: { ...privateHeaders, location } })
const html = (body: string, method: string, authorizationOrigins: string[] = []) => new Response(method === 'HEAD' ? null : body, { headers: { ...privateHeaders, 'content-type': 'text/html; charset=utf-8', 'content-security-policy': `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self' ${authorizationOrigins.map(origin => new URL(origin).origin).join(' ')}; base-uri 'none'; frame-ancestors 'none'` } })
const pages = new Set<AuthPage>(['people', 'move-in', 'agents', 'apps', 'methods', 'activity', 'account', 'organizations', 'roles', 'permissions', 'erasure'])

export async function authResponse(request: Request, original: Bindings, execution: ExecutionContext, allowDevSession?: AuthRuntimeOptions['allowDevSession']): Promise<Response | null> {
 const selected = organizationRequest(request)
 if (selected.id !== 'root') {
  if (new URL(request.url).origin !== runtimeBindings(original).AUTH_ORIGIN) return new Response(null, { status: 403, headers: privateHeaders })
  if (!await organizationDatabase(original.DB, selected.id)) return devNotFound()
  if (['/auth/bootstrap', '/auth/session', '/auth/signout'].includes(new URL(selected.request.url).pathname)) return devNotFound()
  const response = await authResponse(selected.request, { ...original, AUTH_ORGANIZATION_ID: selected.id }, execution, allowDevSession)
  return response ? organizationResponse({ basePath: selected.basePath }, response) : devNotFound()
 }
 const env = runtimeBindings(original), url = new URL(request.url), path = url.pathname
 if (path === '/__dev/outbox' || path === '/__dev/key') {
  const gate = env.MAIL_PROVIDER === 'development' ? devGate({ key: env.RER_DEV_KEY, origin: env.AUTH_ORIGIN, local: env.AUTH_LOCAL === 'true' }) : null
  if (!gate) return devNotFound()
  if (path === '/__dev/key') return await gate.exchange(request) ?? devNotFound()
  if (!await gate.admits(request)) return devNotFound()
  const selectedDb = env.AUTH_ORGANIZATION_ID ? (await organizationDatabase(env.DB, env.AUTH_ORGANIZATION_ID))?.db : env.DB
  if (!selectedDb) return devNotFound()
  const response = await createDevelopmentOutboxHandler({ local: true, origin: env.AUTH_ORIGIN, outbox: createD1DevelopmentOutbox({ db: selectedDb }) })(request)
  if (!response) return devNotFound()
  if (request.method !== 'GET' || !response.headers.get('content-type')?.includes('text/html')) return response
  const body = await response.text()
  return new Response(body.replace('<body>', '<body><p><a href="/signin?returnTo=%2Fsetup">Request an Auth sign-in link in this browser</a></p>'), { status: response.status, headers: response.headers })
 }
 // Base claims the owner, but never authorizes Auth administration or enrollment.
 if (['/auth/bootstrap', '/auth/session', '/auth/signout'].includes(path)) return fontDocumentResponse(await createAuthHandler(operatorAuth(env))(request))
 const ownsIdentity = path.startsWith('/auth/') || path.startsWith('/oidc/') || path.startsWith('/saml/') || path.startsWith('/api/auth/') || ['/.well-known/openid-configuration', '/.well-known/rer-provider', '/.well-known/rer-dependencies'].includes(path)
 const ownsPage = path === '/' || path === '/signin' || path === '/setup' || path === '/app' || path.startsWith('/app/')
 if (!ownsIdentity && !ownsPage) return null
 if (url.origin !== env.AUTH_ORIGIN || (request.headers.has('host') && request.headers.get('host')?.toLowerCase() !== url.host.toLowerCase())) return new Response(null, { status: 403, headers: privateHeaders })
 const auth = identityAuth(env, allowDevSession, work => execution.waitUntil(work))
 if (ownsIdentity) return await auth.fetch(request) ?? devNotFound()
 if (!['GET', 'HEAD'].includes(request.method) && path !== '/setup') return new Response(null, { status: 405, headers: { ...privateHeaders, allow: 'GET, HEAD' } })
 if (path === '/signin') {
  const providers = (await auth.upstreamProviders()).filter(provider => provider.visible)
  return html(renderSignInPage({ issuer: env.AUTH_ORIGIN, returnTo: url.searchParams.get('returnTo') ?? '/setup', providers, notice: url.searchParams.get('reproof') === '1' ? 'A recent email confirmation is required. Check your email and open its link in this browser.' : undefined }), request.method, providers.flatMap(provider => provider.authorizationOrigins))
 }
 const page = path === '/app' || path === '/' || path === '/setup' ? 'account' : path.slice('/app/'.length) as AuthPage
 if (!pages.has(page)) return devNotFound()
 const model = await auth.model(request, page)
 if (page === 'methods' && model.user) model.providers = (await auth.upstreamProviders()).filter(provider => provider.visible)
 if (!env.AUTH_ORGANIZATION_ID && !model.user && path === '/setup' && request.method === 'POST') return firstRunResponse(request, env, { getSession: async () => null }, { theme })
 if (!model.user) return redirect(`/signin?returnTo=${encodeURIComponent(path === '/' ? '/setup' : path + url.search)}`)
 // The shared first-run form consumes Auth's real person, never a Base session.
 // It deliberately permits first email enrollment: administrative actions still
 // require a passkey independently in every Auth API handler.
 const accounts = { getSession: async () => ({ operator: { id: model.user.id, role: model.user.role, displayName: model.user.name, email: model.user.email } }) }
 const setup = env.AUTH_ORGANIZATION_ID ? null : await firstRunResponse(request, env, accounts, { theme })
 if (setup) return setup
 if (path === '/') return redirect('/app/account')
 if (['people', 'move-in', 'agents', 'apps', 'activity', 'permissions', 'erasure'].includes(page) && !model.isAdmin && !(page === 'activity' && model.canReadAudit)) return new Response(renderAuthPage({ ...model, page: 'account', notice: 'Sign in with your passkey to administer Auth.' }), { status: 403, headers: html('', 'GET').headers })
 return html(renderAuthPage(model), request.method)
}
