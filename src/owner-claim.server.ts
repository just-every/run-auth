import { createOwnerClaimHandler, OwnerClaimError } from './modules/owner-claim/index.mjs'
import { runtimeBindings, type Bindings } from './auth.server'
import branding from './branding.json'

/** RER Managed: the signed first-owner claim (Spool's MANAGED-ADMISSION model). Absent configuration answers 404. */
export async function ownerClaimResponse(request: Request, original: Bindings): Promise<Response | null> {
 if (new URL(request.url).pathname !== '/auth/owner-claim') return null
 const env = runtimeBindings(original)
 if (!env.RER_OWNER_CLAIM_ISSUER || !env.RER_OWNER_CLAIM_PUBLIC_KEYS) return new Response(null, { status: 404, headers: { 'cache-control': 'no-store' } })
 try {
  const response = await createOwnerClaimHandler({
   db: env.DB,
   authConfig: { origin: env.AUTH_ORIGIN, local: env.AUTH_LOCAL === 'true', OWNER_EMAIL: env.OWNER_EMAIL, SESSION_SECRET: env.SESSION_SECRET, SETUP_TOKEN: env.SETUP_TOKEN,
    branding: { productName: branding.name, accentColor: branding.primaryColor, signInPath: '/signin' } },
   clientIp: request => request.headers.get('CF-Connecting-IP') ?? '',
   issuer: env.RER_OWNER_CLAIM_ISSUER, installationId: env.RER_OWNER_CLAIM_INSTALLATION_ID!, appOrigin: env.RER_OWNER_CLAIM_APP_ORIGIN!,
   expectedEmail: env.OWNER_EMAIL, publicKeys: JSON.parse(env.RER_OWNER_CLAIM_PUBLIC_KEYS),
  })(request)
  return response
 } catch (error) {
  return Response.json({ error: error instanceof OwnerClaimError ? error.code : 'claim_unavailable' }, { status: error instanceof OwnerClaimError ? error.status : 503, headers: { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } })
 }
}
