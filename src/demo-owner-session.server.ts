import { identityAuth, operatorAuth, type Bindings } from './auth.server'
import { createSession } from './auth/core.mjs'

/** The hosted demo only (RER_DEMO=1, set by rer's demo front): its signed owner claim also opens the
 * owner's Auth session, so a visitor lands in the app signed in. On a real installation the claim opens
 * only the operator session and Auth sign-in stays email proof and passkeys. */
export async function demoOwnerSession(request: Request, claimed: Response, env: Bindings): Promise<Response> {
 if (env.RER_DEMO !== '1' || claimed.status !== 303) return claimed
 const cookie = claimed.headers.getSetCookie().map(value => value.split(';')[0]).join('; ')
 const operator = await operatorAuth(env).getSession(new Request(request.url, { headers: { cookie } }))
 if (operator?.operator.role !== 'owner') throw new Error('demo-owner-session-missing')
 const auth = identityAuth(env), id = operator.operator.id
 // The claim, signed by the demo's issuer for OWNER_EMAIL, is this person's email proof.
 await env.DB.prepare("INSERT INTO auth_emails(person_id,verified_at,proof_kind) VALUES(?,?,'work') ON CONFLICT(person_id) DO UPDATE SET verified_at=excluded.verified_at,proof_kind='work'").bind(id, auth.context.now()).run()
 // A demo copy has no installation for its owner to review: first run is complete.
 await env.DB.prepare('INSERT INTO oa_first_run (singleton, completed_by, completed_at) VALUES (1, ?, ?) ON CONFLICT(singleton) DO NOTHING').bind(id, auth.context.now()).run()
 const headers = new Headers(claimed.headers)
 headers.append('set-cookie', (await createSession(auth.context, id, ['email'])).header)
 return new Response(claimed.body, { status: claimed.status, headers })
}
