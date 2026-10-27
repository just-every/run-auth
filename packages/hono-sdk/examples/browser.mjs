import {Hono} from 'hono';
import {getCookie, setCookie, deleteCookie} from 'hono/cookie';
import {createSessionClient, requirePermission} from '@runeditrun/auth-hono';

const escape = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const random = () => crypto.randomUUID();

/** Single-process, server-only quickstart. Restart deliberately requires sign-in. */
export function createBrowserApp({origin, organizations, sessionLifetimeMs = 3600000, maxSessions = 1000}) {
  const base = new URL(origin);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if (base.origin !== origin || (base.protocol !== 'https:' && !(local && base.protocol === 'http:'))) throw new TypeError('invalid_app_origin');
  if (!Array.isArray(organizations) || !organizations.length || !Number.isSafeInteger(sessionLifetimeMs) || sessionLifetimeMs <= 0 || !Number.isSafeInteger(maxSessions) || maxSessions <= 0) throw new TypeError('invalid_session_configuration');
  const configured = new Map();
  for (const value of organizations) {
    const issuer = new URL(value.issuer);
    if (!/^[a-zA-Z0-9_-]{1,60}$/.test(value.id) || configured.has(value.id) || !value.name ||
        !value.clientId || !value.apiId || !value.resource || issuer.search || issuer.hash || issuer.username || issuer.password ||
        (issuer.protocol !== 'https:' && !(issuer.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(issuer.hostname)))) throw new TypeError('invalid_organization_configuration');
    configured.set(value.id, Object.freeze({...value, redirectUri: `${origin}/callback/${value.id}`}));
  }
  const authOrigins = [...new Set([...configured.values()].map(org => new URL(org.issuer).origin))].join(' ');
  const sessions = new Map();
  const cookie = base.protocol === 'https:' ? '__Host-auth_quickstart' : 'auth_quickstart';
  const app = new Hono();
  const permission = org => ({apiId: org.apiId, action: 'read', resource: 'document:budget'});
  const close = session => {
    session.ended = true;
    // In-flight work retains no browser authority after this session is removed.
    for (const slot of session.memberships.values()) {
      try { slot.client.restore(null); } catch (error) { if (error.code !== 'session_busy') throw error; }
    }
    session.memberships.clear();
    session.pending.clear();
  };
  const alive = session => !session.ended && session.expires > Date.now() && sessions.get(session.id) === session;
  const resolve = context => {
    const session = sessions.get(getCookie(context, cookie));
    if (!session) return null;
    if (!alive(session)) { close(session); sessions.delete(session.id); return null; }
    return session;
  };
  const writeCookie = (context, session) => setCookie(context, cookie, session.id, {
    httpOnly: true, secure: base.protocol === 'https:', sameSite: 'Lax', path: '/', maxAge: Math.floor(sessionLifetimeMs / 1000),
  });
  const page = (context, title, content, status = 200) => context.html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="color-scheme" content="light dark"><title>${escape(title)}</title></head><body><main><h1>${escape(title)}</h1>${content}</main></body></html>`, status);
  app.use('*', async (context, next) => {
    context.header('Cache-Control', 'no-store');
    context.header('Referrer-Policy', 'same-origin');
    context.header('Content-Security-Policy', `default-src 'none'; form-action 'self' ${authOrigins}; frame-ancestors 'none'; base-uri 'none'`);
    // Use a configured public origin, never a forwarded header or a caller's host.
    if (new URL(context.req.url).origin !== origin) return context.json({error: 'invalid_app_origin'}, 400);
    await next();
  });
  app.onError((error, context) => context.json({error: /^[a-z_]{1,80}$/.test(error?.code || '') ? error.code : 'authorization_unavailable'}, 503));
  app.get('/', context => {
    let session = resolve(context);
    if (!session) {
      for (const [id, old] of sessions) if (!alive(old)) { close(old); sessions.delete(id); }
      if (sessions.size >= maxSessions) return context.json({error: 'session_capacity'}, 503);
      session = {id: random(), csrf: random(), expires: Date.now() + sessionLifetimeMs, memberships: new Map(), pending: new Map(), active: null, ended: false};
      sessions.set(session.id, session); writeCookie(context, session);
    }
    const form = (action, label, org) => `<form method="post" action="${action}"><input type="hidden" name="csrf" value="${escape(session.csrf)}">${org ? `<input type="hidden" name="organization" value="${escape(org.id)}">` : ''}<button>${escape(label)}</button></form>`;
    const selected = configured.get(session.active);
    return page(context, 'Documents quickstart', `<p>Active employer: <strong>${escape(selected?.name || 'None')}</strong></p>${[...configured.values()].map(org => `<section><h2>${escape(org.name)}</h2>${form('/login', 'Sign in to ' + org.name, org)}${form('/switch', 'Switch to ' + org.name, org)}</section>`).join('')}${selected ? `<p><a href="/documents/budget">Read budget</a></p>${form('/rotate', 'Rotate session')}${form('/logout', 'Sign out of application and Auth')}` : ''}`);
  });
  app.post('*', async (context, next) => {
    const session = resolve(context);
    if (!session) return context.json({error: 'sign_in_required'}, 401);
    if (context.req.header('origin') !== origin) return context.json({error: 'invalid_origin'}, 403);
    const data = await context.req.parseBody();
    if (data.csrf !== session.csrf) return context.json({error: 'invalid_csrf'}, 403);
    context.set('browserSession', session); context.set('form', data);
    await next();
  });
  app.post('/login', async context => {
    const session = context.get('browserSession'), org = configured.get(context.get('form').organization);
    if (!org) return context.json({error: 'organization_unavailable'}, 404);
    const client = await createSessionClient(org);
    const {url} = await client.authorization({resource: org.resource, scopes: ['read'], deviceName: 'Hono documents server'});
    if (!alive(session)) return context.json({error: 'session_required'}, 401);
    session.pending.set(org.id, {client, expires: Date.now() + 600000});
    return context.redirect(url, 303);
  });
  app.get('/callback/:organization', async context => {
    const session = resolve(context), org = configured.get(context.req.param('organization'));
    const transaction = org && session?.pending.get(org.id);
    if (!transaction || transaction.expires <= Date.now()) return context.json({error: 'invalid_state'}, 400);
    // The first arriving callback owns rotation until its response is prepared.
    // A concurrent callback leaves its transaction pending and sets no cookie.
    if (session.callbackInFlight) return context.json({error: 'callback_in_progress'}, 409);
    session.callbackInFlight = true;
    session.pending.delete(org.id);
    try {
      await transaction.client.complete(context.req.url);
      const result = await transaction.client.resourceRequest('/api/auth/resource-apis/check', permission(org));
      if (result.allowed !== true || !result.principal?.id) throw new Error('membership_required');
      if (!alive(session)) { transaction.client.restore(null); return context.json({error: 'session_required'}, 401); }
      session.memberships.get(org.id)?.client.restore(null);
      session.memberships.set(org.id, {client: transaction.client}); session.active = org.id;
      // Rotate the opaque cookie after authentication; old application cookies stop working.
      sessions.delete(session.id); session.id = random(); sessions.set(session.id, session); writeCookie(context, session);
      return context.redirect('/', 303);
    } catch (error) {
      transaction.client.restore(null);
      return context.json({error: /^[a-z_]{1,80}$/.test(error?.code || '') ? error.code : 'membership_required'}, 400);
    } finally {
      session.callbackInFlight = false;
    }
  });
  app.post('/switch', async context => {
    const session = context.get('browserSession'), id = context.get('form').organization, org = configured.get(id);
    const slot = session.memberships.get(id);
    if (!org || !slot) return context.json({error: 'organization_membership_required'}, 403);
    const result = await slot.client.resourceRequest('/api/auth/resource-apis/check', permission(org));
    if (!alive(session) || result.allowed !== true || !result.principal?.id) return context.json({error: 'access_denied'}, 403);
    session.active = id;
    return context.redirect('/', 303);
  });
  app.post('/rotate', async context => {
    const session = context.get('browserSession'), slot = session.memberships.get(session.active);
    if (!slot) return context.json({error: 'sign_in_required'}, 401);
    await slot.client.refresh();
    if (!alive(session)) { slot.client.restore(null); return context.json({error: 'session_required'}, 401); }
    return context.redirect('/', 303);
  });
  app.post('/logout', context => {
    const session = context.get('browserSession'), org = configured.get(session.active);
    sessions.delete(session.id); close(session); deleteCookie(context, cookie, {path: '/'});
    // Auth owns confirmation and the employer-specific source-session ending.
    return context.redirect(org ? `${org.issuer}/oidc/logout?client_id=${encodeURIComponent(org.clientId)}` : '/', 303);
  });
  app.get('/documents/budget', async (context, next) => {
    const session = resolve(context), org = configured.get(session?.active);
    if (!org) return context.json({error: 'sign_in_required'}, 401);
    context.set('authOrganization', org.id);
    return requirePermission({session: () => session.memberships.get(org.id)?.client, ...permission(org)})(context, async () => {
      if (!alive(session) || session.active !== org.id) { context.res = context.json({error: 'sign_in_required'}, 401); return; }
      await next();
    });
  }, context => context.json({document: 'Budget', organization: context.get('authOrganization'), subject: context.get('authPrincipal').id}));
  return app;
}
