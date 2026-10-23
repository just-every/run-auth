export {createSessionClient} from '@runeditrun/auth-sdk';

/** Resolve only a server-held session; authorize the resource on every request. */
export function requirePermission({session, apiId, action, resource}) {
  if (typeof session !== 'function' || [apiId, action, resource].some(value => typeof value !== 'string' || !value)) {
    throw new TypeError('session_and_exact_permission_required');
  }
  return async (context, next) => {
    context.header('Cache-Control', 'no-store');
    let result;
    try {
      const client = await session(context);
      if (!client) return context.json({error: 'sign_in_required'}, 401);
      result = await client.resourceRequest('/api/auth/resource-apis/check', {apiId, action, resource});
    } catch (error) {
      if (error?.code === 'session_required' || error?.status === 401) return context.json({error: 'sign_in_required'}, 401);
      if (error?.code === 'access_denied' || error?.status === 403) return context.json({error: 'access_denied'}, 403);
      return context.json({error: 'authorization_unavailable'}, 503);
    }
    if (result?.allowed !== true || typeof result.principal?.id !== 'string' || !result.principal.id) {
      return context.json({error: 'access_denied'}, 403);
    }
    context.set('authPrincipal', Object.freeze({...result.principal}));
    await next();
  };
}
