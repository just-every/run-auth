import {SignJWT} from 'jose';

export class AuthAdminError extends Error {
  constructor(code, status, retryAfter) {
    super(code);
    this.name = 'AuthAdminError';
    this.code = code;
    if (status !== undefined) this.status = status;
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
  }
}
const fail = code => { throw new AuthAdminError(code); };
const ADMIN = '/api/auth/admin/v1';

/** Server-only v1 client. No credential, token or response body is logged. */
export function createAdminClient({issuer, clientId, privateKey, kid, algorithm = 'ES256', scopes, fetch: send = globalThis.fetch}) {
  const url = new URL(issuer);
  if (url.username || url.password || url.search || url.hash ||
      url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) ||
      !/^\/(?:org\/[a-f0-9]{32}\/?)?$/.test(url.pathname)) fail('invalid_issuer');
  const base = url.href.replace(/\/$/, '');
  if (typeof clientId !== 'string' || !/^auth-admin-service:[A-Za-z0-9_-]+$/.test(clientId)) fail('invalid_client_id');
  if (privateKey?.type !== 'private' || !['ES256', 'RS256'].includes(algorithm)) fail('private_signing_key_required');
  if (kid !== undefined && (typeof kid !== 'string' || !kid || kid.length > 128)) fail('invalid_kid');
  if (!Array.isArray(scopes) || !scopes.length || scopes.some(s => typeof s !== 'string' || !/^[a-z-]+\.(read|manage)$/.test(s))) fail('invalid_scopes');
  if (typeof send !== 'function') fail('fetch_required');
  const scope = [...new Set(scopes)].sort().join(' '), tokenURL = base + '/oidc/token';
  let token = null, pending = null;

  async function decode(response) {
    // Keep provider descriptions, raw bodies and credential values out of errors.
    let body;
    try {
      const reader = response.body?.getReader();
      if (!reader) throw new Error();
      let size = 0;
      const chunks = [];
      try {
        for (;;) {
          const {value, done} = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 1024 * 1024) throw new Error();
          chunks.push(value);
        }
      } catch (error) { await reader.cancel(); throw error; }
      const buffer = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.length; }
      body = JSON.parse(new TextDecoder().decode(buffer));
    } catch { throw new AuthAdminError('invalid_response', response.status); }
    if (!response.ok || body?.error) {
      const code = typeof body?.error === 'string' && /^[a-z][a-z0-9_]{0,79}$/.test(body.error) ? body.error : 'request_failed';
      const retry = response.headers.get('retry-after');
      throw new AuthAdminError(code, response.status, /^\d{1,8}$/.test(retry ?? '') ? Number(retry) : undefined);
    }
    if (!body || typeof body !== 'object') throw new AuthAdminError('invalid_response', response.status);
    return body;
  }

  async function exchange() {
    if (token && token.until > Date.now()) return token.value;
    if (!pending) pending = (async () => {
      const seconds = Math.floor(Date.now() / 1000);
      let assertion;
      try {
        assertion = await new SignJWT({}).setProtectedHeader({alg: algorithm, ...(kid ? {kid} : {})})
          .setIssuer(clientId).setSubject(clientId).setAudience(tokenURL).setIssuedAt(seconds)
          .setExpirationTime(seconds + 60).setJti(crypto.randomUUID()).sign(privateKey);
      } catch { fail('private_signing_key_required'); }
      const sentAt = Date.now();
      const result = await decode(await send(tokenURL, {method: 'POST', redirect: 'error', credentials: 'omit', cache: 'no-store',
        headers: {'content-type': 'application/x-www-form-urlencoded', accept: 'application/json'},
        body: new URLSearchParams({grant_type: 'client_credentials', client_id: clientId, scope,
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion}).toString()}));
      if (result.token_type !== 'Bearer' || typeof result.access_token !== 'string' || !result.access_token ||
          !Number.isSafeInteger(result.expires_in) || result.expires_in < 1 || result.expires_in > 300 ||
          result.scope?.split(' ').sort().join(' ') !== scope) fail('invalid_token_response');
      token = {value: result.access_token, until: sentAt + result.expires_in * 1000 - 5000};
      return token.value;
    })().finally(() => { pending = null; });
    return pending;
  }

  async function request(method, path, {body, etag} = {}) {
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) fail('invalid_method');
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\#\x00-\x20]/.test(path)) fail('invalid_path');
    const [pathname] = path.split('?');
    let segments;
    try { segments = pathname.slice(1).split('/').map(decodeURIComponent); } catch { fail('invalid_path'); }
    if (!['people', 'groups', 'apps', 'assignments', 'policies', 'idps', 'domains', 'logs', 'openapi.json'].includes(segments[0]) ||
        segments.some(s => !s || s === '.' || s === '..' || /[\/\\?#\x00-\x20]/.test(s))) fail('invalid_path');
    if (method === 'GET' && body !== undefined || body !== undefined && (!body || typeof body !== 'object' || Array.isArray(body))) fail('invalid_body');
    if (etag !== undefined && (typeof etag !== 'string' || !/^"[A-Za-z0-9_-]+"$/.test(etag))) fail('invalid_etag');
    const target = new URL(base + ADMIN + path);
    if (target.origin !== url.origin || !target.pathname.startsWith(url.pathname.replace(/\/$/, '') + ADMIN + '/')) fail('invalid_path');
    try {
      const response = await send(target, {method, redirect: 'error', credentials: 'omit', cache: 'no-store',
        headers: {authorization: 'Bearer ' + await exchange(), accept: 'application/json',
          ...(body !== undefined ? {'content-type': 'application/json'} : {}), ...(etag ? {'if-match': etag} : {})},
        ...(body !== undefined ? {body: JSON.stringify(body)} : {})});
      const data = await decode(response);
      return {data, status: response.status, etag: response.headers.get('etag'),
        rateLimitRemaining: response.headers.get('ratelimit-remaining')};
    } catch (error) {
      if (error.status === 401) token = null;
      if (error instanceof AuthAdminError) throw error;
      throw new AuthAdminError('transport_failed');
    }
  }

  async function* pages(path, {limit = 100} = {}) {
    if (!['/people', '/groups', '/apps', '/assignments', '/policies', '/idps', '/domains', '/logs'].includes(path) ||
        !Number.isInteger(limit) || limit < 1 || limit > 100) fail('invalid_pagination');
    let offset = 0;
    for (;;) {
      const result = await request('GET', path + '?' + new URLSearchParams({limit, offset}));
      const {items, total, nextOffset} = result.data;
      if (!Array.isArray(items) || !Number.isSafeInteger(total) || total < 0 ||
          nextOffset !== null && (!Number.isSafeInteger(nextOffset) || nextOffset <= offset)) fail('invalid_pagination_response');
      yield result;
      if (nextOffset === null) return;
      offset = nextOffset;
    }
  }
  return Object.freeze({request, pages});
}
