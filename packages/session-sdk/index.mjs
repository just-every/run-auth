import { SignJWT, base64url, calculateJwkThumbprint, exportJWK } from 'jose';

const encoder = new TextEncoder();

function failure(code, status) {
  const error = new Error(code);
  error.name = 'SessionError';
  error.code = code;
  if (status !== undefined) error.status = status;
  return error;
}

function requiredString(value, name) {
  if (typeof value !== 'string' || !value.trim()) throw failure(`invalid_${name}`);
  return value;
}

function callbackBase(url) {
  const base = new URL(url);
  base.search = '';
  base.hash = '';
  return base.href;
}

function copyTokens(value) {
  if (!value || typeof value !== 'object' || value.token_type !== 'DPoP' ||
      !Number.isSafeInteger(value.expires_in) || value.expires_in <= 0 ||
      typeof value.scope !== 'string') throw failure('invalid_token_response');
  return Object.freeze({
    access_token: requiredString(value.access_token, 'access_token'),
    refresh_token: requiredString(value.refresh_token, 'refresh_token'),
    token_type: 'DPoP',
    expires_in: value.expires_in,
    scope: value.scope,
    grant_id: requiredString(value.grant_id, 'grant_id'),
  });
}

/** Public OAuth client. The host owns durable token and DPoP-key storage. */
export async function createSessionClient({
  issuer, clientId, redirectUri, fetch: send = globalThis.fetch, keyPair, storage,
}) {
  requiredString(issuer, 'issuer');
  requiredString(clientId, 'client_id');
  requiredString(redirectUri, 'redirect_uri');
  const issuerURL = new URL(issuer);
  const redirectURL = new URL(redirectUri);
  if (!['https:', 'http:'].includes(issuerURL.protocol) || issuerURL.username ||
      issuerURL.password || issuerURL.search || issuerURL.hash) throw failure('invalid_issuer');
  if (redirectURL.username || redirectURL.password || redirectURL.hash) throw failure('invalid_redirect_uri');
  if (typeof send !== 'function') throw failure('fetch_required');
  if (storage && (typeof storage.save !== 'function' || typeof storage.clear !== 'function')) {
    throw failure('invalid_storage');
  }
  const webcrypto = globalThis.crypto;
  if (!webcrypto?.subtle || !webcrypto.getRandomValues) throw failure('webcrypto_required');
  const pair = keyPair ?? await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'],
  );
  if (pair.privateKey?.type !== 'private' || pair.publicKey?.type !== 'public' ||
      [pair.privateKey, pair.publicKey].some(key =>
        key.algorithm?.name !== 'ECDSA' || key.algorithm?.namedCurve !== 'P-256')) {
    throw failure('invalid_key_pair');
  }
  const exported = await exportJWK(pair.publicKey);
  const publicJwk = { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y };
  const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');
  // Fail early if supplied public and private keys do not belong together.
  const keyCheck = webcrypto.getRandomValues(new Uint8Array(32));
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, keyCheck);
  if (!await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, signature, keyCheck)) {
    throw failure('invalid_key_pair');
  }

  const base = issuer.replace(/\/$/, '');
  const tokenEndpoint = `${base}/oidc/token`;
  const checkPath = '/api/auth/resource-apis/check';
  const random = () => base64url.encode(webcrypto.getRandomValues(new Uint8Array(32)));
  const digest = async value => base64url.encode(new Uint8Array(await webcrypto.subtle.digest('SHA-256', encoder.encode(value))));
  let tokens = null;
  let pending = null;
  let completing = false;
  let refreshInFlight = null;

  async function proof(endpoint, accessToken, nonce) {
    const url = new URL(endpoint);
    url.search = '';
    url.hash = '';
    const claims = { htm: 'POST', htu: url.href, iat: Math.floor(Date.now() / 1000), jti: random() };
    if (accessToken) claims.ath = await digest(accessToken);
    if (nonce) claims.nonce = nonce;
    return new SignJWT(claims)
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
      .sign(pair.privateKey);
  }

  async function request(endpoint, body, accessToken) {
    let nonce;
    for (let continuation = 0; continuation < 2; continuation++) {
      const headers = {
        'Content-Type': accessToken ? 'application/json' : 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        DPoP: await proof(endpoint, accessToken, nonce),
      };
      if (accessToken) headers.Authorization = `DPoP ${accessToken}`;
      const response = await send(endpoint, {
        method: 'POST', headers, body, redirect: 'error', credentials: 'omit', cache: 'no-store',
      });
      let result;
      try { result = await response.json(); }
      catch { throw failure('invalid_response', response.status); }
      if (!response.ok && result?.error === 'use_dpop_nonce' && continuation === 0) {
        nonce = response.headers.get('dpop-nonce');
        if (nonce) continue;
      }
      if (!response.ok || result?.error) {
        const code = typeof result?.error === 'string' && /^[a-zA-Z0-9_.-]{1,80}$/.test(result.error)
          ? result.error : 'request_failed';
        throw failure(code, response.status);
      }
      if (!result || typeof result !== 'object' || Array.isArray(result)) throw failure('invalid_response');
      return result;
    }
  }

  async function publish(value) {
    const next = copyTokens(value);
    await storage?.save({ ...next });
    tokens = next;
    return { ...next };
  }

  async function clearAfter(error) {
    tokens = null;
    try { await storage?.clear(); }
    catch { error.storageClearFailed = true; }
    throw error;
  }

  async function authorization({ resource, scopes = [], deviceName }) {
    requiredString(resource, 'resource');
    const audience = new URL(resource);
    if (audience.hash || audience.username || audience.password) throw failure('invalid_resource');
    requiredString(deviceName, 'device_name');
    const requested = typeof scopes === 'string' ? scopes.split(/\s+/).filter(Boolean) : scopes;
    if (!Array.isArray(requested) || requested.some(scope =>
      typeof scope !== 'string' || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
      throw failure('invalid_scopes');
    }
    const state = random();
    const verifier = random();
    const nonce = random();
    const challenge = await digest(verifier);
    const url = new URL(`${base}/oidc/authorize`);
    url.search = new URLSearchParams({
      response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
      scope: [...new Set(['openid', 'offline_access', ...requested])].join(' '),
      resource, device_name: deviceName, dpop_jkt: thumbprint,
      code_challenge: challenge, code_challenge_method: 'S256', state, nonce, prompt: 'consent',
    }).toString();
    pending = { state, verifier };
    return { url: url.href, state };
  }

  async function complete(callbackURL) {
    if (completing || refreshInFlight) throw failure('session_busy');
    const callback = new URL(callbackURL);
    if (callbackBase(callback) !== callbackBase(redirectURL)) throw failure('invalid_callback');
    const params = callback.searchParams;
    if (!pending || params.getAll('state').length !== 1 || params.get('state') !== pending.state) {
      throw failure('invalid_state');
    }
    const transaction = pending;
    pending = null;
    if (params.getAll('iss').length !== 1 || params.get('iss') !== issuer) throw failure('invalid_issuer');
    if (params.has('error')) throw failure('authorization_failed');
    if (params.getAll('code').length !== 1 || !params.get('code')) throw failure('invalid_code');
    completing = true;
    try {
      return await publish(await request(tokenEndpoint, new URLSearchParams({
        grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirectUri,
        code: params.get('code'), code_verifier: transaction.verifier,
      })));
    } catch (error) {
      return await clearAfter(error);
    } finally {
      completing = false;
    }
  }

  function refresh() {
    if (refreshInFlight) return refreshInFlight;
    if (completing) return Promise.reject(failure('session_busy'));
    refreshInFlight = (async () => {
      try {
        if (!tokens) throw failure('session_required');
        const previous = tokens.refresh_token;
        const next = await request(tokenEndpoint, new URLSearchParams({
          grant_type: 'refresh_token', client_id: clientId, refresh_token: previous,
        }));
        if (next.refresh_token === previous) throw failure('refresh_token_not_rotated');
        return await publish(next);
      } catch (error) {
        return await clearAfter(error);
      } finally {
        refreshInFlight = null;
      }
    })();
    return refreshInFlight;
  }

  async function resourceRequest(path, data) {
    if (path !== checkPath) throw failure('invalid_resource_path');
    if (!tokens) throw failure('session_required');
    const result = await request(`${base}${checkPath}`, JSON.stringify(data), tokens.access_token);
    if (result.allowed === false) throw failure('access_denied', 403);
    return result;
  }

  return {
    authorization, complete, refresh, resourceRequest,
    getTokens: () => tokens ? { ...tokens } : null,
    restore(value) {
      if (completing || refreshInFlight) throw failure('session_busy');
      tokens = value === null ? null : copyTokens(value);
      return tokens ? { ...tokens } : null;
    },
  };
}
