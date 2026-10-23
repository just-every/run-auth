"""Scoped machine administration. Credentials and response bodies are never logged."""
import json
import re
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, unquote
from urllib.request import Request, HTTPRedirectHandler, build_opener

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class AuthAdminError(Exception):
    def __init__(self, code, status=None, retry_after=None):
        super().__init__(code)
        self.code, self.status, self.retry_after = code, status, retry_after


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AdminClient:
    """One issuer and one least-privilege service registration per client."""
    def __init__(self, *, issuer, client_id, private_key, scopes, kid=None, algorithm="ES256"):
        try:
            url = urlsplit(issuer)
            valid = (url.hostname and not url.username and not url.password and not url.query and not url.fragment
                     and (url.scheme == "https" or url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))
                     and re.fullmatch(r"/(?:org/[a-f0-9]{32}/?)?", url.path or "/"))
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise AuthAdminError("invalid_issuer")
        if not isinstance(client_id, str) or not re.fullmatch(r"auth-admin-service:[A-Za-z0-9_-]+", client_id):
            raise AuthAdminError("invalid_client_id")
        if not isinstance(scopes, list) or not scopes or any(not isinstance(s, str) or not re.fullmatch(r"[a-z-]+\.(read|manage)", s) for s in scopes):
            raise AuthAdminError("invalid_scopes")
        if kid is not None and (not isinstance(kid, str) or not 1 <= len(kid) <= 128):
            raise AuthAdminError("invalid_kid")
        try:
            key = serialization.load_pem_private_key(private_key, password=None)
            if not (algorithm == "ES256" and isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)
                    or algorithm == "RS256" and isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048):
                raise ValueError()
        except (TypeError, ValueError):
            raise AuthAdminError("private_signing_key_required") from None
        self._base, self._id, self._key = issuer.rstrip("/"), client_id, key
        self._scope, self._kid, self._algorithm = " ".join(sorted(set(scopes))), kid, algorithm
        self._opener = build_opener(_NoRedirect())
        self._token, self._until = None, 0
        self._lock = threading.Lock()

    def _send(self, method, url, body=None, headers=None):
        try:
            request = Request(url, data=body, headers={"Accept": "application/json", **(headers or {})}, method=method)
            try:
                response = self._opener.open(request, timeout=15)
            except HTTPError as error:
                response = error
            with response:
                raw = response.read(1024 * 1024 + 1)
                status, received = response.code, response.headers
            if len(raw) > 1024 * 1024:
                raise AuthAdminError("invalid_response", status)
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeError):
                raise AuthAdminError("invalid_response", status) from None
            if not isinstance(data, dict):
                raise AuthAdminError("invalid_response", status)
            if not 200 <= status < 300 or data.get("error"):
                code = data.get("error")
                if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code):
                    code = "request_failed"
                retry = received.get("Retry-After", "")
                raise AuthAdminError(code, status, int(retry) if re.fullmatch(r"[0-9]{1,8}", retry) else None)
            return {"data": data, "status": status, "etag": received.get("ETag"),
                    "rate_limit_remaining": received.get("RateLimit-Remaining")}
        except AuthAdminError:
            raise
        except (OSError, URLError, ValueError):
            raise AuthAdminError("transport_failed") from None

    def _access_token(self):
        with self._lock:
            if self._token and self._until > time.monotonic():
                return self._token
            endpoint, now = self._base + "/oidc/token", int(time.time())
            assertion = jwt.encode({"iss": self._id, "sub": self._id, "aud": endpoint, "iat": now,
                                    "exp": now + 60, "jti": str(uuid.uuid4())}, self._key,
                                   algorithm=self._algorithm, headers={"kid": self._kid} if self._kid else None)
            sent_at = time.monotonic()
            result = self._send("POST", endpoint, urlencode({"grant_type": "client_credentials", "client_id": self._id,
                "scope": self._scope, "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion}).encode(), {"Content-Type": "application/x-www-form-urlencoded"})["data"]
            lifetime = result.get("expires_in")
            if (result.get("token_type") != "Bearer" or not isinstance(result.get("access_token"), str)
                    or not result["access_token"] or type(lifetime) is not int or not 1 <= lifetime <= 300
                    or not isinstance(result.get("scope"), str) or " ".join(sorted(result["scope"].split())) != self._scope):
                raise AuthAdminError("invalid_token_response")
            self._token, self._until = result["access_token"], sent_at + lifetime - 5
            return self._token

    def request(self, method, path, *, body=None, etag=None):
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise AuthAdminError("invalid_method")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or re.search(r"[\\#\x00-\x20]", path):
            raise AuthAdminError("invalid_path")
        segments = [unquote(part) for part in path.split("?", 1)[0][1:].split("/")]
        if (segments[0] not in ("people", "groups", "apps", "assignments", "policies", "idps", "domains", "logs", "openapi.json")
                or any(not part or part in (".", "..") or re.search(r"[/\\?#\x00-\x20]", part) for part in segments)):
            raise AuthAdminError("invalid_path")
        if body is not None and (method == "GET" or not isinstance(body, dict)):
            raise AuthAdminError("invalid_body")
        if etag is not None and (not isinstance(etag, str) or not re.fullmatch(r'"[A-Za-z0-9_-]+"', etag)):
            raise AuthAdminError("invalid_etag")
        try:
            encoded = json.dumps(body, allow_nan=False).encode() if body is not None else None
        except (TypeError, ValueError):
            raise AuthAdminError("invalid_body") from None
        try:
            return self._send(method, self._base + "/api/auth/admin/v1" + path, encoded,
                {"Authorization": "Bearer " + self._access_token(),
                 **({"Content-Type": "application/json"} if encoded is not None else {}), **({"If-Match": etag} if etag else {})})
        except AuthAdminError as error:
            if error.status == 401:
                with self._lock:
                    self._token, self._until = None, 0
            raise

    def pages(self, path, *, limit=100):
        if path not in ("/people", "/groups", "/apps", "/assignments", "/policies", "/idps", "/domains", "/logs") or type(limit) is not int or not 1 <= limit <= 100:
            raise AuthAdminError("invalid_pagination")
        offset = 0
        while True:
            result = self.request("GET", path + "?" + urlencode({"limit": limit, "offset": offset}))
            data = result["data"]
            next_offset = data.get("nextOffset")
            if (not isinstance(data.get("items"), list) or type(data.get("total")) is not int or data["total"] < 0
                    or "nextOffset" not in data or next_offset is not None and (type(next_offset) is not int or next_offset <= offset)):
                raise AuthAdminError("invalid_pagination_response")
            yield result
            if next_offset is None:
                return
            offset = next_offset
