package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type client struct {
	mu                    sync.Mutex
	issuer, clientID, kid string
	key                   crypto.PrivateKey
	http                  *http.Client
	token                 string
	until                 time.Time
	// Advance only tags produced by this process's own successful writes.
	tags map[string]string
}
type apiError struct {
	status int
	code   string
}

func (e *apiError) Error() string {
	if e.status == 412 {
		return "Auth refused stale ETag (412); review a fresh plan before applying again"
	}
	return fmt.Sprintf("Auth refused request (%d): %s", e.status, e.code)
}
func newClient(issuer, id string) (*client, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) {
		return nil, fmt.Errorf("issuer must be an HTTPS origin; HTTP is allowed only on loopback")
	}
	if id == "" {
		return nil, fmt.Errorf("set client_id or AUTH_CLIENT_ID")
	}
	data, err := os.ReadFile(os.Getenv("AUTH_PRIVATE_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("cannot read AUTH_PRIVATE_KEY_FILE")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key must be PKCS8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key must be PKCS8 PEM")
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ES256 requires P-256")
		}
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key must have at least 2048 bits")
		}
	default:
		return nil, fmt.Errorf("use an RSA or P-256 key")
	}
	return &client{issuer: strings.TrimSuffix(issuer, "/"), clientID: id, kid: os.Getenv("AUTH_KEY_ID"), key: key, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, tags: map[string]string{}}, nil
}
func encoded(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
func (c *client) assertion() (string, error) {
	now := time.Now().Unix()
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("cannot create assertion nonce")
	}
	alg := "ES256"
	if _, ok := c.key.(*rsa.PrivateKey); ok {
		alg = "RS256"
	}
	header := map[string]string{"alg": alg, "typ": "JWT"}
	if c.kid != "" {
		header["kid"] = c.kid
	}
	input := encoded(header) + "." + encoded(map[string]any{"iss": c.clientID, "sub": c.clientID, "aud": c.issuer + "/oidc/token", "iat": now, "exp": now + 60, "jti": base64.RawURLEncoding.EncodeToString(nonce)})
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	switch k := c.key.(type) {
	case *rsa.PrivateKey:
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("cannot sign assertion")
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
		if err != nil {
			return "", fmt.Errorf("cannot sign assertion")
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
func (c *client) authenticate(ctx context.Context) error {
	if c.token != "" && time.Now().Before(c.until) {
		return nil
	}
	assertion, err := c.assertion()
	if err != nil {
		return err
	}
	values := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.clientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	if scopes := os.Getenv("AUTH_SCOPES"); scopes != "" {
		values.Set("scope", scopes)
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", c.issuer+"/oidc/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Auth token transport failed")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("Auth token request refused (%d)", res.StatusCode)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&token) != nil || token.AccessToken == "" || token.ExpiresIn <= 0 {
		return fmt.Errorf("invalid Auth token response")
	}
	c.token = token.AccessToken
	c.until = time.Now().Add(time.Duration(token.ExpiresIn-10) * time.Second)
	return nil
}

var safeCode = regexp.MustCompile(`^[a-z][a-z_]{0,79}$`)

func (c *client) request(ctx context.Context, method, path, tag string, body any) (map[string]any, string, error) {
	// The lock spans authentication and mutation so parallel Terraform resources
	// cannot race this provider's own shared administration revision.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.authenticate(ctx); err != nil {
		return nil, "", err
	}
	for c.tags[tag] != "" {
		tag = c.tags[tag]
	}
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.issuer+"/api/auth/admin/v1"+path, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tag != "" {
		req.Header.Set("If-Match", tag)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("Auth API transport failed")
	}
	defer res.Body.Close()
	var data map[string]any
	decode := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&data)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		code, _ := data["error"].(string)
		if !safeCode.MatchString(code) {
			code = "request_refused"
		}
		return nil, "", &apiError{res.StatusCode, code}
	}
	if decode != nil {
		return nil, "", fmt.Errorf("invalid Auth API response")
	}
	next := res.Header.Get("ETag")
	if next == "" {
		return nil, "", fmt.Errorf("Auth API omitted required ETag")
	}
	if method != "GET" && tag != "" && tag != next {
		c.tags[tag] = next
	}
	return data, next, nil
}
