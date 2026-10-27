package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRefusalNeverRetriesOrLeaksResponse(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-Match") != `"reviewed"` {
			t.Error("reviewed tag was replaced")
		}
		w.WriteHeader(412)
		fmt.Fprint(w, `{"error":"synthetic-auth-1 PRIVATE KEY access_token"}`)
	}))
	defer server.Close()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &client{issuer: server.URL, key: key, http: server.Client(), token: "synthetic-auth-2", until: time.Now().Add(time.Minute), tags: map[string]string{}}
	_, _, err := c.request(context.Background(), "PATCH", "/apps/synthetic-auth-3", `"reviewed"`, map[string]any{"name": "Payroll"})
	if err == nil || !strings.Contains(err.Error(), "stale ETag") || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("unsafe refusal: %v", err)
	}
	if calls != 1 || len(c.tags) != 0 {
		t.Fatal("refusal must not retry or advance a reviewed tag")
	}
}
