package jwkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// discoveryIssuer is an issuer that publishes an OpenID Connect discovery
// document. Its issuer identifier is its own URL, as the specification
// requires, and every part of it can be broken or moved mid-test.
type discoveryIssuer struct {
	srv *httptest.Server

	mu       sync.Mutex
	document string            // body of the discovery document; "" means 404
	jwksAt   map[string]string // path -> JWKS body
	hits     map[string]int
}

func newDiscoveryIssuer(t *testing.T, keys ...testKey) *discoveryIssuer {
	t.Helper()
	d := &discoveryIssuer{jwksAt: map[string]string{}, hits: map[string]int{}}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.hits[r.URL.Path]++
		body, ok := d.jwksAt[r.URL.Path]
		if r.URL.Path == "/.well-known/openid-configuration" {
			body, ok = d.document, d.document != ""
		}
		d.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(d.srv.Close)
	d.publishAt("/keys", keys...)
	d.setDocument(mustJSON(map[string]any{"issuer": d.srv.URL, "jwks_uri": d.srv.URL + "/keys"}))
	return d
}

func (d *discoveryIssuer) setDocument(body string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.document = body
}

func (d *discoveryIssuer) publishAt(path string, keys ...testKey) {
	jwks := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, k.jwk())
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jwksAt[path] = mustJSON(map[string]any{"keys": jwks})
}

func (d *discoveryIssuer) remove(path string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.jwksAt, path)
}

func (d *discoveryIssuer) hitCount(path string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hits[path]
}

// verifier returns a verifier configured with the issuer only: no JWKS URL.
func (d *discoveryIssuer) verifier(t *testing.T, clock *fakeClock, edit ...func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{Issuer: d.srv.URL, Audience: testAudience, Now: clock.Now}
	for _, e := range edit {
		e(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// token mints a token whose iss is this issuer.
func (d *discoveryIssuer) token(k testKey, edit ...func(h, p map[string]any)) string {
	return k.token(append([]func(h, p map[string]any){setClaim("iss", d.srv.URL)}, edit...)...)
}

const discoveryPath = "/.well-known/openid-configuration"

func TestDiscovery(t *testing.T) {
	d := newDiscoveryIssuer(t, rsaKey1)
	clock := newFakeClock()
	v := d.verifier(t, clock)
	if d.hitCount(discoveryPath) != 0 {
		t.Fatal("NewVerifier must not perform discovery")
	}

	for i := 0; i < 5; i++ {
		mustVerify(t, v, d.token(rsaKey1))
	}
	if got := d.hitCount(discoveryPath); got != 1 {
		t.Errorf("discovery document fetched %d times, want 1", got)
	}
	if got := d.hitCount("/keys"); got != 1 {
		t.Errorf("JWKS fetched %d times, want 1", got)
	}

	// A routine refresh reuses the discovered location.
	clock.advance(DefaultCacheTTL)
	mustVerify(t, v, d.token(rsaKey1, setClaim("exp", clock.Now().Unix()+60)))
	if d.hitCount(discoveryPath) != 1 || d.hitCount("/keys") != 2 {
		t.Errorf("after refresh: discovery %d, JWKS %d; want 1 and 2", d.hitCount(discoveryPath), d.hitCount("/keys"))
	}
}

func TestDiscoveryWithTrailingSlashIssuer(t *testing.T) {
	// Auth0-style issuer: "https://tenant.example/". The discovery URL must
	// not end up with a double slash, and iss must still match exactly.
	d := newDiscoveryIssuer(t, rsaKey1)
	issuer := d.srv.URL + "/"
	d.setDocument(mustJSON(map[string]any{"issuer": issuer, "jwks_uri": d.srv.URL + "/keys"}))
	v := d.verifier(t, newFakeClock(), func(c *Config) { c.Issuer = issuer })

	mustVerify(t, v, rsaKey1.token(setClaim("iss", issuer)))
	mustReject(t, v, rsaKey1.token(setClaim("iss", d.srv.URL)), ErrBadIssuer)
	if d.hitCount(discoveryPath) != 1 {
		t.Errorf("discovery document fetched %d times at %s", d.hitCount(discoveryPath), discoveryPath)
	}
}

func TestDiscoveryFailures(t *testing.T) {
	tests := []struct {
		name     string
		document func(base string) string
		wantErr  string
	}{
		{"no document", func(string) string { return "" }, "unexpected HTTP status 404"},
		{"not JSON", func(string) string { return "<html>" }, "not a JSON object"},
		{"document for another issuer", func(base string) string {
			return mustJSON(map[string]any{"issuer": "https://evil.example", "jwks_uri": base + "/keys"})
		}, `document is for issuer "https://evil.example"`},
		{"issuer differs by a trailing slash", func(base string) string {
			return mustJSON(map[string]any{"issuer": base + "/", "jwks_uri": base + "/keys"})
		}, "document is for issuer"},
		{"no issuer", func(base string) string { return mustJSON(map[string]any{"jwks_uri": base + "/keys"}) }, "document is for issuer"},
		{"no jwks_uri", func(base string) string { return mustJSON(map[string]any{"issuer": base}) }, "no jwks_uri"},
		{"jwks_uri is not a string", func(base string) string { return mustJSON(map[string]any{"issuer": base, "jwks_uri": 7}) }, "no jwks_uri"},
		{"relative jwks_uri", func(base string) string { return mustJSON(map[string]any{"issuer": base, "jwks_uri": "/keys"}) }, "jwks_uri"},
		{"jwks_uri with another scheme", func(base string) string {
			return mustJSON(map[string]any{"issuer": base, "jwks_uri": "file:///etc/passwd"})
		}, "jwks_uri"},
		{"unparsable jwks_uri", func(base string) string {
			return mustJSON(map[string]any{"issuer": base, "jwks_uri": "http://[::1"})
		}, "jwks_uri"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := newDiscoveryIssuer(t, rsaKey1)
			good := mustJSON(map[string]any{"issuer": d.srv.URL, "jwks_uri": d.srv.URL + "/keys"})
			d.setDocument(tc.document(d.srv.URL))
			var warned warnings
			v := d.verifier(t, newFakeClock(), func(c *Config) { c.OnWarning = warned.hook })

			_, err := v.Verify(context.Background(), d.token(rsaKey1))
			wantResult(t, err, ErrJWKSUnavailable)
			if !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "OpenID discovery at "+d.srv.URL+discoveryPath) {
				t.Errorf("error = %v, want it to mention discovery and %q", err, tc.wantErr)
			}
			if warned.count() != 1 {
				t.Errorf("want 1 warning, got %d", warned.count())
			}
			if d.hitCount("/keys") != 0 {
				t.Error("the JWKS was fetched although discovery failed")
			}

			// Nothing is cached from a failed discovery: once the document
			// is right, the next call works.
			d.setDocument(good)
			mustVerify(t, v, d.token(rsaKey1))
		})
	}
}

// If the JWKS disappears from the discovered location, the next attempt
// performs discovery again and follows the issuer to the new one.
func TestDiscoveryFollowsAMovedJWKS(t *testing.T) {
	d := newDiscoveryIssuer(t, rsaKey1)
	clock := newFakeClock()
	var warned warnings
	v := d.verifier(t, clock, func(c *Config) { c.OnWarning = warned.hook })
	longLived := func(k testKey) string { return d.token(k, setClaim("exp", testNow.Unix()+86400)) }
	mustVerify(t, v, longLived(rsaKey1))

	// The issuer moves its JWKS and rotates at the same time.
	d.remove("/keys")
	d.publishAt("/keys-v2", rsaKey2)
	d.setDocument(mustJSON(map[string]any{"issuer": d.srv.URL, "jwks_uri": d.srv.URL + "/keys-v2"}))

	// The refresh hits the old location, fails, and the old keys keep working.
	clock.advance(DefaultCacheTTL)
	mustVerify(t, v, longLived(rsaKey1))
	if warned.count() != 1 || !strings.Contains(warned.last(), "/keys") {
		t.Fatalf("warnings: %d, last %q", warned.count(), warned.last())
	}

	// The retry rediscovers, finds the new location and the new key.
	clock.advance(DefaultRefetchInterval)
	mustVerify(t, v, longLived(rsaKey2))
	if d.hitCount(discoveryPath) != 2 || d.hitCount("/keys-v2") != 1 {
		t.Errorf("discovery %d, new JWKS %d; want 2 and 1", d.hitCount(discoveryPath), d.hitCount("/keys-v2"))
	}
	// The old key is gone. Its kid is now unknown, which costs one forced
	// refetch of the JWKS but no further discovery.
	mustReject(t, v, longLived(rsaKey1), ErrUnknownKey)
	if d.hitCount(discoveryPath) != 2 || d.hitCount("/keys-v2") != 2 {
		t.Errorf("discovery %d, new JWKS %d; want 2 and 2", d.hitCount(discoveryPath), d.hitCount("/keys-v2"))
	}
	if warned.count() != 1 {
		t.Errorf("warned again after recovery: %s", warned.last())
	}
}

// A configured JWKS URL is never second-guessed by discovery.
func TestConfiguredJWKSURLSkipsDiscovery(t *testing.T) {
	d := newDiscoveryIssuer(t, rsaKey1)
	v := d.verifier(t, newFakeClock(), func(c *Config) { c.JWKSURL = d.srv.URL + "/keys" })
	mustVerify(t, v, d.token(rsaKey1))
	if d.hitCount(discoveryPath) != 0 {
		t.Error("discovery was performed despite a configured JWKS URL")
	}
}
