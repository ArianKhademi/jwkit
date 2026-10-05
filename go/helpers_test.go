package jwkit

// Test support: signing keys, a token builder, a fake clock and an in-process
// JWKS server. Tokens are signed with the standard library directly rather
// than with jwx, so the tests do not check the library against itself.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const (
	testIssuer   = "https://issuer.example"
	testAudience = "https://api.example"
)

// testNow is the instant every test verifies at, unless it moves the clock.
var testNow = time.Unix(1_750_000_000, 0)

// testKey is a key pair the fake issuer can publish and sign with.
type testKey struct {
	kid string
	alg string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

// Keys are generated once per test binary; RSA generation is too slow to
// repeat in every test.
var (
	rsaKey1  = newRSAKey("rsa-1", 2048)
	rsaKey2  = newRSAKey("rsa-2", 2048)
	rsaKey3  = newRSAKey("rsa-3", 2048)
	rsaSmall = newRSAKey("rsa-small", 1024)
	ecKey1   = newECKey("ec-1", elliptic.P256())
	ecKey2   = newECKey("ec-2", elliptic.P256())
	ecP384   = newECKey("ec-p384", elliptic.P384())
)

func newRSAKey(kid string, bits int) testKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return testKey{kid: kid, alg: "RS256", rsa: k}
}

func newECKey(kid string, curve elliptic.Curve) testKey {
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return testKey{kid: kid, alg: "ES256", ec: k}
}

// withKid returns the same key pair published under another kid.
func (k testKey) withKid(kid string) testKey {
	k.kid = kid
	return k
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwk returns the public JWK for the key.
func (k testKey) jwk() map[string]any {
	if k.rsa != nil {
		return map[string]any{
			"kty": "RSA", "kid": k.kid, "use": "sig", "alg": "RS256",
			"n": b64(k.rsa.N.Bytes()),
			"e": b64(big.NewInt(int64(k.rsa.E)).Bytes()),
		}
	}
	size := (k.ec.Curve.Params().BitSize + 7) / 8
	return map[string]any{
		"kty": "EC", "kid": k.kid, "use": "sig", "crv": k.ec.Curve.Params().Name,
		"x": b64(k.ec.X.FillBytes(make([]byte, size))),
		"y": b64(k.ec.Y.FillBytes(make([]byte, size))),
	}
}

// signature signs the JWS signing input with the key's own algorithm.
func (k testKey) signature(signingInput string) []byte {
	digest := sha256.Sum256([]byte(signingInput))
	if k.rsa != nil {
		sig, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
	r, s, err := ecdsa.Sign(rand.Reader, k.ec, digest[:])
	if err != nil {
		panic(err)
	}
	size := (k.ec.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return sig
}

// signRaw builds a token from literal header and payload bytes, for tests
// that need JSON the encoder would never produce.
func (k testKey) signRaw(header, payload string) string {
	input := b64([]byte(header)) + "." + b64([]byte(payload))
	return input + "." + b64(k.signature(input))
}

// claims are the payload of a token that is valid at testNow.
func validClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"aud": testAudience,
		"sub": "user-1",
		"iat": testNow.Unix(),
		"exp": testNow.Unix() + 300,
	}
}

// token signs a valid token after letting edit change its header and payload.
func (k testKey) token(edit ...func(header, payload map[string]any)) string {
	header := map[string]any{"alg": k.alg, "kid": k.kid, "typ": "JWT"}
	payload := validClaims()
	for _, e := range edit {
		e(header, payload)
	}
	return k.signRaw(mustJSON(header), mustJSON(payload))
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// setClaim and setHeader are edits for testKey.token. A nil value deletes.
func setClaim(name string, value any) func(h, p map[string]any) {
	return func(_, p map[string]any) {
		if value == nil {
			delete(p, name)
		} else {
			p[name] = value
		}
	}
}

func setHeader(name string, value any) func(h, p map[string]any) {
	return func(h, _ map[string]any) {
		if value == nil {
			delete(h, name)
		} else {
			h[name] = value
		}
	}
}

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: testNow} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeIssuer is an in-process JWKS endpoint whose key set, status code and
// caching headers can be changed mid-test, and which counts requests.
type fakeIssuer struct {
	srv *httptest.Server

	mu           sync.Mutex
	body         []byte
	status       int
	cacheControl string
	hits         int
	hold         chan struct{} // if non-nil, requests block until it is closed
}

func newFakeIssuer(t testing.TB, keys ...testKey) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{status: http.StatusOK}
	f.publish(keys...)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.hits++
		body, status, cc, hold := f.body, f.status, f.cacheControl, f.hold
		f.mu.Unlock()
		if hold != nil {
			<-hold
		}
		if cc != "" {
			w.Header().Set("Cache-Control", cc)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) url() string { return f.srv.URL + "/.well-known/jwks.json" }

// publish replaces the key set the endpoint serves, as a rotation would.
func (f *fakeIssuer) publish(keys ...testKey) {
	jwks := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, k.jwk())
	}
	f.setBody(mustJSON(map[string]any{"keys": jwks}))
}

func (f *fakeIssuer) setBody(body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = []byte(body)
}

func (f *fakeIssuer) setStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
}

func (f *fakeIssuer) setCacheControl(v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheControl = v
}

// holdRequests makes every request block until the returned function is
// called. Calling it more than once is harmless, so tests can defer it.
func (f *fakeIssuer) holdRequests() (release func()) {
	hold := make(chan struct{})
	f.mu.Lock()
	f.hold = hold
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.hold = nil
			f.mu.Unlock()
			close(hold)
		})
	}
}

func (f *fakeIssuer) hitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

// newTestVerifier returns a verifier pointed at the fake issuer and clock.
func newTestVerifier(t testing.TB, iss *fakeIssuer, clock *fakeClock, edit ...func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{
		Issuer:   testIssuer,
		Audience: testAudience,
		JWKSURL:  iss.url(),
		Now:      clock.Now,
	}
	for _, e := range edit {
		e(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}
