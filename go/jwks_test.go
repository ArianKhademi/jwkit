package jwkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustVerify(t *testing.T, v *Verifier, token string) {
	t.Helper()
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("want token accepted, got %v", err)
	}
}

func mustReject(t *testing.T, v *Verifier, token string, want error) {
	t.Helper()
	_, err := v.Verify(context.Background(), token)
	wantResult(t, err, want)
}

func wantHits(t *testing.T, iss *fakeIssuer, want int) {
	t.Helper()
	if got := iss.hitCount(); got != want {
		t.Fatalf("JWKS endpoint was fetched %d times, want %d", got, want)
	}
}

func TestJWKSIsFetchedLazilyAndCached(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1, ecKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	wantHits(t, iss, 0) // NewVerifier does no I/O

	for i := 0; i < 10; i++ {
		mustVerify(t, v, rsaKey1.token())
		mustVerify(t, v, ecKey1.token())
	}
	wantHits(t, iss, 1)
}

// The whole rotation life cycle against a JWKS endpoint that changes mid-test.
func TestKeyRotation(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	clock := newFakeClock()
	v := newTestVerifier(t, iss, clock)

	oldToken := rsaKey1.token(setClaim("exp", testNow.Unix()+7200))
	newToken := rsaKey2.token(setClaim("exp", testNow.Unix()+7200))

	mustVerify(t, v, oldToken)
	wantHits(t, iss, 1)

	// The issuer starts signing with a new key and publishes both.
	iss.publish(rsaKey1, rsaKey2)
	clock.advance(time.Minute)

	// Tokens from the old key need no fetch: it is still cached.
	mustVerify(t, v, oldToken)
	wantHits(t, iss, 1)

	// The first token from the new key triggers exactly one refetch...
	mustVerify(t, v, newToken)
	wantHits(t, iss, 2)
	// ...and later ones are served from the cache.
	mustVerify(t, v, newToken)
	mustVerify(t, v, oldToken)
	wantHits(t, iss, 2)

	// The issuer retires the old key. Until the cache is refreshed the old
	// key still verifies; nothing has told us otherwise.
	iss.publish(rsaKey2)
	clock.advance(time.Minute)
	mustVerify(t, v, oldToken)
	wantHits(t, iss, 2)

	// After the TTL the refresh drops the retired key, and its tokens die.
	clock.advance(DefaultCacheTTL)
	mustReject(t, v, oldToken, ErrUnknownKey)
	wantHits(t, iss, 3) // the refresh itself; no second fetch for the unknown kid
	mustVerify(t, v, newToken)
	wantHits(t, iss, 3)
}

func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	clock := newFakeClock()
	v := newTestVerifier(t, iss, clock)

	mustVerify(t, v, rsaKey1.token())
	wantHits(t, iss, 1)

	// A burst of 100 tokens, each with a kid the issuer never published.
	burst := func() {
		for i := 0; i < 100; i++ {
			mustReject(t, v, rsaKey2.withKid(fmt.Sprintf("made-up-%d", i)).token(), ErrUnknownKey)
		}
	}
	burst()
	wantHits(t, iss, 2) // one forced refetch for the whole burst

	// Still inside the window: nothing.
	clock.advance(DefaultRefetchInterval - time.Second)
	burst()
	wantHits(t, iss, 2)

	// The window has passed: one more, and only one.
	clock.advance(time.Second)
	burst()
	wantHits(t, iss, 3)

	// The rate limit never stood in the way of known keys.
	mustVerify(t, v, rsaKey1.token())
	wantHits(t, iss, 3)
}

func TestRefetchIntervalIsConfigurable(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	clock := newFakeClock()
	v := newTestVerifier(t, iss, clock, func(c *Config) { c.RefetchInterval = 5 * time.Second })

	mustVerify(t, v, rsaKey1.token())
	mustReject(t, v, rsaKey2.token(), ErrUnknownKey)
	wantHits(t, iss, 2)
	clock.advance(4 * time.Second)
	mustReject(t, v, rsaKey2.token(), ErrUnknownKey)
	wantHits(t, iss, 2)
	clock.advance(time.Second)
	mustReject(t, v, rsaKey2.token(), ErrUnknownKey)
	wantHits(t, iss, 3)
}

// 200 verifications of tokens signed by a just-rotated key, all in flight at
// once, must share a single JWKS request and all succeed.
func TestConcurrentVerificationsShareOneFetch(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	clock := newFakeClock()
	v := newTestVerifier(t, iss, clock)
	mustVerify(t, v, rsaKey1.token())
	wantHits(t, iss, 1)

	iss.publish(rsaKey1, rsaKey2)
	release := iss.holdRequests() // keep the refetch in flight while the callers pile up
	newToken := rsaKey2.token()

	const parallel = 200
	var wg sync.WaitGroup
	errs := make(chan error, parallel)
	start := make(chan struct{})
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := v.Verify(context.Background(), newToken)
			errs <- err
		}()
	}
	close(start)
	waitFor(t, func() bool { return iss.hitCount() == 2 })
	release()
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent verification failed: %v", err)
		}
	}
	wantHits(t, iss, 2)
}

// The same guarantee for the very first fetch, when the cache is empty.
func TestConcurrentFirstUseSharesOneFetch(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	release := iss.holdRequests()
	token := rsaKey1.token()

	const parallel = 200
	var wg sync.WaitGroup
	errs := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := v.Verify(context.Background(), token)
			errs <- err
		}()
	}
	waitFor(t, func() bool { return iss.hitCount() == 1 })
	release()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent verification failed: %v", err)
		}
	}
	wantHits(t, iss, 1)
}

// waitFor polls until cond holds, failing the test after a generous deadline.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached in time")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCacheTTL(t *testing.T) {
	t.Run("default TTL", func(t *testing.T) {
		iss := newFakeIssuer(t, rsaKey1)
		clock := newFakeClock()
		v := newTestVerifier(t, iss, clock)
		longLived := rsaKey1.token(setClaim("exp", testNow.Unix()+86400*2))

		mustVerify(t, v, longLived)
		clock.advance(DefaultCacheTTL - time.Second)
		mustVerify(t, v, longLived)
		wantHits(t, iss, 1)
		clock.advance(time.Second)
		mustVerify(t, v, longLived)
		wantHits(t, iss, 2)
	})

	t.Run("configured TTL", func(t *testing.T) {
		iss := newFakeIssuer(t, rsaKey1)
		clock := newFakeClock()
		v := newTestVerifier(t, iss, clock, func(c *Config) { c.CacheTTL = time.Minute })
		longLived := rsaKey1.token(setClaim("exp", testNow.Unix()+86400*2))

		mustVerify(t, v, longLived)
		clock.advance(time.Minute)
		mustVerify(t, v, longLived)
		wantHits(t, iss, 2)
	})

	// Cache-Control: max-age from the issuer overrides the configured TTL,
	// clamped to [RefetchInterval, 24h].
	cacheControl := []struct {
		header  string
		wantTTL time.Duration
	}{
		{"max-age=120", 120 * time.Second},
		{"public, max-age=3600, must-revalidate", time.Hour},
		{"MAX-AGE=90", 90 * time.Second},
		{"max-age=1", DefaultRefetchInterval},         // floor
		{"max-age=0", DefaultRefetchInterval},         // floor
		{"max-age=31536000", maxCacheTTL},             // cap
		{"max-age=99999999999999999999", maxCacheTTL}, // cap, without overflowing
		{"no-cache", DefaultCacheTTL},                 // no max-age: configured TTL
		{"max-age=soon", DefaultCacheTTL},             // unparsable: configured TTL
		{"", DefaultCacheTTL},
	}
	for _, tc := range cacheControl {
		t.Run("Cache-Control "+tc.header, func(t *testing.T) {
			iss := newFakeIssuer(t, rsaKey1)
			iss.setCacheControl(tc.header)
			clock := newFakeClock()
			v := newTestVerifier(t, iss, clock)
			longLived := rsaKey1.token(setClaim("exp", testNow.Unix()+86400*2))

			mustVerify(t, v, longLived)
			clock.advance(tc.wantTTL - time.Second)
			mustVerify(t, v, longLived)
			wantHits(t, iss, 1)
			clock.advance(time.Second)
			mustVerify(t, v, longLived)
			wantHits(t, iss, 2)
		})
	}
}

func TestCacheControlMaxAge(t *testing.T) {
	tests := []struct {
		header string
		want   time.Duration
		ok     bool
	}{
		{"max-age=60", time.Minute, true},
		{" public ,  max-age = 60 ", time.Minute, true},
		{`max-age="60"`, time.Minute, true},
		{"s-maxage=60", 0, false},
		{"max-age", 0, false},
		{"max-age=", 0, false},
		{"max-age=-5", 0, false},
		{"max-age=1.5", 0, false},
		{"max-age=1234567890", maxCacheTTL, true},
		{"private", 0, false},
	}
	for _, tc := range tests {
		got, ok := cacheControlMaxAge(tc.header)
		if got != tc.want || ok != tc.ok {
			t.Errorf("cacheControlMaxAge(%q) = %v, %v; want %v, %v", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

// warnings collects what the OnWarning hook received.
type warnings struct {
	mu   sync.Mutex
	errs []error
}

func (w *warnings) hook(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.errs = append(w.errs, err)
}

func (w *warnings) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.errs)
}

func (w *warnings) last() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.errs) == 0 {
		return ""
	}
	return w.errs[len(w.errs)-1].Error()
}

func TestRefreshFailureKeepsLastGoodKeys(t *testing.T) {
	failures := map[string]func(*fakeIssuer){
		"HTTP 500":          func(f *fakeIssuer) { f.setStatus(http.StatusInternalServerError) },
		"HTTP 404":          func(f *fakeIssuer) { f.setStatus(http.StatusNotFound) },
		"not JSON":          func(f *fakeIssuer) { f.setBody("<html>maintenance</html>") },
		"JSON without keys": func(f *fakeIssuer) { f.setBody(`{"error":"down"}`) },
		"empty key set":     func(f *fakeIssuer) { f.setBody(`{"keys":[]}`) },
		"no usable key":     func(f *fakeIssuer) { f.setBody(`{"keys":[{"kty":"oct","kid":"x","k":"AAAA"}]}`) },
		"oversized body":    func(f *fakeIssuer) { f.setBody(`{"keys":[],"pad":"` + strings.Repeat("a", maxJWKSBytes) + `"}`) },
		"connection closed": func(f *fakeIssuer) { f.srv.CloseClientConnections(); f.srv.Close() },
	}
	for name, breakIssuer := range failures {
		t.Run(name, func(t *testing.T) {
			iss := newFakeIssuer(t, rsaKey1)
			clock := newFakeClock()
			var warned warnings
			v := newTestVerifier(t, iss, clock, func(c *Config) { c.OnWarning = warned.hook })
			longLived := rsaKey1.token(setClaim("exp", testNow.Unix()+86400))

			mustVerify(t, v, longLived)
			if warned.count() != 0 {
				t.Fatalf("unexpected warning: %s", warned.last())
			}

			breakIssuer(iss)
			clock.advance(DefaultCacheTTL)

			// The refresh fails; the token still verifies against the last
			// good key set and the hook hears about it.
			mustVerify(t, v, longLived)
			if warned.count() != 1 {
				t.Fatalf("OnWarning called %d times, want 1", warned.count())
			}
			if !strings.Contains(warned.last(), "JWKS refresh from "+iss.url()+" failed") {
				t.Errorf("warning = %q", warned.last())
			}

			// No retry storm: nothing is fetched again until RefetchInterval
			// has passed.
			for i := 0; i < 20; i++ {
				mustVerify(t, v, longLived)
			}
			if warned.count() != 1 {
				t.Fatalf("refresh was retried within RefetchInterval (%d warnings)", warned.count())
			}
			clock.advance(DefaultRefetchInterval)
			mustVerify(t, v, longLived)
			if warned.count() != 2 {
				t.Fatalf("OnWarning called %d times after the retry, want 2", warned.count())
			}
		})
	}
}

func TestRefreshRecoversAfterFailure(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	clock := newFakeClock()
	var warned warnings
	v := newTestVerifier(t, iss, clock, func(c *Config) { c.OnWarning = warned.hook })
	mustVerify(t, v, rsaKey1.token())

	iss.setStatus(http.StatusServiceUnavailable)
	clock.advance(DefaultCacheTTL)
	mustVerify(t, v, rsaKey1.token(setClaim("exp", clock.Now().Unix()+60)))
	if warned.count() != 1 {
		t.Fatalf("want 1 warning, got %d", warned.count())
	}

	// The issuer comes back, having rotated in the meantime.
	iss.setStatus(http.StatusOK)
	iss.publish(rsaKey2)
	clock.advance(DefaultRefetchInterval)
	mustVerify(t, v, rsaKey2.token(setClaim("exp", clock.Now().Unix()+60)))
	mustReject(t, v, rsaKey1.token(setClaim("exp", clock.Now().Unix()+60)), ErrUnknownKey)
	if warned.count() != 1 {
		t.Fatalf("warned again after recovery: %s", warned.last())
	}
}

func TestFailedForcedRefetchKeepsCache(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	clock := newFakeClock()
	var warned warnings
	v := newTestVerifier(t, iss, clock, func(c *Config) { c.OnWarning = warned.hook })
	mustVerify(t, v, rsaKey1.token())

	iss.setStatus(http.StatusBadGateway)
	mustReject(t, v, rsaKey2.token(), ErrUnknownKey)
	wantHits(t, iss, 2)
	if warned.count() != 1 {
		t.Fatalf("want 1 warning, got %d", warned.count())
	}
	// The failed lookup did not damage the cache or shorten its life.
	mustVerify(t, v, rsaKey1.token())
	wantHits(t, iss, 2)
}

func TestJWKSUnavailableOnFirstUse(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	iss.setStatus(http.StatusInternalServerError)
	var warned warnings
	v := newTestVerifier(t, iss, newFakeClock(), func(c *Config) { c.OnWarning = warned.hook })

	// With no key set at all there is nothing to fall back on.
	_, err := v.Verify(context.Background(), rsaKey1.token())
	wantResult(t, err, ErrJWKSUnavailable)
	if !strings.Contains(err.Error(), "unexpected HTTP status 500") {
		t.Errorf("error does not explain the cause: %v", err)
	}
	if warned.count() != 1 {
		t.Fatalf("want 1 warning, got %d", warned.count())
	}

	// It is not a permanent state: the next call tries again.
	iss.setStatus(http.StatusOK)
	mustVerify(t, v, rsaKey1.token())
	wantHits(t, iss, 2)
}

func TestMalformedTokenNeverTouchesTheNetwork(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	mustReject(t, v, "garbage", ErrMalformed)
	mustReject(t, v, unsigned(map[string]any{"alg": "none"}), ErrUnsupportedAlg)
	mustReject(t, v, hs256WithPublicKey(rsaKey1), ErrUnsupportedAlg)
	wantHits(t, iss, 0)
}

func TestVerifyHonoursContextWhileWaitingForKeys(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	release := iss.holdRequests()
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := v.Verify(ctx, rsaKey1.token())
		done <- err
	}()
	waitFor(t, func() bool { return iss.hitCount() == 1 })
	cancel()

	err := <-done
	wantResult(t, err, ErrJWKSUnavailable)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled: %v", err)
	}

	// The fetch itself was not cancelled with the caller: once it completes,
	// the keys are there for everyone else.
	release()
	mustVerify(t, v, rsaKey1.token())
	wantHits(t, iss, 1)
}

func TestFetchErrors(t *testing.T) {
	// A URL that passes validation but cannot be turned into a request.
	c := &keyCache{jwksURL: "http://issuer.example/\x7f", client: &http.Client{}, now: time.Now}
	if _, _, err := c.fetch(); err == nil {
		t.Error("want an error for an unusable URL")
	}
}

func TestParseJWKS(t *testing.T) {
	jwkWith := func(k testKey, edit func(map[string]any)) map[string]any {
		j := k.jwk()
		edit(j)
		return j
	}
	privateRSA := jwkWith(rsaKey2, func(j map[string]any) {
		// A private key published by mistake: only n and e may be used.
		j["d"] = b64(rsaKey2.rsa.D.Bytes())
		j["p"] = b64(rsaKey2.rsa.Primes[0].Bytes())
		j["q"] = b64(rsaKey2.rsa.Primes[1].Bytes())
	})
	offCurve := jwkWith(ecKey2, func(j map[string]any) { j["kid"] = "off-curve"; j["y"] = j["x"] })

	doc := mustJSON(map[string]any{"keys": []any{
		rsaKey1.jwk(),
		ecKey1.jwk(),
		privateRSA,
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "rsa-1" }),                     // duplicate kid: ignored
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "enc"; j["use"] = "enc" }),     // encryption key
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "ps256"; j["alg"] = "PS256" }), // other algorithm
		jwkWith(rsaKey3, func(j map[string]any) { delete(j, "kid") }),                       // no kid
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = 7 }),                           // kid not a string
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "no-n"; delete(j, "n") }),      // incomplete
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "bad-n"; j["n"] = "!!!" }),     // not base64url
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "zero-n"; j["n"] = b64(make([]byte, 256)) }), // all-zero modulus
		jwkWith(rsaKey3, func(j map[string]any) { j["kid"] = "no-alg-use"; delete(j, "alg"); delete(j, "use") }),
		rsaSmall.jwk(), // 1024-bit modulus
		ecP384.jwk(),   // wrong curve
		offCurve,
		map[string]any{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
		map[string]any{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "AAAA"},
		"not an object",
		nil,
	}})

	keys, err := parseJWKS([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"rsa-1": "RS256", "ec-1": "ES256", "rsa-2": "RS256", "no-alg-use": "RS256"}
	if len(keys) != len(want) {
		t.Errorf("loaded %d keys, want %d: %v", len(keys), len(want), keys)
	}
	for kid, alg := range want {
		if keys[kid].alg != alg {
			t.Errorf("key %q: alg = %q, want %q", kid, keys[kid].alg, alg)
		}
	}
	// First key wins on a duplicate kid.
	if !rsaKey1.rsa.PublicKey.Equal(keys["rsa-1"].public) {
		t.Error("duplicate kid replaced the first key")
	}
	// Keys are held as public keys even if private material was published.
	if !rsaKey2.rsa.PublicKey.Equal(keys["rsa-2"].public) {
		t.Errorf("rsa-2 held as %T", keys["rsa-2"].public)
	}

	for name, body := range map[string]string{
		"not JSON":           `<html>`,
		"array":              `[]`,
		"no keys member":     `{}`,
		"keys not array":     `{"keys":{}}`,
		"keys null":          `{"keys":null}`,
		"wrong case":         `{"KEYS":[` + mustJSON(rsaKey1.jwk()) + `]}`,
		"only unusable":      `{"keys":[{"kty":"oct","kid":"a"}]}`,
		"empty document":     ``,
		"keys of wrong type": `{"keys":[1,2,3]}`,
	} {
		if _, err := parseJWKS([]byte(body)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
