package jwkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	// fetchTimeout bounds one JWKS request, whatever the HTTP client's own settings.
	fetchTimeout = 10 * time.Second
	// maxJWKSBytes caps the response body. Real key sets are a few kilobytes.
	maxJWKSBytes = 1 << 20
	// maxCacheTTL caps a Cache-Control max-age sent by the issuer, so that a
	// key withdrawn from the JWKS is dropped within a day at worst.
	maxCacheTTL = 24 * time.Hour
	// minRSABits is the smallest RSA modulus accepted for RS256 (RFC 7518 section 3.3).
	minRSABits = 2048
)

// verificationKey is a public key bound to the single algorithm it may be
// used with. Binding the algorithm to the key, rather than trusting the alg
// in the token header, rules out algorithm confusion by construction.
type verificationKey struct {
	alg    string
	public any // *rsa.PublicKey or *ecdsa.PublicKey
}

// keyCache holds the issuer's current key set and decides when to refetch it.
//
// One mutex guards all state. The critical sections are a map lookup and a
// few comparisons; the network fetch always happens outside the lock.
type keyCache struct {
	jwksURL         string
	client          *http.Client
	ttl             time.Duration
	refetchInterval time.Duration
	now             func() time.Time
	warn            func(error)

	mu         sync.Mutex
	keys       map[string]verificationKey // nil until the first successful fetch
	expiresAt  time.Time                  // when keys must be refreshed
	lastForced time.Time                  // last refetch caused by an unknown kid
	everForced bool
	inflight   *fetchCall // the fetch in progress, if any
}

// fetchCall is one in-flight JWKS fetch that any number of callers can wait on.
type fetchCall struct {
	done chan struct{} // closed when the fetch has finished and the cache is updated
	err  error         // valid once done is closed
}

// get returns the key for kid, fetching the JWKS if the cache is empty or
// stale, or (rate limited) if kid is not in it.
//
// The lookup and the decision to fetch happen under one lock acquisition.
// That is why this is hand-rolled instead of using x/sync/singleflight: a
// caller that is over the refetch rate limit must still be able to join a
// fetch that is already running, and "is a fetch running?" has to be answered
// atomically with "am I allowed to start one?".
func (c *keyCache) get(ctx context.Context, kid string) (verificationKey, error) {
	c.mu.Lock()
	now := c.now()
	fresh := c.keys != nil && now.Before(c.expiresAt)
	if key, ok := c.keys[kid]; ok && fresh {
		c.mu.Unlock()
		return key, nil
	}

	var call *fetchCall
	switch {
	case c.inflight != nil:
		// Someone is already fetching. Share their result instead of
		// sending a duplicate request.
		call = c.inflight
	case !fresh:
		// First use, or the TTL ran out.
		call = c.startFetchLocked()
	case !c.everForced || now.Sub(c.lastForced) >= c.refetchInterval:
		// Fresh cache but unknown kid: the issuer may have rotated keys
		// since the last fetch, so look once.
		c.everForced = true
		c.lastForced = now
		call = c.startFetchLocked()
	default:
		// Unknown kid and we already looked recently. Answer from the cache
		// so a burst of made-up kids costs the issuer nothing.
		c.mu.Unlock()
		return verificationKey{}, ErrUnknownKey.withDetail("no key with kid %q in the JWKS", kid)
	}
	c.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		return verificationKey{}, ErrJWKSUnavailable.withCause(ctx.Err(), "gave up waiting for the JWKS: %v", ctx.Err())
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys == nil {
		return verificationKey{}, ErrJWKSUnavailable.withCause(call.err, "%v", call.err)
	}
	// Whether or not the fetch worked there is a key set to answer from: the
	// new one, or the last good one.
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	return verificationKey{}, ErrUnknownKey.withDetail("no key with kid %q in the JWKS", kid)
}

// startFetchLocked starts a fetch on its own goroutine. c.mu must be held.
//
// The fetch is deliberately not tied to the context of the request that
// triggered it: many requests share its result, and one of them being
// cancelled must not fail the others.
func (c *keyCache) startFetchLocked() *fetchCall {
	call := &fetchCall{done: make(chan struct{})}
	c.inflight = call
	go func() {
		keys, ttl, err := c.fetch()

		c.mu.Lock()
		now := c.now()
		if err == nil {
			// Replace, never merge: a key the issuer has withdrawn must stop
			// verifying tokens as soon as we learn about it.
			c.keys = keys
			c.expiresAt = now.Add(ttl)
		} else if retryAt := now.Add(c.refetchInterval); c.expiresAt.Before(retryAt) {
			// Keep serving the last good key set, and do not retry before
			// refetchInterval so an outage is not answered with a fetch on
			// every request.
			c.expiresAt = retryAt
		}
		call.err = err
		c.inflight = nil
		c.mu.Unlock()

		// Warn before waking the waiters, so the hook has run by the time
		// any Verify call that depended on this fetch returns.
		if err != nil && c.warn != nil {
			c.warn(fmt.Errorf("jwkit: JWKS refresh from %s failed: %w", c.jwksURL, err))
		}
		close(call.done)
	}()
	return call
}

// fetch downloads and parses the JWKS, returning the keys and how long they
// may be cached.
func (c *keyCache) fetch() (map[string]verificationKey, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	// Read one byte past the cap to tell "exactly at the cap" from "over it".
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxJWKSBytes {
		return nil, 0, fmt.Errorf("response is larger than %d bytes", maxJWKSBytes)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, 0, err
	}

	ttl := c.ttl
	if maxAge, ok := cacheControlMaxAge(resp.Header.Get("Cache-Control")); ok {
		// The issuer knows its own rotation schedule better than a default
		// does, within limits: never poll faster than refetchInterval and
		// never trust a key set for more than maxCacheTTL.
		ttl = min(max(maxAge, c.refetchInterval), maxCacheTTL)
	}
	return keys, ttl, nil
}

// cacheControlMaxAge extracts max-age from a Cache-Control header value.
func cacheControlMaxAge(header string) (time.Duration, bool) {
	for _, directive := range strings.Split(header, ",") {
		name, value, found := strings.Cut(directive, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "max-age") {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if value == "" || strings.Trim(value, "0123456789") != "" {
			return 0, false
		}
		if len(value) > 9 {
			// More than nine digits is decades; clamp without parsing so
			// the conversion below cannot overflow.
			return maxCacheTTL, true
		}
		seconds, _ := strconv.Atoi(value)
		return time.Duration(seconds) * time.Second, true
	}
	return 0, false
}

// parseJWKS turns a JWKS document into verification keys indexed by kid.
//
// Keys jwkit cannot or should not use are skipped rather than failing the
// whole set, because issuers routinely publish encryption keys and other
// algorithms next to their signing keys. A document with no usable key at
// all is an error, so that a broken response never replaces a good cache.
func parseJWKS(body []byte) (map[string]verificationKey, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("JWKS is not a JSON object")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(doc["keys"], &entries); err != nil {
		return nil, errors.New(`JWKS has no "keys" array`)
	}
	keys := make(map[string]verificationKey)
	for _, entry := range entries {
		var jwkFields map[string]any
		if err := json.Unmarshal(entry, &jwkFields); err != nil {
			continue
		}
		kid, key, ok := importKey(jwkFields)
		if !ok {
			continue
		}
		// First one wins if the issuer repeats a kid.
		if _, dup := keys[kid]; !dup {
			keys[kid] = key
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable RS256 or ES256 key")
	}
	return keys, nil
}

// importKey converts one JWK into a verification key. ok is false if the key
// is not an RSA (2048 bits or more) or P-256 signature-verification key with
// a kid.
func importKey(f map[string]any) (kid string, key verificationKey, ok bool) {
	kid, _ = f["kid"].(string)
	if kid == "" {
		return "", key, false
	}
	if use, present := f["use"]; present && use != "sig" {
		return "", key, false
	}

	// Copy only the public members into the JWK handed to the library. If an
	// issuer ever published a private key by mistake, its private parameters
	// are never parsed, let alone kept.
	var public map[string]any
	switch f["kty"] {
	case "RSA":
		key.alg = algRS256
		public = map[string]any{"kty": "RSA", "n": f["n"], "e": f["e"]}
	case "EC":
		if f["crv"] != "P-256" {
			return "", key, false
		}
		key.alg = algES256
		public = map[string]any{"kty": "EC", "crv": "P-256", "x": f["x"], "y": f["y"]}
	default:
		return "", key, false
	}
	// A JWK may pin its own algorithm; respect it by ignoring keys meant for
	// algorithms we do not implement (PS256, RS384, ...).
	if alg, present := f["alg"]; present && alg != key.alg {
		return "", key, false
	}

	encoded, err := json.Marshal(public)
	if err != nil {
		return "", key, false
	}
	parsed, err := jwk.ParseKey(encoded)
	if err != nil {
		return "", key, false
	}
	if err := parsed.Raw(&key.public); err != nil {
		return "", key, false
	}
	switch pub := key.public.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSABits {
			return "", key, false
		}
	case *ecdsa.PublicKey:
		// ECDH() validates that the point is on the curve.
		if _, err := pub.ECDH(); err != nil {
			return "", key, false
		}
	}
	return kid, key, true
}
