// Package jwkit verifies JWTs issued by an identity provider that publishes a
// JWKS endpoint (Auth0, Clerk, Cognito, Keycloak, or an in-house issuer).
//
// It has three parts:
//
//   - Verifier checks a token's signature against the issuer's keys and then
//     its iss, aud, exp, nbf and iat claims, failing with a typed *Error.
//   - A key cache fetches the JWKS, caches keys by kid, and refetches (rate
//     limited) when a token arrives signed by a key it has not seen, which is
//     how key rotation is handled without restarts.
//   - GinMiddleware wires the verifier into a Gin router.
//
// A TypeScript package with the same behaviour and the same error names lives
// next to this module; a shared conformance suite keeps the two in agreement.
package jwkit

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults applied by NewVerifier when the corresponding Config field is zero.
const (
	DefaultClockSkew       = 60 * time.Second
	DefaultCacheTTL        = 10 * time.Minute
	DefaultRefetchInterval = 30 * time.Second
	// DefaultMaxTokenBytes matches the 8 KiB header limit of common proxies:
	// a larger bearer token would not have reached the service anyway.
	DefaultMaxTokenBytes = 8192
)

// Config configures a Verifier. Issuer, Audience and JWKSURL are required.
type Config struct {
	// Issuer is the exact value the token's iss claim must have.
	Issuer string
	// Audience must appear in the token's aud claim.
	Audience string
	// JWKSURL is where the issuer publishes its public keys.
	JWKSURL string

	// ClockSkew is the tolerance applied to exp, nbf and iat. Zero means
	// DefaultClockSkew; a negative value means no tolerance.
	ClockSkew time.Duration
	// CacheTTL is how long a fetched key set is used before it is refreshed,
	// unless the JWKS response carries Cache-Control: max-age. Zero means
	// DefaultCacheTTL.
	CacheTTL time.Duration
	// RefetchInterval is the minimum time between refetches triggered by a
	// token with an unknown kid. It is the limit that stops a client spraying
	// random kids from turning this service into a load generator against
	// the JWKS endpoint. Zero means DefaultRefetchInterval.
	RefetchInterval time.Duration
	// MaxTokenBytes rejects longer tokens before any parsing. Zero means
	// DefaultMaxTokenBytes.
	MaxTokenBytes int

	// HTTPClient fetches the JWKS. Nil means a client with default settings;
	// every fetch is additionally bounded by a 10 second timeout.
	HTTPClient *http.Client
	// OnWarning, if set, is called when a JWKS refresh fails and the verifier
	// keeps serving the last good key set. It runs on the fetching goroutine
	// and must not block.
	OnWarning func(error)
	// Now overrides the clock. It exists for tests and for the conformance
	// runner, which verifies fixtures at a fixed instant.
	Now func() time.Time
}

// Verifier verifies tokens for one issuer and audience. It is safe for
// concurrent use; create one per issuer and share it.
type Verifier struct {
	issuer        string
	audience      string
	skewSeconds   float64
	maxTokenBytes int
	now           func() time.Time
	keys          *keyCache
}

// NewVerifier validates cfg and returns a Verifier. It performs no network
// I/O: the JWKS is fetched lazily by the first Verify call.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("jwkit: Config.Issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("jwkit: Config.Audience is required")
	}
	if err := checkHTTPURL(cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("jwkit: Config.JWKSURL: %w", err)
	}

	skew := cfg.ClockSkew
	switch {
	case skew == 0:
		skew = DefaultClockSkew
	case skew < 0:
		skew = 0
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.RefetchInterval <= 0 {
		cfg.RefetchInterval = DefaultRefetchInterval
	}
	if cfg.MaxTokenBytes <= 0 {
		cfg.MaxTokenBytes = DefaultMaxTokenBytes
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Verifier{
		issuer:        cfg.Issuer,
		audience:      cfg.Audience,
		skewSeconds:   skew.Seconds(),
		maxTokenBytes: cfg.MaxTokenBytes,
		now:           cfg.Now,
		keys: &keyCache{
			jwksURL:         cfg.JWKSURL,
			client:          cfg.HTTPClient,
			ttl:             cfg.CacheTTL,
			refetchInterval: cfg.RefetchInterval,
			now:             cfg.Now,
			warn:            cfg.OnWarning,
		},
	}, nil
}

func checkHTTPURL(raw string) error {
	if raw == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return nil
}

// Claims is the verified payload of a token.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	// ExpiresAt is always set: jwkit rejects tokens without exp.
	ExpiresAt time.Time
	// NotBefore and IssuedAt are the zero time when the token omits them.
	NotBefore time.Time
	IssuedAt  time.Time
	// Raw holds every claim as decoded from JSON. Numbers are json.Number
	// rather than float64 so that large integer claims keep their precision.
	Raw map[string]any
}

// Strings returns the named claim as a list of strings. It accepts the two
// encodings identity providers use for lists: a JSON array of strings, or a
// single space-delimited string (the OAuth 2.0 "scope" format). Any other
// shape yields nil.
func (c *Claims) Strings(name string) []string {
	switch v := c.Raw[name].(type) {
	case string:
		return strings.Fields(v)
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Scopes returns the token's scopes from the "scope" claim (RFC 8693) and the
// "scp" claim (used by Okta and Microsoft Entra ID), in that order.
func (c *Claims) Scopes() []string {
	return append(c.Strings("scope"), c.Strings("scp")...)
}
