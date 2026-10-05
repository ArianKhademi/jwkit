package jwkit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// The algorithm allow-list. Everything else, including "none" and the HMAC
// family, is rejected before a key is looked up. Never letting a token choose
// a symmetric algorithm is what defeats the RS256-to-HS256 confusion attack,
// where the attacker signs with the public key as an HMAC secret.
const (
	algRS256 = "RS256"
	algES256 = "ES256"
)

// es256SignatureLen is the size of an ES256 signature: r and s, 32 bytes each.
const es256SignatureLen = 64

// jwkit owns parsing and policy; the signature maths is delegated to jwx.
var (
	rs256Verifier = mustVerifier(jwa.RS256)
	es256Verifier = mustVerifier(jwa.ES256)
)

func mustVerifier(alg jwa.SignatureAlgorithm) jws.Verifier {
	v, err := jws.NewVerifier(alg)
	if err != nil {
		panic("jwkit: " + err.Error()) // unreachable: RS256 and ES256 are built into jwx
	}
	return v
}

// Verify checks token and returns its claims, or a *Error naming the first
// check that failed. The order is fixed and identical in the TypeScript
// implementation, so a token that is wrong in several ways produces the same
// error in both:
//
//  1. structure (ErrMalformed)
//  2. algorithm allow-list (ErrUnsupportedAlg), then kid presence (ErrMalformed)
//  3. key lookup (ErrUnknownKey, ErrJWKSUnavailable)
//  4. signature (ErrBadSignature)
//  5. iss (ErrBadIssuer), aud (ErrBadAudience)
//  6. exp/nbf/iat types (ErrMalformed), exp (ErrExpired), nbf and iat (ErrNotYetValid)
//
// Claims are only examined after the signature has verified, so the error
// type never reveals anything about an unauthenticated payload.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	p, err := parseToken(token, v.maxTokenBytes)
	if err != nil {
		return nil, err
	}
	alg, kid, err := checkHeader(p.header)
	if err != nil {
		return nil, err
	}
	key, err := v.keys.get(ctx, kid)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(alg, kid, key, p); err != nil {
		return nil, err
	}
	return v.checkClaims(p.payload)
}

// DecodeUnverified parses a token and returns its header and payload WITHOUT
// checking the signature or any claim. It exists for debugging tools; never
// make an authorization decision from its result.
func DecodeUnverified(token string) (header, payload map[string]any, err error) {
	p, err := parseToken(token, DefaultMaxTokenBytes)
	if err != nil {
		return nil, nil, err
	}
	return p.header, p.payload, nil
}

// parsedToken is a structurally valid compact JWS.
type parsedToken struct {
	header    map[string]any
	payload   map[string]any
	signature []byte
	// signingInput is "<header>.<payload>" byte for byte as received. The
	// signature covers these bytes, not a re-encoding of the decoded JSON.
	signingInput []byte
}

// parseToken enforces the structure of a compact JWS carrying a JWT: exactly
// three segments of canonical unpadded base64url, where the first two decode
// to UTF-8 JSON objects. Every failure is ErrMalformed.
func parseToken(token string, maxBytes int) (*parsedToken, error) {
	// Size first, so that nothing below does work proportional to an
	// attacker-chosen length.
	if len(token) > maxBytes {
		return nil, ErrMalformed.withDetail("token is %d bytes; the limit is %d", len(token), maxBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed.withDetail("expected 3 dot-separated segments, found %d", len(parts))
	}
	header, err := decodeObject(parts[0])
	if err != nil {
		return nil, ErrMalformed.withDetail("header: %v", err)
	}
	payload, err := decodeObject(parts[1])
	if err != nil {
		return nil, ErrMalformed.withDetail("payload: %v", err)
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return nil, ErrMalformed.withDetail("signature: %v", err)
	}
	return &parsedToken{
		header:       header,
		payload:      payload,
		signature:    signature,
		signingInput: []byte(token[:len(parts[0])+1+len(parts[1])]),
	}, nil
}

// decodeSegment decodes one base64url segment strictly.
func decodeSegment(s string) ([]byte, error) {
	// Go's base64 decoder silently skips '\r' and '\n'. JWS allows no such
	// thing and other implementations reject them, so check the alphabet
	// ourselves before decoding.
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return nil, errors.New("not base64url")
		}
	}
	// Strict also rejects non-zero trailing bits, so every byte string has
	// exactly one accepted encoding and a signature cannot be re-spelled
	// into a different token that still verifies.
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("not canonical base64url")
	}
	return b, nil
}

// decodeObject decodes a base64url segment that must contain a JSON object.
func decodeObject(segment string) (map[string]any, error) {
	raw, err := decodeSegment(segment)
	if err != nil {
		return nil, err
	}
	// encoding/json replaces invalid UTF-8 with U+FFFD instead of failing.
	// Reject it up front so both implementations agree on what is JSON.
	if !utf8.Valid(raw) {
		return nil, errors.New("not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Keep numbers as written. Converting to float64 here would make Go fail
	// on a literal such as 1e400 that other JSON parsers accept.
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("not valid JSON")
	}
	// Decode stops at the end of the first value; anything but whitespace
	// after it makes the segment invalid.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("not valid JSON: data after the top-level value")
	}
	// Decoding into a map (not a struct) keeps member names case-sensitive:
	// encoding/json would happily match "ALG" to a field tagged "alg".
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	return obj, nil
}

// checkHeader applies the header policy and returns the algorithm and key ID.
func checkHeader(h map[string]any) (alg, kid string, err error) {
	alg, ok := h["alg"].(string)
	if !ok {
		return "", "", ErrMalformed.withDetail(`header has no string "alg"`)
	}
	if alg != algRS256 && alg != algES256 {
		return "", "", ErrUnsupportedAlg.withDetail("alg %q is not allowed; only RS256 and ES256 are", alg)
	}
	// RFC 7515 section 4.1.11: a token listing critical extensions must be
	// rejected unless every one of them is understood. jwkit implements none.
	if _, present := h["crit"]; present {
		return "", "", ErrMalformed.withDetail(`header has "crit" but no critical extensions are supported`)
	}
	kid, ok = h["kid"].(string)
	if !ok || kid == "" {
		return "", "", ErrMalformed.withDetail(`header has no "kid"`)
	}
	// Headers that point at key material (jku, x5u, jwk, x5c) are deliberately
	// never read: keys come only from the configured JWKS URL.
	return alg, kid, nil
}

func verifySignature(alg, kid string, key verificationKey, p *parsedToken) error {
	// The key decides the algorithm, not the token. Each cached key is bound
	// to the one algorithm its type supports, so a token cannot ask for an
	// RSA key to be used as anything other than an RS256 verification key.
	if key.alg != alg {
		return ErrBadSignature.withDetail("token alg is %s but key %q is an %s key", alg, kid, key.alg)
	}
	var err error
	switch alg {
	case algRS256:
		err = rs256Verifier.Verify(p.signingInput, p.signature, key.public)
	case algES256:
		// Enforced here rather than left to the crypto library so that the
		// rule is identical in both languages.
		if len(p.signature) != es256SignatureLen {
			return ErrBadSignature.withDetail("ES256 signature is %d bytes, want %d", len(p.signature), es256SignatureLen)
		}
		err = es256Verifier.Verify(p.signingInput, p.signature, key.public)
	}
	if err != nil {
		return ErrBadSignature.withDetail("signature does not verify with key %q", kid)
	}
	return nil
}

func (v *Verifier) checkClaims(p map[string]any) (*Claims, error) {
	iss, ok := p["iss"].(string)
	if !ok || iss != v.issuer {
		return nil, ErrBadIssuer.withDetail("iss is not %q", v.issuer)
	}
	aud := audiences(p["aud"])
	if !contains(aud, v.audience) {
		return nil, ErrBadAudience.withDetail("aud does not contain %q", v.audience)
	}

	exp, hasExp, err := numericDate(p, "exp")
	if err != nil {
		return nil, err
	}
	if !hasExp {
		return nil, ErrMalformed.withDetail("token has no exp claim")
	}
	nbf, hasNbf, err := numericDate(p, "nbf")
	if err != nil {
		return nil, err
	}
	iat, hasIat, err := numericDate(p, "iat")
	if err != nil {
		return nil, err
	}

	// Whole seconds and float64 arithmetic, exactly as the TypeScript side
	// computes it, so boundary cases land on the same side in both.
	now := float64(v.now().Unix())
	if now >= exp+v.skewSeconds {
		return nil, ErrExpired.withDetail("token expired at %s", unixTime(exp).Format(time.RFC3339))
	}
	if hasNbf && nbf > now+v.skewSeconds {
		return nil, ErrNotYetValid.withDetail("token is not valid before %s", unixTime(nbf).Format(time.RFC3339))
	}
	if hasIat && iat > now+v.skewSeconds {
		return nil, ErrNotYetValid.withDetail("token was issued in the future, at %s", unixTime(iat).Format(time.RFC3339))
	}

	c := &Claims{Issuer: iss, Audience: aud, ExpiresAt: unixTime(exp), Raw: p}
	c.Subject, _ = p["sub"].(string)
	if hasNbf {
		c.NotBefore = unixTime(nbf)
	}
	if hasIat {
		c.IssuedAt = unixTime(iat)
	}
	return c, nil
}

// audiences normalises the aud claim, which may be one string or an array.
// Non-string array elements cannot match an audience and are dropped.
func audiences(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		var out []string
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// numericDate reads a NumericDate claim (seconds since the epoch, fractions
// allowed). A claim that is present but not a finite JSON number is
// ErrMalformed.
func numericDate(p map[string]any, name string) (value float64, present bool, err error) {
	raw, present := p[name]
	if !present {
		return 0, false, nil
	}
	num, ok := raw.(json.Number)
	if !ok {
		return 0, true, ErrMalformed.withDetail("%s is not a number", name)
	}
	// Float64 fails with a range error for literals beyond float64, such as
	// 1e400, and returns ±Inf. Underflow (1e-400) quietly becomes 0, which
	// is also what JSON.parse yields.
	f, convErr := num.Float64()
	if convErr != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, true, ErrMalformed.withDetail("%s is not a finite number", name)
	}
	return f, true, nil
}

// Bounds of what time.Time can format as a four-digit year.
const (
	minUnix = -62135596800 // 0001-01-01T00:00:00Z
	maxUnix = 253402300799 // 9999-12-31T23:59:59Z
)

// unixTime converts a NumericDate to a time.Time, clamping absurd values
// (exp: 1e300 is a legal claim) instead of overflowing int64.
func unixTime(sec float64) time.Time {
	sec = math.Max(minUnix, math.Min(maxUnix, sec))
	whole, frac := math.Modf(sec)
	return time.Unix(int64(whole), int64(frac*1e9)).UTC()
}
