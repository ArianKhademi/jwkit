package jwkit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// wantResult fails the test unless err matches want (nil meaning success).
func wantResult(t *testing.T, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("want token accepted, got %v", err)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error %v (%T) is not a *jwkit.Error", err, err)
	}
}

// splitToken returns the three segments of a well-formed token.
func splitToken(t *testing.T, token string) (header, payload, sig string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("test token has %d segments", len(parts))
	}
	return parts[0], parts[1], parts[2]
}

// hs256WithPublicKey mounts the classic algorithm-confusion attack: an HS256
// token whose HMAC secret is the issuer's RSA public key in PEM form, which
// the attacker knows because it is public.
func hs256WithPublicKey(k testKey) string {
	der, err := x509.MarshalPKIXPublicKey(&k.rsa.PublicKey)
	if err != nil {
		panic(err)
	}
	secret := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	input := b64([]byte(mustJSON(map[string]any{"alg": "HS256", "kid": k.kid, "typ": "JWT"}))) +
		"." + b64([]byte(mustJSON(validClaims())))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + b64(mac.Sum(nil))
}

// unsigned builds an "alg: none" token: valid claims, empty signature.
func unsigned(header map[string]any) string {
	return b64([]byte(mustJSON(header))) + "." + b64([]byte(mustJSON(validClaims()))) + "."
}

func TestVerify(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1, ecKey1, rsaSmall, ecP384)
	now := testNow.Unix()

	valid := rsaKey1.token()
	vh, vp, vs := splitToken(t, valid)
	validES := ecKey1.token()
	eh, ep, _ := splitToken(t, validES)

	tests := []struct {
		name  string
		token string
		want  error
		edit  func(*Config)
	}{
		// Accepted tokens.
		{name: "valid RS256", token: valid},
		{name: "valid ES256", token: validES},
		{name: "aud is an array containing the audience", token: rsaKey1.token(setClaim("aud", []any{"other", testAudience}))},
		{name: "aud array with non-string members", token: rsaKey1.token(setClaim("aud", []any{7, nil, testAudience}))},
		{name: "no iat, no nbf", token: rsaKey1.token(setClaim("iat", nil))},
		{name: "fractional exp", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"iss":"https://issuer.example","aud":"https://api.example","exp":1750000300.5}`)},
		{name: "exp inside the clock skew", token: rsaKey1.token(setClaim("exp", now-59))},
		{name: "nbf inside the clock skew", token: rsaKey1.token(setClaim("nbf", now+60))},
		{name: "iat inside the clock skew", token: rsaKey1.token(setClaim("iat", now+60))},
		{name: "unknown header members are ignored", token: rsaKey1.token(setHeader("x-custom", map[string]any{"a": 1}))},
		{name: "duplicate header member: the last one wins", token: rsaKey1.signRaw(`{"alg":"none","alg":"RS256","kid":"rsa-1"}`, mustJSON(validClaims()))},
		{name: "whitespace around the JSON is allowed", token: rsaKey1.signRaw(" {\"alg\":\"RS256\",\"kid\":\"rsa-1\"}\n", "\t"+mustJSON(validClaims())+" ")},
		{name: "huge exp", token: rsaKey1.token(setClaim("exp", 1e300))},
		{name: "claims named like JavaScript's Object.prototype members", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"__proto__":{"iss":"x"},"constructor":"x","iss":"https://issuer.example","aud":"https://api.example","exp":1750000300}`)},

		// Time-based claims.
		{name: "expired", token: rsaKey1.token(setClaim("exp", now-3600)), want: ErrExpired},
		{name: "expired exactly at the skew boundary", token: rsaKey1.token(setClaim("exp", now-60)), want: ErrExpired},
		{name: "exp underflows to zero", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"iss":"https://issuer.example","aud":"https://api.example","exp":1e-400}`), want: ErrExpired},
		{name: "nbf in the future", token: rsaKey1.token(setClaim("nbf", now+61)), want: ErrNotYetValid},
		{name: "iat in the future", token: rsaKey1.token(setClaim("iat", now+3600)), want: ErrNotYetValid},
		{name: "no skew: exp equal to now", token: rsaKey1.token(setClaim("exp", now)), want: ErrExpired, edit: func(c *Config) { c.ClockSkew = -1 }},
		{name: "no skew: exp one second ahead", token: rsaKey1.token(setClaim("exp", now+1)), edit: func(c *Config) { c.ClockSkew = -1 }},
		{name: "custom skew", token: rsaKey1.token(setClaim("exp", now-5)), want: ErrExpired, edit: func(c *Config) { c.ClockSkew = 5 * time.Second }},
		{name: "missing exp", token: rsaKey1.token(setClaim("exp", nil)), want: ErrMalformed},
		{name: "exp is a string", token: rsaKey1.token(setClaim("exp", "1750000300")), want: ErrMalformed},
		{name: "exp is beyond float64", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"iss":"https://issuer.example","aud":"https://api.example","exp":1e400}`), want: ErrMalformed},
		{name: "nbf is a string", token: rsaKey1.token(setClaim("nbf", "soon")), want: ErrMalformed},
		{name: "iat is null", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"iss":"https://issuer.example","aud":"https://api.example","exp":1750000300,"iat":null}`), want: ErrMalformed},

		// Issuer and audience.
		{name: "wrong issuer", token: rsaKey1.token(setClaim("iss", "https://evil.example")), want: ErrBadIssuer},
		{name: "missing issuer", token: rsaKey1.token(setClaim("iss", nil)), want: ErrBadIssuer},
		{name: "issuer is not a string", token: rsaKey1.token(setClaim("iss", []any{testIssuer})), want: ErrBadIssuer},
		{name: "issuer differs by a trailing slash", token: rsaKey1.token(setClaim("iss", testIssuer+"/")), want: ErrBadIssuer},
		{name: "wrong audience", token: rsaKey1.token(setClaim("aud", "https://other.example")), want: ErrBadAudience},
		{name: "missing audience", token: rsaKey1.token(setClaim("aud", nil)), want: ErrBadAudience},
		{name: "audience array without ours", token: rsaKey1.token(setClaim("aud", []any{"a", "b"})), want: ErrBadAudience},
		{name: "audience is a number", token: rsaKey1.token(setClaim("aud", 42)), want: ErrBadAudience},
		{name: "claims are not read from a __proto__ member", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"__proto__":{"iss":"https://issuer.example","aud":"https://api.example","exp":1750000300}}`), want: ErrBadIssuer},
		{name: "wrong issuer wins over expiry", token: rsaKey1.token(setClaim("iss", "x"), setClaim("exp", now-3600)), want: ErrBadIssuer},

		// Signature.
		{name: "tampered payload", token: vh + "." + b64([]byte(strings.Replace(mustJSON(validClaims()), "user-1", "admin", 1))) + "." + vs, want: ErrBadSignature},
		{name: "tampered signature", token: vh + "." + vp + "." + flipBit(t, vs), want: ErrBadSignature},
		{name: "signed by a different key under a published kid", token: rsaKey2.withKid("rsa-1").token(), want: ErrBadSignature},
		{name: "signature from another token", token: vh + "." + b64([]byte(mustJSON(map[string]any{"iss": testIssuer, "aud": testAudience, "exp": now + 900}))) + "." + vs, want: ErrBadSignature},
		{name: "empty signature", token: vh + "." + vp + ".", want: ErrBadSignature},
		{name: "ES256 header pointing at an RSA key", token: ecKey1.withKid("rsa-1").token(), want: ErrBadSignature},
		{name: "RS256 header pointing at an EC key", token: rsaKey1.withKid("ec-1").token(), want: ErrBadSignature},
		{name: "ES256 signature in DER form", token: eh + "." + ep + "." + b64(derSignature(ecKey1, eh+"."+ep)), want: ErrBadSignature},
		{name: "ES256 signature with an extra byte", token: eh + "." + ep + "." + b64(append([]byte{0}, ecKey1.signature(eh+"."+ep)...)), want: ErrBadSignature},
		{name: "tampered ES256 payload", token: eh + "." + b64([]byte(strings.Replace(mustJSON(validClaims()), "user-1", "admin", 1))) + "." + b64(ecKey1.signature(eh+"."+ep)), want: ErrBadSignature},
		{name: "embedded jwk header is not trusted", token: rsaKey2.withKid("rsa-1").token(setHeader("jwk", rsaKey2.jwk())), want: ErrBadSignature},

		// Key lookup.
		{name: "unknown kid", token: rsaKey2.token(), want: ErrUnknownKey},
		{name: "RSA key below 2048 bits is never loaded", token: rsaSmall.token(), want: ErrUnknownKey},
		{name: "P-384 key is never loaded", token: ecP384.token(), want: ErrUnknownKey},

		// Algorithms.
		{name: "alg none", token: unsigned(map[string]any{"alg": "none", "typ": "JWT"}), want: ErrUnsupportedAlg},
		{name: "alg none with a kid", token: unsigned(map[string]any{"alg": "none", "kid": "rsa-1"}), want: ErrUnsupportedAlg},
		{name: "alg None, mixed case", token: unsigned(map[string]any{"alg": "None", "kid": "rsa-1"}), want: ErrUnsupportedAlg},
		{name: "HS256 keyed with the RSA public key", token: hs256WithPublicKey(rsaKey1), want: ErrUnsupportedAlg},
		{name: "RS384", token: rsaKey1.token(setHeader("alg", "RS384")), want: ErrUnsupportedAlg},
		{name: "PS256", token: rsaKey1.token(setHeader("alg", "PS256")), want: ErrUnsupportedAlg},
		{name: "ES384", token: ecKey1.token(setHeader("alg", "ES384")), want: ErrUnsupportedAlg},
		{name: "alg in lower case", token: rsaKey1.token(setHeader("alg", "rs256")), want: ErrUnsupportedAlg},
		{name: "empty alg", token: rsaKey1.token(setHeader("alg", "")), want: ErrUnsupportedAlg},
		{name: "missing alg", token: rsaKey1.token(setHeader("alg", nil)), want: ErrMalformed},
		{name: "alg is not a string", token: rsaKey1.token(setHeader("alg", 256)), want: ErrMalformed},
		{name: "member names are case-sensitive", token: rsaKey1.signRaw(`{"ALG":"RS256","kid":"rsa-1"}`, mustJSON(validClaims())), want: ErrMalformed},

		{name: "alg is not read from a __proto__ member", token: rsaKey1.signRaw(`{"__proto__":{"alg":"RS256","kid":"rsa-1"}}`, mustJSON(validClaims())), want: ErrMalformed},

		// Header policy.
		{name: "missing kid", token: rsaKey1.token(setHeader("kid", nil)), want: ErrMalformed},
		{name: "empty kid", token: rsaKey1.token(setHeader("kid", "")), want: ErrMalformed},
		{name: "kid is not a string", token: rsaKey1.token(setHeader("kid", 1)), want: ErrMalformed},
		{name: "crit header", token: rsaKey1.token(setHeader("crit", []any{"exp"})), want: ErrMalformed},

		// Structure.
		{name: "empty token", token: "", want: ErrMalformed},
		{name: "one segment", token: "abc", want: ErrMalformed},
		{name: "two segments", token: vh + "." + vp, want: ErrMalformed},
		{name: "four segments", token: valid + ".abc", want: ErrMalformed},
		{name: "five segments, like a JWE", token: valid + ".abc.def", want: ErrMalformed},
		{name: "only dots", token: "..", want: ErrMalformed},
		{name: "leading space", token: " " + valid, want: ErrMalformed},
		{name: "trailing newline", token: valid + "\n", want: ErrMalformed},
		{name: "newline inside the header segment", token: vh[:10] + "\n" + vh[10:] + "." + vp + "." + vs, want: ErrMalformed},
		{name: "invalid character in the header", token: "!" + vh[1:] + "." + vp + "." + vs, want: ErrMalformed},
		{name: "invalid character in the payload", token: vh + "." + vp[:5] + "*" + vp[6:] + "." + vs, want: ErrMalformed},
		{name: "invalid character in the signature", token: vh + "." + vp + "." + vs[:5] + "~" + vs[6:], want: ErrMalformed},
		{name: "standard base64 alphabet", token: vh + "." + vp + "." + stdAlphabet(t, vs), want: ErrMalformed},
		{name: "padded base64", token: vh + "." + vp + "." + vs + "==", want: ErrMalformed},
		{name: "impossible base64 length", token: vh + "." + vp + "." + vs + "AAA", want: ErrMalformed}, // 345 characters: length mod 4 is 1
		{name: "non-canonical trailing bits in the signature", token: vh + "." + vp + "." + nonCanonical(t, vs), want: ErrMalformed},
		{name: "non-UTF-8 character in the token", token: vh + "." + vp + "é." + vs, want: ErrMalformed},
		{name: "header is not JSON", token: rsaKey1.signRaw(`not json`, mustJSON(validClaims())), want: ErrMalformed},
		{name: "header is a JSON array", token: rsaKey1.signRaw(`["RS256"]`, mustJSON(validClaims())), want: ErrMalformed},
		{name: "header is JSON null", token: rsaKey1.signRaw(`null`, mustJSON(validClaims())), want: ErrMalformed},
		{name: "empty header", token: "." + vp + "." + vs, want: ErrMalformed},
		{name: "payload is not JSON", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `{"iss":`), want: ErrMalformed},
		{name: "payload is a JSON string", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, `"claims"`), want: ErrMalformed},
		{name: "nested JWT: payload is a token, not claims", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1","cty":"JWT"}`, valid), want: ErrMalformed},
		{name: "payload has data after the object", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, mustJSON(validClaims())+`{}`), want: ErrMalformed},
		{name: "payload has a stray closing brace", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, mustJSON(validClaims())+`}`), want: ErrMalformed},
		{name: "payload is not UTF-8", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, "{\"iss\":\"\xff\"}"), want: ErrMalformed},
		{name: "payload starts with a byte order mark", token: rsaKey1.signRaw(`{"alg":"RS256","kid":"rsa-1"}`, "\xef\xbb\xbf"+mustJSON(validClaims())), want: ErrMalformed},

		// Size limit.
		{name: "oversized token", token: rsaKey1.token(setClaim("pad", strings.Repeat("a", 9000))), want: ErrMalformed},
		{name: "oversized token allowed by a higher limit", token: rsaKey1.token(setClaim("pad", strings.Repeat("a", 9000))), edit: func(c *Config) { c.MaxTokenBytes = 20000 }},
		{name: "exactly at the limit", token: valid, edit: func(c *Config) { c.MaxTokenBytes = len(valid) }},
		{name: "one byte over the limit", token: valid, want: ErrMalformed, edit: func(c *Config) { c.MaxTokenBytes = len(valid) - 1 }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var edits []func(*Config)
			if tc.edit != nil {
				edits = append(edits, tc.edit)
			}
			v := newTestVerifier(t, iss, newFakeClock(), edits...)
			_, err := v.Verify(context.Background(), tc.token)
			wantResult(t, err, tc.want)
		})
	}
}

// flipBit returns the base64url segment with one bit of its decoded bytes flipped.
func flipBit(t *testing.T, segment string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	return b64(raw)
}

// stdAlphabet re-encodes a segment with the non-URL-safe base64 alphabet,
// making sure the result really contains '+' or '/'.
func stdAlphabet(t *testing.T, segment string) string {
	t.Helper()
	out := strings.NewReplacer("-", "+", "_", "/").Replace(segment)
	if out == segment {
		return "+" + segment[1:]
	}
	return out
}

// nonCanonical changes only the unused trailing bits of the last character,
// producing a different string that a lenient decoder maps to the same bytes.
func nonCanonical(t *testing.T, segment string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(segment)%4 == 0 {
		t.Fatal("segment has no trailing bits to change")
	}
	last := strings.IndexByte(alphabet, segment[len(segment)-1])
	out := segment[:len(segment)-1] + string(alphabet[last|1])
	lenient, err := base64.RawURLEncoding.DecodeString(out)
	want, _ := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || string(lenient) != string(want) || out == segment {
		t.Fatal("failed to build a non-canonical encoding")
	}
	return out
}

// derSignature signs like a TLS stack would: ASN.1 DER instead of the fixed
// width r||s that JWS requires.
func derSignature(k testKey, signingInput string) []byte {
	raw := k.signature(signingInput)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]),
	})
	if err != nil {
		panic(err)
	}
	return der
}

func TestVerifyReturnsClaims(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	now := testNow.Unix()

	token := rsaKey1.token(
		setClaim("aud", []any{testAudience, "https://other.example"}),
		setClaim("nbf", now-10),
		setClaim("scope", "read:users write:users"),
		setClaim("scp", []any{"admin", 7}),
		setClaim("roles", []any{"editor"}),
		setClaim("big", json.Number("12345678901234567890")),
	)
	c, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != testIssuer || c.Subject != "user-1" {
		t.Errorf("issuer/subject = %q/%q", c.Issuer, c.Subject)
	}
	if got := strings.Join(c.Audience, ","); got != testAudience+",https://other.example" {
		t.Errorf("audience = %q", got)
	}
	if !c.ExpiresAt.Equal(testNow.Add(300*time.Second)) || !c.IssuedAt.Equal(testNow) || !c.NotBefore.Equal(testNow.Add(-10*time.Second)) {
		t.Errorf("times = exp %v, iat %v, nbf %v", c.ExpiresAt, c.IssuedAt, c.NotBefore)
	}
	if got := strings.Join(c.Scopes(), ","); got != "read:users,write:users,admin" {
		t.Errorf("scopes = %q", got)
	}
	if got := strings.Join(c.Strings("roles"), ","); got != "editor" {
		t.Errorf("roles = %q", got)
	}
	if c.Strings("sub-missing") != nil || c.Strings("exp") != nil {
		t.Error("Strings should be nil for absent or non-list claims")
	}
	// Large integers survive because numbers are kept as json.Number.
	if got := c.Raw["big"]; got != json.Number("12345678901234567890") {
		t.Errorf("big = %v (%T)", got, got)
	}

	// Optional claims stay at their zero value when absent.
	c, err = v.Verify(context.Background(), rsaKey1.token(setClaim("iat", nil), setClaim("sub", nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IssuedAt.IsZero() || !c.NotBefore.IsZero() || c.Subject != "" {
		t.Errorf("optional claims not zero: %+v", c)
	}
	// No scopes is an empty list, not nil: it must encode as [] in JSON.
	if got := mustJSON(c.Scopes()); got != "[]" {
		t.Errorf("Scopes() of a token without scopes encodes as %s", got)
	}

	// A NumericDate far outside what time.Time can represent is clamped.
	c, err = v.Verify(context.Background(), rsaKey1.token(setClaim("exp", 1e300), setClaim("iat", -1e300)))
	if err != nil {
		t.Fatal(err)
	}
	if c.ExpiresAt.Year() != 9999 || c.IssuedAt.Year() != 1 {
		t.Errorf("clamped years = %d, %d", c.ExpiresAt.Year(), c.IssuedAt.Year())
	}
}

// Headers that name a key location must never cause a request to it.
func TestKeyLocationHeadersAreIgnored(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	attacker := newFakeIssuer(t, rsaKey2, rsaKey2.withKid("rsa-1"))

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"legitimate token carrying jku and x5u", rsaKey1.token(setHeader("jku", attacker.url()), setHeader("x5u", attacker.url())), nil},
		{"attacker key, own kid, jku to attacker JWKS", rsaKey2.token(setHeader("jku", attacker.url())), ErrUnknownKey},
		{"attacker key, issuer's kid, jku to attacker JWKS", rsaKey2.withKid("rsa-1").token(setHeader("jku", attacker.url())), ErrBadSignature},
		{"attacker key, issuer's kid, x5u to attacker", rsaKey2.withKid("rsa-1").token(setHeader("x5u", attacker.url())), ErrBadSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestVerifier(t, iss, newFakeClock())
			_, err := v.Verify(context.Background(), tc.token)
			wantResult(t, err, tc.want)
		})
	}
	if n := attacker.hitCount(); n != 0 {
		t.Fatalf("the URL named in the token header was fetched %d times", n)
	}
}

func TestDecodeUnverified(t *testing.T) {
	// A token nobody could verify still decodes: that is the point, and the danger.
	header, payload, err := DecodeUnverified(unsigned(map[string]any{"alg": "none"}))
	if err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "none" || payload["iss"] != testIssuer {
		t.Errorf("header = %v, payload = %v", header, payload)
	}
	if _, _, err := DecodeUnverified("not-a-token"); !errors.Is(err, ErrMalformed) {
		t.Errorf("want ErrMalformed, got %v", err)
	}
}
