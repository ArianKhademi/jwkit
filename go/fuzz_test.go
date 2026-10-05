package jwkit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// The fuzzers are seeded with the conformance fixtures: tokens that are
// valid, tokens that are wrong in every way the suite knows about, and the
// keys and configuration they are meant to be verified with. The fixture keys
// are fixed, unlike the keys in helpers_test.go, which matters because the
// fuzzing engine runs workers in separate processes and replays its corpus
// across runs: a token must mean the same thing every time.
const fixturesPath = "../conformance/fixtures.json"

type conformanceFixtures struct {
	Config struct {
		Issuer        string `json:"issuer"`
		Audience      string `json:"audience"`
		Now           int64  `json:"now"`
		ClockSkewSec  int    `json:"clock_skew_sec"`
		MaxTokenBytes int    `json:"max_token_bytes"`
	} `json:"config"`
	JWKS struct {
		Keys []map[string]string `json:"keys"`
	} `json:"jwks"`
	RawJWKS json.RawMessage `json:"-"`
	Cases   []struct {
		Name   string `json:"name"`
		Token  string `json:"token"`
		Expect string `json:"expect"`
	} `json:"cases"`
}

func loadFixtures(tb testing.TB) *conformanceFixtures {
	tb.Helper()
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		tb.Skipf("conformance fixtures not available: %v", err)
	}
	var fx conformanceFixtures
	if err := json.Unmarshal(raw, &fx); err != nil {
		tb.Fatalf("%s: %v", fixturesPath, err)
	}
	var doc struct {
		JWKS json.RawMessage `json:"jwks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		tb.Fatal(err)
	}
	fx.RawJWKS = doc.JWKS
	return &fx
}

// seed adds every fixture token to the corpus, except those so far over the
// size limit that mutating them would only ever exercise the length check.
func (fx *conformanceFixtures) seed(f *testing.F) {
	for _, c := range fx.Cases {
		if len(c.Token) <= 2*DefaultMaxTokenBytes {
			f.Add(c.Token)
		}
	}
}

// FuzzParse checks the structural parser: whatever the input, it returns a
// token or ErrMalformed, never panics, and never accepts a token that has a
// second spelling.
func FuzzParse(f *testing.F) {
	loadFixtures(f).seed(f)
	for _, s := range []string{"", ".", "..", "...", "e30.e30.", "e30.e30.AA", "bnVsbA.e30.", "W10.e30.", "e30.IiI.", "e30.e30.A"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		p, err := parseToken(token, DefaultMaxTokenBytes)
		header, payload, publicErr := DecodeUnverified(token)

		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("parse failed with %v, want ErrMalformed", err)
			}
			if !errors.Is(publicErr, ErrMalformed) || header != nil || payload != nil {
				t.Fatalf("DecodeUnverified disagrees with parseToken: %v", publicErr)
			}
			return
		}

		// Everything below is what "structurally valid" promises to the
		// rest of the verifier.
		if publicErr != nil {
			t.Fatalf("DecodeUnverified rejected a token parseToken accepted: %v", publicErr)
		}
		if len(token) > DefaultMaxTokenBytes {
			t.Fatalf("accepted a %d-byte token", len(token))
		}
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("accepted a token with %d segments", len(parts))
		}
		if p.header == nil || p.payload == nil {
			t.Fatal("accepted a token whose header or payload is not an object")
		}
		if string(p.signingInput) != parts[0]+"."+parts[1] {
			t.Fatalf("signing input %q is not the first two segments", p.signingInput)
		}
		// Canonical encoding: decoding a segment and encoding it again must
		// give back the same characters, so no accepted token has a twin.
		for i, raw := range [][]byte{mustDecode(t, parts[0]), mustDecode(t, parts[1]), p.signature} {
			if base64.RawURLEncoding.EncodeToString(raw) != parts[i] {
				t.Fatalf("segment %d has a non-canonical encoding", i)
			}
		}
	})
}

func mustDecode(t *testing.T, segment string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("accepted segment does not decode: %v", err)
	}
	return b
}

// FuzzVerify checks the whole verifier against the fixture issuer: whatever
// the input, the result is a token's claims or one of the typed errors, never
// a panic, and a token is only ever accepted if an independent check of its
// signature and claims, written directly against the standard library,
// agrees.
func FuzzVerify(f *testing.F) {
	fx := loadFixtures(f)
	fx.seed(f)

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fx.RawJWKS)
	}))
	f.Cleanup(issuer.Close)

	v, err := NewVerifier(Config{
		Issuer:        fx.Config.Issuer,
		Audience:      fx.Config.Audience,
		JWKSURL:       issuer.URL,
		ClockSkew:     time.Duration(fx.Config.ClockSkewSec) * time.Second,
		MaxTokenBytes: fx.Config.MaxTokenBytes,
		Now:           func() time.Time { return time.Unix(fx.Config.Now, 0) },
	})
	if err != nil {
		f.Fatal(err)
	}
	oracle := newOracle(f, fx)

	// The fuzzer cannot forge a signature, so the only tokens that should
	// ever be accepted are the fixtures' own valid ones. Anything else that
	// gets through is a second spelling of a signed token: malleability.
	known := map[string]bool{}
	for _, c := range fx.Cases {
		if c.Expect == "ok" {
			known[c.Token] = true
		}
	}

	typed := map[string]bool{
		ErrMalformed.Name: true, ErrUnsupportedAlg.Name: true, ErrUnknownKey.Name: true, ErrBadSignature.Name: true,
		ErrBadIssuer.Name: true, ErrBadAudience.Name: true, ErrExpired.Name: true, ErrNotYetValid.Name: true,
	}

	f.Fuzz(func(t *testing.T, token string) {
		claims, err := v.Verify(context.Background(), token)
		if err != nil {
			if claims != nil {
				t.Fatal("returned claims together with an error")
			}
			if name := ErrorName(err); !typed[name] {
				t.Fatalf("verification failed with %v (%T), which is not a token error", err, err)
			}
			return
		}
		if claims == nil {
			t.Fatal("accepted a token but returned no claims")
		}
		if why := oracle.check(token); why != "" {
			t.Fatalf("accepted a token the independent check rejects: %s", why)
		}
		if !known[token] {
			t.Fatalf("accepted a token that is not one of the signed fixtures: %q", token)
		}
	})
}

// oracle re-derives "should this token be accepted?" with none of the code
// under test: its own lenient parsing and crypto/rsa and crypto/ecdsa.
type oracle struct {
	rsaKeys map[string]*rsa.PublicKey
	ecKeys  map[string]*ecdsa.PublicKey
	fx      *conformanceFixtures
}

func newOracle(tb testing.TB, fx *conformanceFixtures) *oracle {
	tb.Helper()
	o := &oracle{rsaKeys: map[string]*rsa.PublicKey{}, ecKeys: map[string]*ecdsa.PublicKey{}, fx: fx}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			tb.Fatal(err)
		}
		return b
	}
	for _, k := range fx.JWKS.Keys {
		// Only the two keys the issuer actually signs valid tokens with;
		// the other published keys are ones a verifier must refuse.
		switch k["kid"] {
		case "rsa-current":
			o.rsaKeys[k["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(dec(k["n"])), E: int(new(big.Int).SetBytes(dec(k["e"])).Int64())}
		case "ec-current":
			point := append([]byte{4}, append(dec(k["x"]), dec(k["y"])...)...)
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
			if err != nil {
				tb.Fatal(err)
			}
			o.ecKeys[k["kid"]] = pub
		}
	}
	if len(o.rsaKeys) != 1 || len(o.ecKeys) != 1 {
		tb.Fatal("fixture JWKS does not contain rsa-current and ec-current")
	}
	return o
}

// check returns "" if the token deserves to be accepted, or the reason it does not.
func (o *oracle) check(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "not three segments"
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(headerJSON, &header) != nil {
		return "undecodable header"
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "undecodable signature"
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	if key, ok := o.rsaKeys[header.Kid]; ok {
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
			return "RSA signature does not verify"
		}
	} else if key, ok := o.ecKeys[header.Kid]; ok {
		if len(sig) != 64 || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return "ECDSA signature does not verify"
		}
	} else {
		return "kid is not a key the issuer signs with"
	}

	var claims struct {
		Iss string   `json:"iss"`
		Aud any      `json:"aud"`
		Exp *float64 `json:"exp"`
		Nbf *float64 `json:"nbf"`
		Iat *float64 `json:"iat"`
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(payloadJSON, &claims) != nil {
		return "undecodable payload"
	}
	if claims.Iss != o.fx.Config.Issuer {
		return "wrong issuer"
	}
	audOK := false
	switch aud := claims.Aud.(type) {
	case string:
		audOK = aud == o.fx.Config.Audience
	case []any:
		for _, a := range aud {
			audOK = audOK || a == o.fx.Config.Audience
		}
	}
	if !audOK {
		return "wrong audience"
	}
	now, skew := float64(o.fx.Config.Now), float64(o.fx.Config.ClockSkewSec)
	if claims.Exp == nil || now >= *claims.Exp+skew {
		return "expired or no exp"
	}
	if (claims.Nbf != nil && *claims.Nbf > now+skew) || (claims.Iat != nil && *claims.Iat > now+skew) {
		return "not yet valid"
	}
	return ""
}

// The oracle is itself code that could be wrong. Run it over the fixtures:
// it must accept exactly the cases the fixtures mark "ok".
func TestOracleAgreesWithFixtures(t *testing.T) {
	fx := loadFixtures(t)
	o := newOracle(t, fx)
	for _, c := range fx.Cases {
		why := o.check(c.Token)
		if (why == "") != (c.Expect == "ok") {
			// The oracle is deliberately lenient about structure, so it may
			// accept a few tokens jwkit rejects as malformed; it must never
			// reject one jwkit should accept.
			if c.Expect == "ok" {
				t.Errorf("%s: oracle rejects a valid token: %s", c.Name, why)
			} else if c.Expect != ErrMalformed.Name && c.Expect != ErrUnsupportedAlg.Name {
				t.Errorf("%s: oracle accepts a token that should fail with %s", c.Name, c.Expect)
			}
		}
	}
}

// The fixtures must hold for the verifier configured exactly as the fuzzer
// configures it; this is the Go half of the conformance suite run as a unit
// test, so `go test` alone already proves it.
func TestConformanceFixtures(t *testing.T) {
	fx := loadFixtures(t)
	if len(fx.Cases) < 40 {
		t.Fatalf("only %d conformance cases", len(fx.Cases))
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fx.RawJWKS)
	}))
	defer issuer.Close()

	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			v, err := NewVerifier(Config{
				Issuer:        fx.Config.Issuer,
				Audience:      fx.Config.Audience,
				JWKSURL:       issuer.URL,
				ClockSkew:     time.Duration(fx.Config.ClockSkewSec) * time.Second,
				MaxTokenBytes: fx.Config.MaxTokenBytes,
				Now:           func() time.Time { return time.Unix(fx.Config.Now, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			got := "ok"
			if _, err := v.Verify(context.Background(), c.Token); err != nil {
				got = ErrorName(err)
			}
			if got != c.Expect {
				t.Errorf("got %s, want %s", got, c.Expect)
			}
		})
	}
}
