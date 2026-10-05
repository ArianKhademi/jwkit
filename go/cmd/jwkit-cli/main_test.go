package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

// The CLI is tested with the conformance fixtures: fixed keys, fixed tokens,
// and a fixed instant to verify them at, which the -at flag supplies.
type fixtures struct {
	Config struct {
		Issuer   string `json:"issuer"`
		Audience string `json:"audience"`
		Now      int64  `json:"now"`
	} `json:"config"`
	JWKS  json.RawMessage `json:"jwks"`
	Cases []struct {
		Name   string `json:"name"`
		Token  string `json:"token"`
		Expect string `json:"expect"`
	} `json:"cases"`
}

func loadFixtures(t *testing.T) (fx fixtures, jwksURL string) {
	t.Helper()
	raw, err := os.ReadFile("../../../conformance/fixtures.json")
	if err != nil {
		t.Skipf("conformance fixtures not available: %v", err)
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fx.JWKS)
	}))
	t.Cleanup(srv.Close)
	return fx, srv.URL
}

func (fx fixtures) token(t *testing.T, name string) string {
	t.Helper()
	for _, c := range fx.Cases {
		if c.Name == name {
			return c.Token
		}
	}
	t.Fatalf("no fixture named %q", name)
	return ""
}

// cli runs the command and returns its exit code and output streams.
func cli(stdin string, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVerifyAgreesWithEveryFixture(t *testing.T) {
	fx, jwksURL := loadFixtures(t)
	at := strconv.FormatInt(fx.Config.Now, 10)

	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			code, stdout, stderr := cli(c.Token, "verify", "-issuer", fx.Config.Issuer, "-audience", fx.Config.Audience, "-jwks-url", jwksURL, "-at", at)
			// The report echoes numbers exactly as the token wrote them, and
			// one fixture's exp is 1e400, so decode numbers without
			// converting them to float64.
			var r report
			dec := json.NewDecoder(strings.NewReader(stdout))
			dec.UseNumber()
			if err := dec.Decode(&r); err != nil {
				t.Fatalf("output is not a JSON report: %v\n%s%s", err, stdout, stderr)
			}

			// Surrounding whitespace is stripped from the input, so the two
			// fixtures that are nothing but a valid token plus whitespace
			// are, for the CLI, valid tokens.
			want := c.Expect
			if c.Name == "leading-space" || c.Name == "trailing-newline" {
				want = "ok"
			}

			if want == "ok" {
				if code != 0 || !r.Valid || r.Error != "" {
					t.Fatalf("exit %d, report %+v; want a valid token", code, r)
				}
				if r.Claims["iss"] != fx.Config.Issuer {
					t.Errorf("claims not reported: %v", r.Claims)
				}
				return
			}
			if code != 1 || r.Valid || r.Error != want {
				t.Fatalf("exit %d, report %+v; want error %s", code, r, want)
			}
			// A rejected token is still shown whenever it parses, and it
			// never parses when the verdict is ErrMalformed for structure.
			if r.Error != "ErrMalformed" && r.Header == nil {
				t.Errorf("rejected with %s but the header was not shown", r.Error)
			}
		})
	}
}

func TestVerifyOptions(t *testing.T) {
	fx, jwksURL := loadFixtures(t)
	base := []string{"verify", "-issuer", fx.Config.Issuer, "-audience", fx.Config.Audience, "-jwks-url", jwksURL}
	valid := fx.token(t, "valid-rs256")
	withinSkew := fx.token(t, "valid-exp-within-skew") // expired 59 s before the fixture instant

	t.Run("a pasted token with a trailing newline", func(t *testing.T) {
		if code, _, stderr := cli(valid+"\n", append(base, "-at", strconv.FormatInt(fx.Config.Now, 10))...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})

	t.Run("-at accepts RFC 3339", func(t *testing.T) {
		code, stdout, _ := cli(valid, append(base, "-at", "2025-06-15T15:06:40Z")...)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stdout)
		}
	})

	t.Run("without -at the real clock is used", func(t *testing.T) {
		// The fixtures were minted for an instant in 2025.
		code, stdout, _ := cli(valid, base...)
		if code != 1 || !strings.Contains(stdout, `"error": "ErrExpired"`) || !strings.Contains(stdout, `"detail": "token expired at`) {
			t.Fatalf("exit %d: %s", code, stdout)
		}
	})

	t.Run("-skew 0 means no tolerance", func(t *testing.T) {
		at := strconv.FormatInt(fx.Config.Now, 10)
		if code, _, _ := cli(withinSkew, append(base, "-at", at)...); code != 0 {
			t.Fatal("default skew should accept the token")
		}
		code, stdout, _ := cli(withinSkew, append(base, "-at", at, "-skew", "0")...)
		if code != 1 || !strings.Contains(stdout, "ErrExpired") {
			t.Fatalf("exit %d: %s", code, stdout)
		}
		if code, _, _ := cli(withinSkew, append(base, "-at", at, "-skew", "5m")...); code != 0 {
			t.Fatal("a 5 minute skew should accept the token")
		}
	})

	t.Run("an unreachable JWKS is reported, with a warning", func(t *testing.T) {
		code, stdout, stderr := cli(valid, "verify", "-issuer", fx.Config.Issuer, "-audience", fx.Config.Audience, "-jwks-url", "http://127.0.0.1:1/jwks")
		if code != 1 || !strings.Contains(stdout, "ErrJWKSUnavailable") || !strings.Contains(stderr, "warning:") {
			t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
	})
}

func TestVerifyWithDiscovery(t *testing.T) {
	fx, _ := loadFixtures(t)
	// An issuer that is its own discovery endpoint. The fixture tokens name a
	// different issuer, so the verdict is ErrBadIssuer: which proves that
	// the keys were found (the signature check passed) through discovery.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/keys"})
			return
		}
		_, _ = w.Write(fx.JWKS)
	}))
	defer srv.Close()

	code, stdout, _ := cli(fx.token(t, "valid-rs256"), "verify", "-issuer", srv.URL, "-audience", fx.Config.Audience)
	if code != 1 || !strings.Contains(stdout, `"error": "ErrBadIssuer"`) {
		t.Fatalf("exit %d: %s", code, stdout)
	}
}

func TestDecode(t *testing.T) {
	fx, _ := loadFixtures(t)

	// Decoding needs no keys and passes no judgement: an alg-none token decodes.
	code, stdout, stderr := cli(fx.token(t, "alg-none")+"\n", "decode")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		Header  map[string]any `json:"header"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Header["alg"] != "none" || out.Payload["iss"] != fx.Config.Issuer {
		t.Errorf("decoded %+v", out)
	}
	if !strings.Contains(stderr, "NOT verified") {
		t.Errorf("decode must say it did not verify; stderr: %q", stderr)
	}

	code, stdout, stderr = cli("not-a-token", "decode")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "ErrMalformed") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"no command", nil, "usage:"},
		{"unknown command", []string{"sign"}, `unknown command "sign"`},
		{"unknown flag", []string{"verify", "-nope"}, "flag provided but not defined"},
		{"missing issuer", []string{"verify", "-audience", "a", "-jwks-url", "https://x.example/keys"}, "Config.Issuer is required"},
		{"missing audience", []string{"verify", "-issuer", "https://x.example", "-jwks-url", "https://x.example/keys"}, "Config.Audience is required"},
		{"no JWKS URL and a non-URL issuer", []string{"verify", "-issuer", "x", "-audience", "a"}, "cannot be used for discovery"},
		{"bad -at", []string{"verify", "-issuer", "https://x.example", "-audience", "a", "-at", "yesterday"}, "neither Unix seconds nor an RFC 3339 time"},
		{"bad -skew", []string{"verify", "-skew", "soon"}, "invalid value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := cli("", tc.args...)
			if code != 2 || stdout != "" || !strings.Contains(stderr, tc.wantStderr) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and %q", code, stdout, stderr, tc.wantStderr)
			}
		})
	}

	if code, stdout, _ := cli("", "help"); code != 0 || !strings.Contains(stdout, "usage:") {
		t.Errorf("help: exit %d, stdout %q", code, stdout)
	}
}

func TestUnreadableInput(t *testing.T) {
	broken := iotest.ErrReader(errors.New("disk on fire"))
	for _, args := range [][]string{
		{"decode"},
		{"verify", "-issuer", "https://x.example", "-audience", "a", "-jwks-url", "https://x.example/keys"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, broken, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "disk on fire") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errOut.String())
		}
	}
}
