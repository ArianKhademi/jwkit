package jwkit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newGinServer serves a real Gin router over HTTP with the middleware
// installed and two routes behind it.
func newGinServer(t *testing.T, v *Verifier, opts ...MiddlewareOptions) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(GinMiddleware(v, opts...))
	r.GET("/me", func(c *gin.Context) {
		claims := GinClaims(c)
		c.JSON(http.StatusOK, gin.H{"sub": claims.Subject, "scopes": claims.Scopes()})
	})
	r.GET("/public/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"authenticated": GinClaims(c) != nil})
	})
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv
}

type response struct {
	status    int
	challenge string
	body      map[string]any
	raw       string
}

func get(t *testing.T, url string, edit ...func(*http.Request)) response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edit {
		e(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	out := response{status: resp.StatusCode, challenge: resp.Header.Get("WWW-Authenticate"), raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body) // not every route answers in JSON
	return out
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func TestGinMiddleware(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1, ecKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	srv := newGinServer(t, v)
	now := testNow.Unix()

	valid := rsaKey1.token()
	vh, _, vs := splitToken(t, valid)
	tampered := vh + "." + b64([]byte(strings.Replace(mustJSON(validClaims()), "user-1", "admin", 1))) + "." + vs

	t.Run("valid token reaches the handler with its claims", func(t *testing.T) {
		for _, token := range []string{valid, ecKey1.token()} {
			res := get(t, srv.URL+"/me", bearer(token))
			if res.status != http.StatusOK || res.body["sub"] != "user-1" {
				t.Fatalf("status %d, body %s", res.status, res.raw)
			}
			if res.challenge != "" {
				t.Errorf("unexpected challenge %q", res.challenge)
			}
		}
	})

	t.Run("the Bearer scheme is case-insensitive", func(t *testing.T) {
		res := get(t, srv.URL+"/me", func(r *http.Request) { r.Header.Set("Authorization", "bearer  "+valid+" ") })
		if res.status != http.StatusOK {
			t.Fatalf("status %d, body %s", res.status, res.raw)
		}
	})

	rejected := []struct {
		name      string
		edit      func(*http.Request)
		status    int
		wantError string
		challenge string
	}{
		{"no Authorization header", func(*http.Request) {}, 401, "ErrMissingToken", "Bearer"},
		{"another auth scheme", func(r *http.Request) { r.SetBasicAuth("user", "pass") }, 401, "ErrMissingToken", "Bearer"},
		{"scheme without a token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer") }, 401, "ErrMissingToken", "Bearer"},
		{"scheme with a blank token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer   ") }, 401, "ErrMissingToken", "Bearer"},
		{"expired token", bearer(rsaKey1.token(setClaim("exp", now-3600))), 401, "ErrExpired", `Bearer error="invalid_token", error_description="ErrExpired"`},
		{"wrong audience", bearer(rsaKey1.token(setClaim("aud", "https://other.example"))), 401, "ErrBadAudience", `Bearer error="invalid_token", error_description="ErrBadAudience"`},
		{"wrong issuer", bearer(rsaKey1.token(setClaim("iss", "https://evil.example"))), 401, "ErrBadIssuer", `Bearer error="invalid_token", error_description="ErrBadIssuer"`},
		{"tampered token", bearer(tampered), 401, "ErrBadSignature", `Bearer error="invalid_token", error_description="ErrBadSignature"`},
		{"not yet valid", bearer(rsaKey1.token(setClaim("nbf", now+3600))), 401, "ErrNotYetValid", `Bearer error="invalid_token", error_description="ErrNotYetValid"`},
		{"unknown key", bearer(rsaKey2.token()), 401, "ErrUnknownKey", `Bearer error="invalid_token", error_description="ErrUnknownKey"`},
		{"alg none", bearer(unsigned(map[string]any{"alg": "none"})), 401, "ErrUnsupportedAlg", `Bearer error="invalid_token", error_description="ErrUnsupportedAlg"`},
		{"HS256 confusion", bearer(hs256WithPublicKey(rsaKey1)), 401, "ErrUnsupportedAlg", `Bearer error="invalid_token", error_description="ErrUnsupportedAlg"`},
		{"garbage", bearer("not.a.token"), 401, "ErrMalformed", `Bearer error="invalid_token", error_description="ErrMalformed"`},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			res := get(t, srv.URL+"/me", tc.edit)
			if res.status != tc.status {
				t.Errorf("status = %d, want %d", res.status, tc.status)
			}
			// The body is exactly {"error": "<name>"}: no detail leaks.
			if len(res.body) != 1 || res.body["error"] != tc.wantError {
				t.Errorf("body = %s, want error %q", res.raw, tc.wantError)
			}
			if res.challenge != tc.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", res.challenge, tc.challenge)
			}
		})
	}
}

func TestGinMiddlewareScopesAndRoles(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())

	tests := []struct {
		name      string
		opts      MiddlewareOptions
		token     string
		status    int
		challenge string
	}{
		{
			name:   "all required scopes present in scope",
			opts:   MiddlewareOptions{RequiredScopes: []string{"read:users", "write:users"}},
			token:  rsaKey1.token(setClaim("scope", "write:users openid read:users")),
			status: 200,
		},
		{
			name:   "scopes in the scp array",
			opts:   MiddlewareOptions{RequiredScopes: []string{"read:users"}},
			token:  rsaKey1.token(setClaim("scp", []any{"read:users"})),
			status: 200,
		},
		{
			name:      "one required scope missing",
			opts:      MiddlewareOptions{RequiredScopes: []string{"read:users", "write:users"}},
			token:     rsaKey1.token(setClaim("scope", "read:users")),
			status:    403,
			challenge: `Bearer error="insufficient_scope", error_description="ErrInsufficientScope", scope="read:users write:users"`,
		},
		{
			name:      "no scope claim at all",
			opts:      MiddlewareOptions{RequiredScopes: []string{"read:users"}},
			token:     rsaKey1.token(),
			status:    403,
			challenge: `Bearer error="insufficient_scope", error_description="ErrInsufficientScope", scope="read:users"`,
		},
		{
			name:      "a scope is not matched as a substring",
			opts:      MiddlewareOptions{RequiredScopes: []string{"read"}},
			token:     rsaKey1.token(setClaim("scope", "read:users")),
			status:    403,
			challenge: `Bearer error="insufficient_scope", error_description="ErrInsufficientScope", scope="read"`,
		},
		{
			name:   "required role present",
			opts:   MiddlewareOptions{RequiredRoles: []string{"admin"}},
			token:  rsaKey1.token(setClaim("roles", []any{"editor", "admin"})),
			status: 200,
		},
		{
			name:      "required role missing",
			opts:      MiddlewareOptions{RequiredRoles: []string{"admin"}},
			token:     rsaKey1.token(setClaim("roles", []any{"editor"})),
			status:    403,
			challenge: `Bearer error="insufficient_scope", error_description="ErrInsufficientScope"`,
		},
		{
			name:   "roles under a custom claim name",
			opts:   MiddlewareOptions{RequiredRoles: []string{"admin"}, RolesClaim: "https://example.com/roles"},
			token:  rsaKey1.token(setClaim("https://example.com/roles", []any{"admin"})),
			status: 200,
		},
		{
			name:      "custom roles claim does not fall back to roles",
			opts:      MiddlewareOptions{RequiredRoles: []string{"admin"}, RolesClaim: "groups"},
			token:     rsaKey1.token(setClaim("roles", []any{"admin"})),
			status:    403,
			challenge: `Bearer error="insufficient_scope", error_description="ErrInsufficientScope"`,
		},
		{
			name:      "scope satisfied but role missing",
			opts:      MiddlewareOptions{RequiredScopes: []string{"read:users"}, RequiredRoles: []string{"admin"}},
			token:     rsaKey1.token(setClaim("scope", "read:users")),
			status:    403,
			challenge: `Bearer error="insufficient_scope", error_description="ErrInsufficientScope", scope="read:users"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newGinServer(t, v, tc.opts)
			res := get(t, srv.URL+"/me", bearer(tc.token))
			if res.status != tc.status {
				t.Fatalf("status = %d, want %d (body %s)", res.status, tc.status, res.raw)
			}
			if res.challenge != tc.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", res.challenge, tc.challenge)
			}
			if tc.status == 403 && res.body["error"] != "ErrInsufficientScope" {
				t.Errorf("body = %s", res.raw)
			}
		})
	}
}

func TestGinMiddlewareTokenExtractors(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	token := rsaKey1.token()

	t.Run("cookie", func(t *testing.T) {
		srv := newGinServer(t, v, MiddlewareOptions{TokenExtractor: CookieToken("session")})
		withCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "session", Value: token}) }
		if res := get(t, srv.URL+"/me", withCookie); res.status != 200 {
			t.Fatalf("status %d, body %s", res.status, res.raw)
		}
		// The Authorization header is no longer consulted.
		if res := get(t, srv.URL+"/me", bearer(token)); res.status != 401 || res.body["error"] != "ErrMissingToken" {
			t.Fatalf("status %d, body %s", res.status, res.raw)
		}
	})

	t.Run("custom header", func(t *testing.T) {
		srv := newGinServer(t, v, MiddlewareOptions{TokenExtractor: HeaderToken("X-Auth-Token")})
		if res := get(t, srv.URL+"/me", func(r *http.Request) { r.Header.Set("X-Auth-Token", token) }); res.status != 200 {
			t.Fatalf("status %d, body %s", res.status, res.raw)
		}
		if res := get(t, srv.URL+"/me"); res.status != 401 || res.body["error"] != "ErrMissingToken" {
			t.Fatalf("status %d, body %s", res.status, res.raw)
		}
	})

	t.Run("custom function", func(t *testing.T) {
		srv := newGinServer(t, v, MiddlewareOptions{TokenExtractor: func(r *http.Request) string { return r.URL.Query().Get("access_token") }})
		if res := get(t, srv.URL+"/me?access_token="+token); res.status != 200 {
			t.Fatalf("status %d, body %s", res.status, res.raw)
		}
	})
}

func TestGinMiddlewareSkipPaths(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	v := newTestVerifier(t, iss, newFakeClock())
	srv := newGinServer(t, v, MiddlewareOptions{SkipPaths: []string{"/healthz", "/public/*"}})

	if res := get(t, srv.URL+"/healthz"); res.status != 200 || res.raw != "ok" {
		t.Errorf("exact skip path: status %d, body %q", res.status, res.raw)
	}
	// Skipped means skipped: even a valid token is not looked at.
	res := get(t, srv.URL+"/public/ping", bearer(rsaKey1.token()))
	if res.status != 200 || res.body["authenticated"] != false {
		t.Errorf("prefix skip path: status %d, body %s", res.status, res.raw)
	}
	if res := get(t, srv.URL+"/me"); res.status != 401 {
		t.Errorf("unlisted path: status %d", res.status)
	}
	// An exact entry is not a prefix.
	if res := get(t, srv.URL+"/healthz/deep"); res.status != 401 {
		t.Errorf("/healthz/deep: status %d, want 401", res.status)
	}
	wantHits(t, iss, 0)
}

func TestGinMiddlewareWhenJWKSIsDown(t *testing.T) {
	iss := newFakeIssuer(t, rsaKey1)
	iss.setStatus(http.StatusInternalServerError)
	v := newTestVerifier(t, iss, newFakeClock())
	srv := newGinServer(t, v)

	res := get(t, srv.URL+"/me", bearer(rsaKey1.token()))
	if res.status != http.StatusServiceUnavailable || res.body["error"] != "ErrJWKSUnavailable" {
		t.Fatalf("status %d, body %s", res.status, res.raw)
	}
	if res.challenge != "" {
		t.Errorf("a 503 should carry no challenge, got %q", res.challenge)
	}
}
