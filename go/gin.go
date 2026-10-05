package jwkit

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// GinClaimsKey is the gin.Context key under which GinMiddleware stores the
// verified *Claims. Prefer GinClaims over reading it directly.
const GinClaimsKey = "jwkit.claims"

// TokenExtractor finds the token on a request. It returns "" when the request
// carries none.
type TokenExtractor func(*http.Request) string

// MiddlewareOptions customises GinMiddleware. The zero value protects every
// route and reads the token from the Authorization header.
type MiddlewareOptions struct {
	// RequiredScopes must all be present in the token's scope or scp claim.
	RequiredScopes []string
	// RequiredRoles must all be present in the claim named by RolesClaim.
	RequiredRoles []string
	// RolesClaim is the claim that lists roles, as a JSON array or a
	// space-delimited string. Default "roles".
	RolesClaim string
	// TokenExtractor overrides where the token is read from. Default BearerToken.
	TokenExtractor TokenExtractor
	// SkipPaths lists request paths that bypass authentication entirely. An
	// entry matches the path exactly, or as a prefix if it ends in "*"
	// ("/public/*").
	SkipPaths []string
}

// BearerToken extracts the token from "Authorization: Bearer <token>". The
// scheme is matched case-insensitively, as RFC 9110 requires.
func BearerToken(r *http.Request) string {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.Trim(token, " ")
}

// CookieToken returns an extractor that reads the token from the named cookie.
func CookieToken(name string) TokenExtractor {
	return func(r *http.Request) string {
		c, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return c.Value
	}
}

// HeaderToken returns an extractor that reads the token from the named
// header, verbatim (for gateways that forward it as, say, X-Auth-Token).
func HeaderToken(name string) TokenExtractor {
	return func(r *http.Request) string { return r.Header.Get(name) }
}

// GinMiddleware returns Gin middleware that authenticates requests with v.
//
// On success the verified claims are stored on the context (see GinClaims)
// and the next handler runs. On failure the request is aborted with a JSON
// body {"error": "<error name>"} and:
//
//   - 401 and a WWW-Authenticate: Bearer challenge for a missing or invalid token
//   - 403 when the token is valid but lacks a required scope or role
//   - 503 when the issuer's keys cannot be fetched, since that is not the
//     client's fault and the same token may succeed on retry
//
// At most one MiddlewareOptions may be passed.
func GinMiddleware(v *Verifier, opts ...MiddlewareOptions) gin.HandlerFunc {
	var o MiddlewareOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.TokenExtractor == nil {
		o.TokenExtractor = BearerToken
	}
	if o.RolesClaim == "" {
		o.RolesClaim = "roles"
	}

	return func(c *gin.Context) {
		if skipped(o.SkipPaths, c.Request.URL.Path) {
			c.Next()
			return
		}
		token := o.TokenExtractor(c.Request)
		if token == "" {
			reject(c, ErrMissingToken, o)
			return
		}
		claims, err := v.Verify(c.Request.Context(), token)
		if err != nil {
			reject(c, err, o)
			return
		}
		if !containsAll(claims.Scopes(), o.RequiredScopes) || !containsAll(claims.Strings(o.RolesClaim), o.RequiredRoles) {
			reject(c, ErrInsufficientScope, o)
			return
		}
		c.Set(GinClaimsKey, claims)
		c.Next()
	}
}

// GinClaims returns the claims GinMiddleware verified for this request, or
// nil if the middleware did not run or the path was skipped.
func GinClaims(c *gin.Context) *Claims {
	v, _ := c.Get(GinClaimsKey)
	claims, _ := v.(*Claims)
	return claims
}

func skipped(patterns []string, path string) bool {
	for _, p := range patterns {
		if prefix, isPrefix := strings.CutSuffix(p, "*"); isPrefix {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if p == path {
			return true
		}
	}
	return false
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !contains(have, w) {
			return false
		}
	}
	return true
}

// reject aborts the request with the status, challenge and body for err.
// Only the error's stable name is sent to the client; the detail may describe
// the token or the key set and stays in the server's hands.
func reject(c *gin.Context, err error, o MiddlewareOptions) {
	name := ErrorName(err)
	status := http.StatusUnauthorized
	// Challenge formats follow RFC 6750 section 3.
	challenge := `Bearer error="invalid_token", error_description="` + name + `"`
	switch name {
	case ErrMissingToken.Name:
		// No credentials at all: RFC 6750 says to send no error code.
		challenge = "Bearer"
	case ErrInsufficientScope.Name:
		status = http.StatusForbidden
		challenge = `Bearer error="insufficient_scope", error_description="` + name + `"`
		if len(o.RequiredScopes) > 0 {
			challenge += `, scope="` + strings.Join(o.RequiredScopes, " ") + `"`
		}
	case ErrJWKSUnavailable.Name:
		status = http.StatusServiceUnavailable
		challenge = ""
	}
	if challenge != "" {
		c.Header("WWW-Authenticate", challenge)
	}
	c.AbortWithStatusJSON(status, gin.H{"error": name})
}
