package jwkit

import (
	"errors"
	"fmt"
)

// Error is the only error type returned by token verification.
//
// Name is the stable contract. The TypeScript package raises errors with the
// same names, and the conformance suite compares the two implementations by
// name. Detail is for humans and logs; it may change between releases and
// must not be parsed.
type Error struct {
	Name   string
	Detail string
	cause  error
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "jwkit: " + e.Name
	}
	return "jwkit: " + e.Name + ": " + e.Detail
}

// Is reports whether target is a jwkit error with the same Name. It lets
// callers write errors.Is(err, jwkit.ErrExpired) even though the error they
// hold is a copy of the sentinel carrying per-token detail.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Name == e.Name
}

// Unwrap returns the underlying cause, if any (for example the network error
// behind ErrJWKSUnavailable).
func (e *Error) Unwrap() error { return e.cause }

// Verification failures. The first seven are the core contract shared with
// the TypeScript package; ErrNotYetValid covers nbf/iat in the future, which
// the core seven have no name for.
var (
	// ErrMalformed: the token is not a well-formed compact JWS carrying a JWT
	// (segment count, base64url, JSON, missing kid or exp, oversized, ...).
	ErrMalformed = &Error{Name: "ErrMalformed"}
	// ErrUnsupportedAlg: the header names any algorithm other than RS256 or
	// ES256. This includes "none" and every HMAC algorithm.
	ErrUnsupportedAlg = &Error{Name: "ErrUnsupportedAlg"}
	// ErrUnknownKey: no key in the issuer's JWKS has the token's kid.
	ErrUnknownKey = &Error{Name: "ErrUnknownKey"}
	// ErrBadSignature: the signature does not verify with the key the kid
	// refers to, or that key belongs to a different algorithm.
	ErrBadSignature = &Error{Name: "ErrBadSignature"}
	// ErrBadIssuer: iss is missing or differs from the configured issuer.
	ErrBadIssuer = &Error{Name: "ErrBadIssuer"}
	// ErrBadAudience: aud is missing or does not contain the configured audience.
	ErrBadAudience = &Error{Name: "ErrBadAudience"}
	// ErrExpired: exp (plus clock skew) is not in the future.
	ErrExpired = &Error{Name: "ErrExpired"}
	// ErrNotYetValid: nbf or iat (minus clock skew) is in the future.
	ErrNotYetValid = &Error{Name: "ErrNotYetValid"}
)

// Failures that are not about the token's contents.
var (
	// ErrJWKSUnavailable: the key set could not be fetched and there is no
	// previously fetched set to fall back on, so nothing can be verified.
	ErrJWKSUnavailable = &Error{Name: "ErrJWKSUnavailable"}
	// ErrMissingToken: the middleware found no token on the request.
	ErrMissingToken = &Error{Name: "ErrMissingToken"}
	// ErrInsufficientScope: the token is valid but lacks a scope or role the
	// middleware was configured to require.
	ErrInsufficientScope = &Error{Name: "ErrInsufficientScope"}
)

// withDetail returns a copy of the sentinel carrying a formatted detail.
// Sentinels are never mutated, so they stay safe to share across goroutines.
func (e *Error) withDetail(format string, args ...any) *Error {
	return &Error{Name: e.Name, Detail: fmt.Sprintf(format, args...)}
}

// withCause is withDetail plus an underlying error exposed through Unwrap.
func (e *Error) withCause(cause error, format string, args ...any) *Error {
	return &Error{Name: e.Name, Detail: fmt.Sprintf(format, args...), cause: cause}
}

// ErrorName returns the stable name of a jwkit error ("ErrExpired",
// "ErrBadSignature", ...). It returns "" if err is nil or did not originate
// in this package.
func ErrorName(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Name
	}
	return ""
}
