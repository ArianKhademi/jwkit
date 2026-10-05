package jwkit

import (
	"errors"
	"testing"
)

func TestErrors(t *testing.T) {
	detailed := ErrExpired.withDetail("at %d", 5)
	if !errors.Is(detailed, ErrExpired) || errors.Is(detailed, ErrMalformed) {
		t.Error("Is must compare by name")
	}
	if errors.Is(detailed, errors.New("ErrExpired")) {
		t.Error("Is must not match foreign errors")
	}
	if got := detailed.Error(); got != "jwkit: ErrExpired: at 5" {
		t.Errorf("Error() = %q", got)
	}
	if got := ErrExpired.Error(); got != "jwkit: ErrExpired" {
		t.Errorf("Error() = %q", got)
	}
	if ErrExpired.Detail != "" {
		t.Error("withDetail must not modify the sentinel")
	}

	cause := errors.New("connection refused")
	wrapped := ErrJWKSUnavailable.withCause(cause, "fetch failed")
	if !errors.Is(wrapped, cause) || !errors.Is(wrapped, ErrJWKSUnavailable) {
		t.Error("withCause must expose both the sentinel and the cause")
	}

	if got := ErrorName(wrapped); got != "ErrJWKSUnavailable" {
		t.Errorf("ErrorName = %q", got)
	}
	if ErrorName(nil) != "" || ErrorName(cause) != "" {
		t.Error("ErrorName must be empty for nil and foreign errors")
	}

	// The names are the cross-language contract; a rename must be deliberate.
	names := map[*Error]string{
		ErrMalformed: "ErrMalformed", ErrUnsupportedAlg: "ErrUnsupportedAlg", ErrUnknownKey: "ErrUnknownKey",
		ErrBadSignature: "ErrBadSignature", ErrBadIssuer: "ErrBadIssuer", ErrBadAudience: "ErrBadAudience",
		ErrExpired: "ErrExpired", ErrNotYetValid: "ErrNotYetValid", ErrJWKSUnavailable: "ErrJWKSUnavailable",
		ErrMissingToken: "ErrMissingToken", ErrInsufficientScope: "ErrInsufficientScope",
	}
	for sentinel, want := range names {
		if sentinel.Name != want {
			t.Errorf("sentinel name = %q, want %q", sentinel.Name, want)
		}
	}
}
