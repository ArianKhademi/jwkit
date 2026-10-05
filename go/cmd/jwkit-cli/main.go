// Command jwkit-cli decodes and verifies a JWT read from standard input. It
// is a debugging aid: it answers "what is in this token, and would jwkit
// accept it?" without writing any code.
//
//	jwkit-cli verify -issuer https://tenant.example/ -audience https://api.example < token.txt
//	jwkit-cli verify -issuer ... -audience ... -jwks-url https://tenant.example/keys < token.txt
//	jwkit-cli verify -issuer ... -audience ... -at 2026-01-31T12:00:00Z < token.txt
//	jwkit-cli decode < token.txt
//
// verify prints a JSON report and exits 0 if the token is valid and 1 if it
// is not. Without -jwks-url the key set is found through OpenID Connect
// discovery from the issuer. decode prints the header and payload without
// verifying anything. Usage errors exit 2.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	jwkit "github.com/ArianKhademi/jwkit/go"
)

const usage = `usage:
  jwkit-cli verify -issuer <iss> -audience <aud> [-jwks-url <url>] [-skew <duration>] [-at <time>] < token
  jwkit-cli decode < token
`

// maxInput bounds what is read from standard input; a token is a few kilobytes.
const maxInput = 1 << 20

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "verify":
		return verify(args[1:], stdin, stdout, stderr)
	case "decode":
		return decode(stdin, stdout, stderr)
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "jwkit-cli: unknown command %q\n%s", args[0], usage)
		return 2
	}
}

// report is what verify prints. Header and Claims are filled in whenever the
// token can be parsed at all, valid or not, because seeing what a rejected
// token says is usually the point of running this tool.
type report struct {
	Valid  bool           `json:"valid"`
	Error  string         `json:"error,omitempty"`
	Detail string         `json:"detail,omitempty"`
	Header map[string]any `json:"header,omitempty"`
	Claims map[string]any `json:"claims,omitempty"`
}

func verify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	issuer := fs.String("issuer", "", "expected iss claim (required)")
	audience := fs.String("audience", "", "expected aud claim (required)")
	jwksURL := fs.String("jwks-url", "", "JWKS location; if omitted it is discovered from the issuer")
	skew := fs.Duration("skew", jwkit.DefaultClockSkew, "clock skew tolerance; 0 for none")
	at := fs.String("at", "", "verify as of this time (RFC 3339 or Unix seconds) instead of now")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := jwkit.Config{
		Issuer:    *issuer,
		Audience:  *audience,
		JWKSURL:   *jwksURL,
		ClockSkew: *skew,
		OnWarning: func(err error) { fmt.Fprintln(stderr, "warning:", err) },
	}
	if *skew == 0 {
		cfg.ClockSkew = -1 // Config treats zero as "use the default"
	}
	if *at != "" {
		instant, err := parseTime(*at)
		if err != nil {
			fmt.Fprintf(stderr, "jwkit-cli: -at: %v\n", err)
			return 2
		}
		cfg.Now = func() time.Time { return instant }
	}
	verifier, err := jwkit.NewVerifier(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n%s", err, usage)
		return 2
	}

	token, err := readToken(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "jwkit-cli: reading standard input: %v\n", err)
		return 2
	}

	var r report
	// Decoded for display only; the verdict below comes from Verify.
	r.Header, r.Claims, _ = jwkit.DecodeUnverified(token)
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		r.Error = jwkit.ErrorName(err)
		var typed *jwkit.Error
		if errors.As(err, &typed) {
			r.Detail = typed.Detail
		}
	} else {
		r.Valid = true
	}
	writeJSON(stdout, r)
	if !r.Valid {
		return 1
	}
	return 0
}

func decode(stdin io.Reader, stdout, stderr io.Writer) int {
	token, err := readToken(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "jwkit-cli: reading standard input: %v\n", err)
		return 2
	}
	header, payload, err := jwkit.DecodeUnverified(token)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stderr, "note: decoded only; the signature and claims were NOT verified")
	writeJSON(stdout, map[string]any{"header": header, "payload": payload})
	return 0
}

// readToken reads the token and strips surrounding whitespace, since a token
// pasted into a file or piped from echo ends with a newline.
func readToken(stdin io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, maxInput))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func parseTime(s string) (time.Time, error) {
	if seconds, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(seconds, 0), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither Unix seconds nor an RFC 3339 time", s)
	}
	return t, nil
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v) // the values are decoded JSON and a few strings; encoding cannot fail
}
