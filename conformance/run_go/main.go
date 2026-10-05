// Command run_go runs the conformance fixtures through the Go implementation
// of jwkit and writes what it produced for each case.
//
//	go run ./run_go -fixtures fixtures.json -out results/go.json
//
// The output is a JSON array of {"name", "result"} in fixture order, where
// result is "ok" or the name of the typed error. The TypeScript runner writes
// the same format byte for byte, so the two files can be compared with diff.
// The exit status is 1 if any result differs from the fixture's expectation.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	jwkit "github.com/ArianKhademi/jwkit/go"
)

type fixtures struct {
	Config struct {
		Issuer        string `json:"issuer"`
		Audience      string `json:"audience"`
		Now           int64  `json:"now"`
		ClockSkewSec  int    `json:"clock_skew_sec"`
		MaxTokenBytes int    `json:"max_token_bytes"`
	} `json:"config"`
	JWKS  json.RawMessage `json:"jwks"`
	Cases []struct {
		Name   string `json:"name"`
		Token  string `json:"token"`
		Expect string `json:"expect"`
	} `json:"cases"`
}

type result struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

func main() {
	fixturesPath := flag.String("fixtures", "fixtures.json", "path of the fixtures file")
	outPath := flag.String("out", "", "write results to this file instead of standard output")
	flag.Parse()

	mismatches, err := run(*fixturesPath, *outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run_go:", err)
		os.Exit(2)
	}
	if mismatches > 0 {
		fmt.Fprintf(os.Stderr, "run_go: %d case(s) differ from the fixture expectations\n", mismatches)
		os.Exit(1)
	}
}

func run(fixturesPath, outPath string) (mismatches int, err error) {
	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		return 0, err
	}
	var fx fixtures
	if err := json.Unmarshal(raw, &fx); err != nil {
		return 0, fmt.Errorf("%s: %w", fixturesPath, err)
	}

	// The verifier is exercised end to end, JWKS fetch included, against an
	// in-process issuer that serves the fixture key set.
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fx.JWKS)
	}))
	defer issuer.Close()

	results := make([]result, 0, len(fx.Cases))
	for _, c := range fx.Cases {
		// A fresh verifier per case keeps cases independent: no shared key
		// cache and no shared refetch rate limit.
		v, err := jwkit.NewVerifier(jwkit.Config{
			Issuer:        fx.Config.Issuer,
			Audience:      fx.Config.Audience,
			JWKSURL:       issuer.URL,
			ClockSkew:     time.Duration(fx.Config.ClockSkewSec) * time.Second,
			MaxTokenBytes: fx.Config.MaxTokenBytes,
			Now:           func() time.Time { return time.Unix(fx.Config.Now, 0) },
		})
		if err != nil {
			return 0, err
		}

		got := "ok"
		if _, err := v.Verify(context.Background(), c.Token); err != nil {
			if got = jwkit.ErrorName(err); got == "" {
				got = "untyped error: " + err.Error()
			}
		}
		results = append(results, result{Name: c.Name, Result: got})
		if got != c.Expect {
			mismatches++
			fmt.Fprintf(os.Stderr, "MISMATCH %s: expected %s, got %s\n", c.Name, c.Expect, got)
		}
	}

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		return 0, err
	}
	if outPath == "" {
		_, err = os.Stdout.Write(out.Bytes())
		return mismatches, err
	}
	fmt.Printf("run_go: %d cases, %d mismatches -> %s\n", len(results), mismatches, outPath)
	return mismatches, os.WriteFile(outPath, out.Bytes(), 0o644)
}
