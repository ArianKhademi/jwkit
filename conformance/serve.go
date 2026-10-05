package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// serve turns the generator into a small test issuer, so the examples and the
// CLI can be tried without an external identity provider:
//
//	GET /.well-known/jwks.json             the fixture key set
//	GET /.well-known/openid-configuration  discovery document pointing at it
//	GET /token                             a fresh token, valid for five minutes
//
// /token accepts ?alg=ES256, ?sub=, ?scope= and ?aud=. The issuer is the
// address the server is reached at, for example http://localhost:8089.
func serve(addr string, keys *keyring) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	base := "http://" + ln.Addr().String()
	if host, port, err := net.SplitHostPort(ln.Addr().String()); err == nil && (host == "::" || host == "0.0.0.0") {
		base = "http://localhost:" + port
	}

	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=300")
		writeJSON(w, keys.jwks())
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, obj{"issuer": base, "jwks_uri": base + "/.well-known/jwks.json"})
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		k := keys.rsaCurrent
		if strings.EqualFold(q.Get("alg"), "ES256") {
			k = keys.ecCurrent
		}
		at := time.Now().Unix()
		c := obj{"iss": base, "aud": audience, "sub": "user-123", "iat": at, "exp": at + 300}
		for _, name := range []string{"sub", "scope", "aud"} {
			if v := q.Get(name); v != "" {
				c[name] = v
			}
		}
		fmt.Fprintln(w, k.signed(toJSON(k.header()), toJSON(c)))
	})

	fmt.Printf("test issuer listening\n  issuer:   %s\n  audience: %s\n  JWKS:     %s/.well-known/jwks.json\n  token:    curl -s %s/token\n",
		base, audience, base, base)
	return http.Serve(ln, mux)
}
