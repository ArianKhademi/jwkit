package jwkit

import "testing"

func TestNewVerifierValidatesConfig(t *testing.T) {
	ok := Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: "https://issuer.example/jwks.json"}
	if _, err := NewVerifier(ok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]func(*Config){
		"missing issuer":   func(c *Config) { c.Issuer = "" },
		"missing audience": func(c *Config) { c.Audience = "" },
		"no JWKS URL and an issuer that is not a URL": func(c *Config) { c.JWKSURL = ""; c.Issuer = "my-issuer" },
		"relative JWKS URL":                           func(c *Config) { c.JWKSURL = "/jwks.json" },
		"non-HTTP JWKS URL":                           func(c *Config) { c.JWKSURL = "file:///etc/jwks.json" },
		"unparsable JWKS URL":                         func(c *Config) { c.JWKSURL = "http://[::1" },
	}
	for name, edit := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := ok
			edit(&cfg)
			if _, err := NewVerifier(cfg); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}
