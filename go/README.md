# jwkit (Go)

JWT verification against an identity provider's JWKS endpoint, with a
key-rotation-aware key cache and drop-in Gin middleware.

```sh
go get github.com/ArianKhademi/jwkit/go
```

```go
import jwkit "github.com/ArianKhademi/jwkit/go"

verifier, err := jwkit.NewVerifier(jwkit.Config{
	Issuer:   "https://your-tenant.example/",
	Audience: "https://api.example.com",
	JWKSURL:  "https://your-tenant.example/.well-known/jwks.json", // omit to use OIDC discovery
})
if err != nil {
	log.Fatal(err)
}

r := gin.Default()
r.Use(jwkit.GinMiddleware(verifier))
r.GET("/me", func(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"sub": jwkit.GinClaims(c).Subject})
})
```

This module has a TypeScript twin with identical behaviour and error names.
What is checked, the key-rotation design, the threat model and the
cross-language conformance suite are described in the
[repository README](https://github.com/ArianKhademi/jwkit#readme).
