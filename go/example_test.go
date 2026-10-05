package jwkit_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	jwkit "github.com/ArianKhademi/jwkit/go"
)

// Verifying a token directly and reacting to the typed error.
func ExampleVerifier_Verify() {
	verifier, err := jwkit.NewVerifier(jwkit.Config{
		Issuer:   "https://your-tenant.example/",
		Audience: "https://api.example.com",
		// JWKSURL is omitted, so the key set is found through OpenID Connect
		// discovery on first use.
	})
	if err != nil {
		log.Fatal(err)
	}

	claims, err := verifier.Verify(context.Background(), "eyJhbGciOi...")
	switch {
	case errors.Is(err, jwkit.ErrExpired):
		fmt.Println("ask the client to refresh its token")
	case err != nil:
		// The name is stable and safe to return to a client; the full error
		// carries detail that belongs in a server log.
		fmt.Println("rejected:", jwkit.ErrorName(err))
	default:
		fmt.Println("authenticated as", claims.Subject)
	}
}

// Protecting a group of Gin routes, with a stricter rule for some of them.
func ExampleGinMiddleware() {
	verifier, err := jwkit.NewVerifier(jwkit.Config{
		Issuer:   "https://your-tenant.example/",
		Audience: "https://api.example.com",
		JWKSURL:  "https://your-tenant.example/.well-known/jwks.json",
	})
	if err != nil {
		log.Fatal(err)
	}

	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	api := r.Group("/api", jwkit.GinMiddleware(verifier))
	api.GET("/me", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"sub": jwkit.GinClaims(c).Subject})
	})

	admin := r.Group("/admin", jwkit.GinMiddleware(verifier, jwkit.MiddlewareOptions{
		RequiredScopes: []string{"admin"},
	}))
	admin.GET("/stats", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	log.Fatal(r.Run(":8080"))
}
