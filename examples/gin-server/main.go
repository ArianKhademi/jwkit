// A Gin service protected by jwkit.
//
//	JWKIT_ISSUER=https://your-tenant.example/ \
//	JWKIT_AUDIENCE=https://api.example.com \
//	JWKIT_JWKS_URL=https://your-tenant.example/.well-known/jwks.json \
//	go run .
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	jwkit "github.com/ArianKhademi/jwkit/go"
)

func main() {
	verifier, err := jwkit.NewVerifier(jwkit.Config{
		Issuer:    os.Getenv("JWKIT_ISSUER"),
		Audience:  os.Getenv("JWKIT_AUDIENCE"),
		JWKSURL:   os.Getenv("JWKIT_JWKS_URL"),
		OnWarning: func(err error) { log.Println(err) },
	})
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	// Everything under /api needs a valid token.
	api := r.Group("/api", jwkit.GinMiddleware(verifier))
	api.GET("/me", func(c *gin.Context) {
		claims := jwkit.GinClaims(c)
		c.JSON(http.StatusOK, gin.H{"sub": claims.Subject, "scopes": claims.Scopes()})
	})

	// Everything under /admin also needs the "admin" scope.
	admin := r.Group("/admin", jwkit.GinMiddleware(verifier, jwkit.MiddlewareOptions{RequiredScopes: []string{"admin"}}))
	admin.GET("/stats", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"requests": 42}) })

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(r.Run(addr))
}
