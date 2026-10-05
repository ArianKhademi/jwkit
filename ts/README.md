# jwkit (TypeScript)

JWT verification against an identity provider's JWKS endpoint, with a
key-rotation-aware key cache and drop-in Express middleware. Node.js 20+.

```ts
import express from 'express'
import { jwkitExpress, Verifier } from '@ariankhademi/jwkit'

const verifier = new Verifier({
  issuer: 'https://your-tenant.example/',
  audience: 'https://api.example.com',
  jwksUrl: 'https://your-tenant.example/.well-known/jwks.json', // omit to use OIDC discovery
})

const app = express()
app.use(jwkitExpress(verifier))
app.get('/me', (req, res) => {
  res.json({ sub: req.auth?.sub })
})
```

Without Express:

```ts
import { ErrExpired, JwkitError } from '@ariankhademi/jwkit'

try {
  const claims = await verifier.verify(token)
} catch (err) {
  if (err instanceof ErrExpired) { /* ... */ }
  if (err instanceof JwkitError) console.log(err.code) // "ErrBadSignature", ...
}
```

This package has a Go twin with identical behaviour and error names. What is
checked, the key-rotation design, the threat model and the cross-language
conformance suite are described in the
[repository README](https://github.com/ArianKhademi/jwkit#readme).
