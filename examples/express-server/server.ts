// An Express service protected by jwkit.
//
//   JWKIT_ISSUER=https://your-tenant.example/ \
//   JWKIT_AUDIENCE=https://api.example.com \
//   JWKIT_JWKS_URL=https://your-tenant.example/.well-known/jwks.json \
//   npm start

import express from 'express'

import { jwkitExpress, scopes, Verifier } from '@ariankhademi/jwkit'

const verifier = new Verifier({
  issuer: process.env.JWKIT_ISSUER ?? '',
  audience: process.env.JWKIT_AUDIENCE ?? '',
  jwksUrl: process.env.JWKIT_JWKS_URL ?? '',
  onWarning: (err) => {
    console.warn(err.message)
  },
})

const app = express()
app.get('/healthz', (_req, res) => {
  res.send('ok')
})

// Everything under /api needs a valid token.
app.use('/api', jwkitExpress(verifier))
app.get('/api/me', (req, res) => {
  res.json({ sub: req.auth?.sub, scopes: req.auth ? scopes(req.auth) : [] })
})

// Everything under /admin also needs the "admin" scope.
app.use('/admin', jwkitExpress(verifier, { requiredScopes: ['admin'] }))
app.get('/admin/stats', (_req, res) => {
  res.json({ requests: 42 })
})

const port = Number(process.env.PORT ?? 8080)
app.listen(port, () => {
  console.log(`listening on :${port}`)
})
