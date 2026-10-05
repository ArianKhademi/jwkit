import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'

import express from 'express'
import { afterAll, describe, expect, test } from 'vitest'

import { cookieToken, headerToken, jwkitExpress, scopes, type MiddlewareOptions, type Verifier } from '../src/index.js'
import {
  b64,
  ecKey1,
  FakeClock,
  FakeIssuer,
  hs256WithPublicKey,
  newVerifier,
  NOW,
  rsaKey1,
  rsaKey2,
  setClaim,
  splitToken,
  token,
  unsigned,
  validClaims,
} from './helpers.js'

/**
 * Serves a real Express app over HTTP with the middleware installed and a few
 * routes behind it. Returns the base URL.
 */
async function startApp(verifier: Verifier, opts?: MiddlewareOptions, mount?: string): Promise<string> {
  const app = express()
  if (mount === undefined) {
    app.use(jwkitExpress(verifier, opts))
  } else {
    app.use(mount, jwkitExpress(verifier, opts))
  }
  app.get(['/me', '/api/me'], (req, res) => {
    res.json({ sub: req.auth?.sub, scopes: req.auth === undefined ? [] : scopes(req.auth) })
  })
  app.get(['/public/ping', '/api/public/ping'], (req, res) => {
    res.json({ authenticated: req.auth !== undefined })
  })
  app.get('/healthz', (_req, res) => {
    res.send('ok')
  })
  app.get('/healthz/deep', (_req, res) => {
    res.send('deep')
  })
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => {
      resolve(s)
    })
  })
  afterAll(() => {
    server.closeAllConnections()
    server.close()
  })
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
}

interface Reply {
  status: number
  challenge: string | null
  raw: string
  body: Record<string, unknown>
}

async function get(url: string, headers: Record<string, string> = {}): Promise<Reply> {
  const res = await fetch(url, { headers })
  const raw = await res.text()
  let body: Record<string, unknown> = {}
  try {
    body = JSON.parse(raw) as Record<string, unknown>
  } catch {
    // not every route answers in JSON
  }
  return { status: res.status, challenge: res.headers.get('www-authenticate'), raw, body }
}

const bearer = (tok: string): Record<string, string> => ({ authorization: `Bearer ${tok}` })
const invalid = (name: string): string => `Bearer error="invalid_token", error_description="${name}"`

describe('jwkitExpress', async () => {
  const issuer = await FakeIssuer.start(rsaKey1, ecKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  const base = await startApp(verifier)

  const valid = token(rsaKey1)
  const [vh, , vs] = splitToken(valid)
  const tampered = `${vh}.${b64(JSON.stringify(validClaims()).replace('user-1', 'admin'))}.${vs}`

  test('a valid token reaches the handler with its claims on req.auth', async () => {
    for (const tok of [valid, token(ecKey1)]) {
      const res = await get(`${base}/me`, bearer(tok))
      expect(res.status).toBe(200)
      expect(res.body.sub).toBe('user-1')
      expect(res.challenge).toBeNull()
    }
  })

  test('the Bearer scheme is case-insensitive', async () => {
    const res = await get(`${base}/me`, { authorization: `bearer  ${valid} ` })
    expect(res.status).toBe(200)
  })

  test.each<[string, Record<string, string>, number, string, string]>([
    ['no Authorization header', {}, 401, 'ErrMissingToken', 'Bearer'],
    ['another auth scheme', { authorization: `Basic ${b64('user:pass')}` }, 401, 'ErrMissingToken', 'Bearer'],
    ['scheme without a token', { authorization: 'Bearer' }, 401, 'ErrMissingToken', 'Bearer'],
    ['scheme with a blank token', { authorization: 'Bearer   ' }, 401, 'ErrMissingToken', 'Bearer'],
    ['expired token', bearer(token(rsaKey1, setClaim('exp', NOW - 3600))), 401, 'ErrExpired', invalid('ErrExpired')],
    ['wrong audience', bearer(token(rsaKey1, setClaim('aud', 'https://other.example'))), 401, 'ErrBadAudience', invalid('ErrBadAudience')],
    ['wrong issuer', bearer(token(rsaKey1, setClaim('iss', 'https://evil.example'))), 401, 'ErrBadIssuer', invalid('ErrBadIssuer')],
    ['tampered token', bearer(tampered), 401, 'ErrBadSignature', invalid('ErrBadSignature')],
    ['not yet valid', bearer(token(rsaKey1, setClaim('nbf', NOW + 3600))), 401, 'ErrNotYetValid', invalid('ErrNotYetValid')],
    ['unknown key', bearer(token(rsaKey2)), 401, 'ErrUnknownKey', invalid('ErrUnknownKey')],
    ['alg none', bearer(unsigned({ alg: 'none' })), 401, 'ErrUnsupportedAlg', invalid('ErrUnsupportedAlg')],
    ['HS256 confusion', bearer(hs256WithPublicKey(rsaKey1)), 401, 'ErrUnsupportedAlg', invalid('ErrUnsupportedAlg')],
    ['garbage', bearer('not.a.token'), 401, 'ErrMalformed', invalid('ErrMalformed')],
  ])('%s is rejected', async (_name, headers, status, error, challenge) => {
    const res = await get(`${base}/me`, headers)
    expect(res.status).toBe(status)
    // The body is exactly {"error": "<name>"}: no detail leaks.
    expect(res.body).toEqual({ error })
    expect(res.challenge).toBe(challenge)
  })
})

describe('scopes and roles', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  const insufficient = 'Bearer error="insufficient_scope", error_description="ErrInsufficientScope"'

  test.each<[string, MiddlewareOptions, string, number, string | null]>([
    ['all required scopes present in scope', { requiredScopes: ['read:users', 'write:users'] }, token(rsaKey1, setClaim('scope', 'write:users openid read:users')), 200, null],
    ['scopes in the scp array', { requiredScopes: ['read:users'] }, token(rsaKey1, setClaim('scp', ['read:users'])), 200, null],
    ['one required scope missing', { requiredScopes: ['read:users', 'write:users'] }, token(rsaKey1, setClaim('scope', 'read:users')), 403, `${insufficient}, scope="read:users write:users"`],
    ['no scope claim at all', { requiredScopes: ['read:users'] }, token(rsaKey1), 403, `${insufficient}, scope="read:users"`],
    ['a scope is not matched as a substring', { requiredScopes: ['read'] }, token(rsaKey1, setClaim('scope', 'read:users')), 403, `${insufficient}, scope="read"`],
    ['required role present', { requiredRoles: ['admin'] }, token(rsaKey1, setClaim('roles', ['editor', 'admin'])), 200, null],
    ['required role missing', { requiredRoles: ['admin'] }, token(rsaKey1, setClaim('roles', ['editor'])), 403, insufficient],
    ['roles under a custom claim name', { requiredRoles: ['admin'], rolesClaim: 'https://example.com/roles' }, token(rsaKey1, setClaim('https://example.com/roles', ['admin'])), 200, null],
    ['custom roles claim does not fall back to roles', { requiredRoles: ['admin'], rolesClaim: 'groups' }, token(rsaKey1, setClaim('roles', ['admin'])), 403, insufficient],
    ['scope satisfied but role missing', { requiredScopes: ['read:users'], requiredRoles: ['admin'] }, token(rsaKey1, setClaim('scope', 'read:users')), 403, `${insufficient}, scope="read:users"`],
  ])('%s', async (_name, opts, tok, status, challenge) => {
    const base = await startApp(verifier, opts)
    const res = await get(`${base}/me`, bearer(tok))
    expect(res.status).toBe(status)
    expect(res.challenge).toBe(challenge)
    if (status === 403) {
      expect(res.body).toEqual({ error: 'ErrInsufficientScope' })
    }
  })
})

describe('token extractors', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  const tok = token(rsaKey1)

  test('cookie', async () => {
    const base = await startApp(verifier, { tokenExtractor: cookieToken('session') })
    expect((await get(`${base}/me`, { cookie: `theme=dark; session=${tok}; other=1` })).status).toBe(200)
    expect((await get(`${base}/me`, { cookie: `session="${tok}"` })).status).toBe(200)
    // Another cookie, a malformed pair, or no cookie at all is a missing token.
    for (const cookie of ['theme=dark', 'session', '']) {
      const res = await get(`${base}/me`, cookie === '' ? {} : { cookie })
      expect(res.status).toBe(401)
      expect(res.body).toEqual({ error: 'ErrMissingToken' })
    }
    // The Authorization header is no longer consulted.
    expect((await get(`${base}/me`, bearer(tok))).body).toEqual({ error: 'ErrMissingToken' })
  })

  test('custom header', async () => {
    const base = await startApp(verifier, { tokenExtractor: headerToken('X-Auth-Token') })
    expect((await get(`${base}/me`, { 'x-auth-token': tok })).status).toBe(200)
    expect((await get(`${base}/me`)).body).toEqual({ error: 'ErrMissingToken' })
  })

  test('custom function', async () => {
    const base = await startApp(verifier, {
      tokenExtractor: (req) => (typeof req.query.access_token === 'string' ? req.query.access_token : undefined),
    })
    expect((await get(`${base}/me?access_token=${tok}`)).status).toBe(200)
  })
})

describe('skip paths', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const verifier = newVerifier(issuer, new FakeClock())

  test('exact and prefix entries bypass authentication', async () => {
    const base = await startApp(verifier, { skipPaths: ['/healthz', '/public/*'] })
    expect(await get(`${base}/healthz`)).toMatchObject({ status: 200, raw: 'ok' })
    expect((await get(`${base}/healthz?verbose=1`)).status).toBe(200)
    // Skipped means skipped: even a valid token is not looked at.
    expect(await get(`${base}/public/ping`, bearer(token(rsaKey1)))).toMatchObject({ status: 200, body: { authenticated: false } })
    expect((await get(`${base}/me`)).status).toBe(401)
    // An exact entry is not a prefix.
    expect((await get(`${base}/healthz/deep`)).status).toBe(401)
    expect(issuer.hits).toBe(0)
  })

  test('paths are matched in full even when the middleware is mounted on a prefix', async () => {
    const base = await startApp(verifier, { skipPaths: ['/api/public/*'] }, '/api')
    expect((await get(`${base}/api/public/ping`)).status).toBe(200)
    expect((await get(`${base}/api/me`)).status).toBe(401)
    expect((await get(`${base}/api/me`, bearer(token(rsaKey1)))).status).toBe(200)
  })
})

test('503 without a challenge when the JWKS is down', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  issuer.status = 500
  const base = await startApp(newVerifier(issuer, new FakeClock()))

  const res = await get(`${base}/me`, bearer(token(rsaKey1)))
  expect(res.status).toBe(503)
  expect(res.body).toEqual({ error: 'ErrJWKSUnavailable' })
  expect(res.challenge).toBeNull()
})

test('an unexpected error goes to the application error handler, not into a 401', async () => {
  const broken = {
    verify: () => Promise.reject(new Error('bug in a custom verifier')),
  } as unknown as Verifier
  const app = express()
  app.use(jwkitExpress(broken))
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ handled: err.message })
  })
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => {
      resolve(s)
    })
  })
  afterAll(() => {
    server.closeAllConnections()
    server.close()
  })
  const res = await get(`http://127.0.0.1:${(server.address() as AddressInfo).port}/me`, bearer('a.b.c'))
  expect(res.status).toBe(500)
  expect(res.body).toEqual({ handled: 'bug in a custom verifier' })
})
