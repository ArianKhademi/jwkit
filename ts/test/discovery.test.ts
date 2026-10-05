import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

import { afterAll, describe, expect, test } from 'vitest'

import { ErrJWKSUnavailable, Verifier, type VerifierConfig } from '../src/index.js'
import { DEFAULT_CACHE_TTL_SEC, DEFAULT_REFETCH_INTERVAL_SEC } from '../src/verifier.js'
import { AUDIENCE, FakeClock, jwk, NOW, result, rsaKey1, rsaKey2, setClaim, token, type Edit, type TestKey } from './helpers.js'

const DISCOVERY_PATH = '/.well-known/openid-configuration'

/**
 * An issuer that publishes an OpenID Connect discovery document. Its issuer
 * identifier is its own URL, as the specification requires, and every part of
 * it can be broken or moved mid-test.
 */
class DiscoveryIssuer {
  /** Body of the discovery document; "" means 404. */
  document = ''
  /** path -> JWKS body */
  readonly jwksAt = new Map<string, string>()
  readonly hits = new Map<string, number>()
  private readonly server: Server

  private constructor(server: Server) {
    this.server = server
  }

  static async start(...keys: TestKey[]): Promise<DiscoveryIssuer> {
    const server = createServer((req, res) => {
      const path = req.url ?? ''
      issuer.hits.set(path, issuer.hitCount(path) + 1)
      const body = path === DISCOVERY_PATH ? issuer.document : (issuer.jwksAt.get(path) ?? '')
      if (body === '') {
        res.writeHead(404).end('not found')
        return
      }
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(body)
    })
    const issuer = new DiscoveryIssuer(server)
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    afterAll(() => {
      server.closeAllConnections()
      server.close()
    })
    issuer.publishAt('/keys', ...keys)
    issuer.document = JSON.stringify({ issuer: issuer.url, jwks_uri: `${issuer.url}/keys` })
    return issuer
  }

  get url(): string {
    return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`
  }

  publishAt(path: string, ...keys: TestKey[]): void {
    this.jwksAt.set(path, JSON.stringify({ keys: keys.map(jwk) }))
  }

  hitCount(path: string): number {
    return this.hits.get(path) ?? 0
  }

  /** A verifier configured with the issuer only: no JWKS URL. */
  verifier(clock: FakeClock, overrides: Partial<VerifierConfig> = {}): Verifier {
    return new Verifier({ issuer: this.url, audience: AUDIENCE, now: clock.now, ...overrides })
  }

  /** A token whose iss is this issuer. */
  token(key: TestKey, ...edits: Edit[]): string {
    return token(key, setClaim('iss', this.url), ...edits)
  }
}

test('the JWKS location is discovered from the issuer, once', async () => {
  const d = await DiscoveryIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const verifier = d.verifier(clock)
  expect(d.hitCount(DISCOVERY_PATH)).toBe(0) // the constructor performs no discovery

  for (let i = 0; i < 5; i++) {
    expect(await result(verifier, d.token(rsaKey1))).toBe('ok')
  }
  expect(d.hitCount(DISCOVERY_PATH)).toBe(1)
  expect(d.hitCount('/keys')).toBe(1)

  // A routine refresh reuses the discovered location.
  clock.advance(DEFAULT_CACHE_TTL_SEC)
  expect(await result(verifier, d.token(rsaKey1, setClaim('exp', clock.seconds + 60)))).toBe('ok')
  expect(d.hitCount(DISCOVERY_PATH)).toBe(1)
  expect(d.hitCount('/keys')).toBe(2)
})

test('an issuer with a trailing slash', async () => {
  // Auth0-style issuer: "https://tenant.example/". The discovery URL must not
  // end up with a double slash, and iss must still match exactly.
  const d = await DiscoveryIssuer.start(rsaKey1)
  const issuer = `${d.url}/`
  d.document = JSON.stringify({ issuer, jwks_uri: `${d.url}/keys` })
  const verifier = d.verifier(new FakeClock(), { issuer })

  expect(await result(verifier, token(rsaKey1, setClaim('iss', issuer)))).toBe('ok')
  expect(await result(verifier, token(rsaKey1, setClaim('iss', d.url)))).toBe('ErrBadIssuer')
  expect(d.hitCount(DISCOVERY_PATH)).toBe(1)
})

describe('discovery failures', () => {
  const doc = (v: unknown): string => JSON.stringify(v)
  test.each<[string, (base: string) => string, string]>([
    ['no document', () => '', 'unexpected HTTP status 404'],
    ['not JSON', () => '<html>', 'not a JSON object'],
    ['JSON that is not an object', () => '[]', 'not a JSON object'],
    ['document for another issuer', (base) => doc({ issuer: 'https://evil.example', jwks_uri: `${base}/keys` }), 'document is for issuer "https://evil.example"'],
    ['issuer differs by a trailing slash', (base) => doc({ issuer: `${base}/`, jwks_uri: `${base}/keys` }), 'document is for issuer'],
    ['no issuer', (base) => doc({ jwks_uri: `${base}/keys` }), 'document is for issuer'],
    ['no jwks_uri', (base) => doc({ issuer: base }), 'no jwks_uri'],
    ['jwks_uri is not a string', (base) => doc({ issuer: base, jwks_uri: 7 }), 'no jwks_uri'],
    ['relative jwks_uri', (base) => doc({ issuer: base, jwks_uri: '/keys' }), 'jwks_uri'],
    ['jwks_uri with another scheme', (base) => doc({ issuer: base, jwks_uri: 'file:///etc/passwd' }), 'jwks_uri'],
    ['unparsable jwks_uri', (base) => doc({ issuer: base, jwks_uri: 'http://[::1' }), 'jwks_uri'],
  ])('%s', async (_name, document, wantError) => {
    const d = await DiscoveryIssuer.start(rsaKey1)
    const good = d.document
    d.document = document(d.url)
    const warnings: Error[] = []
    const verifier = d.verifier(new FakeClock(), { onWarning: (err) => warnings.push(err) })

    const err: unknown = await verifier.verify(d.token(rsaKey1)).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ErrJWKSUnavailable)
    expect((err as Error).message).toContain(`OpenID discovery at ${d.url}${DISCOVERY_PATH}`)
    expect((err as Error).message).toContain(wantError)
    expect(warnings).toHaveLength(1)
    expect(d.hitCount('/keys')).toBe(0) // no JWKS fetch without a successful discovery

    // Nothing is cached from a failed discovery: once the document is right,
    // the next call works.
    d.document = good
    expect(await result(verifier, d.token(rsaKey1))).toBe('ok')
  })
})

// If the JWKS disappears from the discovered location, the next attempt
// performs discovery again and follows the issuer to the new one.
test('a moved JWKS is found again through discovery', async () => {
  const d = await DiscoveryIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const warnings: Error[] = []
  const verifier = d.verifier(clock, { onWarning: (err) => warnings.push(err) })
  const longLived = (key: TestKey): string => d.token(key, setClaim('exp', NOW + 86400))
  expect(await result(verifier, longLived(rsaKey1))).toBe('ok')

  // The issuer moves its JWKS and rotates at the same time.
  d.jwksAt.delete('/keys')
  d.publishAt('/keys-v2', rsaKey2)
  d.document = JSON.stringify({ issuer: d.url, jwks_uri: `${d.url}/keys-v2` })

  // The refresh hits the old location, fails, and the old keys keep working.
  clock.advance(DEFAULT_CACHE_TTL_SEC)
  expect(await result(verifier, longLived(rsaKey1))).toBe('ok')
  expect(warnings).toHaveLength(1)
  expect(warnings[0]!.message).toContain('/keys')

  // The retry rediscovers, finds the new location and the new key.
  clock.advance(DEFAULT_REFETCH_INTERVAL_SEC)
  expect(await result(verifier, longLived(rsaKey2))).toBe('ok')
  expect([d.hitCount(DISCOVERY_PATH), d.hitCount('/keys-v2')]).toEqual([2, 1])
  // The old key is gone. Its kid is now unknown, which costs one forced
  // refetch of the JWKS but no further discovery.
  expect(await result(verifier, longLived(rsaKey1))).toBe('ErrUnknownKey')
  expect([d.hitCount(DISCOVERY_PATH), d.hitCount('/keys-v2')]).toEqual([2, 2])
  expect(warnings).toHaveLength(1)
})

// A configured JWKS URL is never second-guessed by discovery.
test('a configured JWKS URL skips discovery', async () => {
  const d = await DiscoveryIssuer.start(rsaKey1)
  const verifier = d.verifier(new FakeClock(), { jwksUrl: `${d.url}/keys` })
  expect(await result(verifier, d.token(rsaKey1))).toBe('ok')
  expect(d.hitCount(DISCOVERY_PATH)).toBe(0)
})
