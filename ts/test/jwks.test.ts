import { describe, expect, test } from 'vitest'

import { ErrJWKSUnavailable, type Verifier } from '../src/index.js'
import { cacheControlMaxAge, MAX_CACHE_TTL_SEC, MAX_JWKS_BYTES, parseJwks } from '../src/jwks.js'
import { DEFAULT_CACHE_TTL_SEC, DEFAULT_REFETCH_INTERVAL_SEC } from '../src/verifier.js'
import {
  b64,
  ecKey1,
  ecKey2,
  ecP384,
  FakeClock,
  FakeIssuer,
  hs256WithPublicKey,
  jwk,
  newVerifier,
  NOW,
  result,
  rsaKey1,
  rsaKey2,
  rsaKey3,
  rsaSmall,
  setClaim,
  token,
  unsigned,
  waitFor,
  withKid,
} from './helpers.js'

async function mustVerify(verifier: Verifier, tok: string): Promise<void> {
  expect(await result(verifier, tok)).toBe('ok')
}

const longLived = (): string => token(rsaKey1, setClaim('exp', NOW + 86400 * 2))

test('the JWKS is fetched lazily and cached', async () => {
  const issuer = await FakeIssuer.start(rsaKey1, ecKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  expect(issuer.hits).toBe(0) // the constructor does no I/O

  for (let i = 0; i < 10; i++) {
    await mustVerify(verifier, token(rsaKey1))
    await mustVerify(verifier, token(ecKey1))
  }
  expect(issuer.hits).toBe(1)
})

// The whole rotation life cycle against a JWKS endpoint that changes mid-test.
test('key rotation', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const verifier = newVerifier(issuer, clock)

  const oldToken = token(rsaKey1, setClaim('exp', NOW + 7200))
  const newToken = token(rsaKey2, setClaim('exp', NOW + 7200))

  await mustVerify(verifier, oldToken)
  expect(issuer.hits).toBe(1)

  // The issuer starts signing with a new key and publishes both.
  issuer.publish(rsaKey1, rsaKey2)
  clock.advance(60)

  // Tokens from the old key need no fetch: it is still cached.
  await mustVerify(verifier, oldToken)
  expect(issuer.hits).toBe(1)

  // The first token from the new key triggers exactly one refetch...
  await mustVerify(verifier, newToken)
  expect(issuer.hits).toBe(2)
  // ...and later ones are served from the cache.
  await mustVerify(verifier, newToken)
  await mustVerify(verifier, oldToken)
  expect(issuer.hits).toBe(2)

  // The issuer retires the old key. Until the cache is refreshed the old key
  // still verifies; nothing has told us otherwise.
  issuer.publish(rsaKey2)
  clock.advance(60)
  await mustVerify(verifier, oldToken)
  expect(issuer.hits).toBe(2)

  // After the TTL the refresh drops the retired key, and its tokens die.
  clock.advance(DEFAULT_CACHE_TTL_SEC)
  expect(await result(verifier, oldToken)).toBe('ErrUnknownKey')
  expect(issuer.hits).toBe(3) // the refresh itself; no second fetch for the unknown kid
  await mustVerify(verifier, newToken)
  expect(issuer.hits).toBe(3)
})

test('refetches for unknown kids are rate limited', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const verifier = newVerifier(issuer, clock)

  await mustVerify(verifier, token(rsaKey1))
  expect(issuer.hits).toBe(1)

  // A burst of 100 tokens, each with a kid the issuer never published.
  const burst = async (): Promise<void> => {
    for (let i = 0; i < 100; i++) {
      expect(await result(verifier, token(withKid(rsaKey2, `made-up-${i}`)))).toBe('ErrUnknownKey')
    }
  }
  await burst()
  expect(issuer.hits).toBe(2) // one forced refetch for the whole burst

  // The same burst fired all at once is no different.
  const all = await Promise.all(Array.from({ length: 100 }, (_, i) => result(verifier, token(withKid(rsaKey2, `parallel-${i}`)))))
  expect(new Set(all)).toEqual(new Set(['ErrUnknownKey']))
  expect(issuer.hits).toBe(2)

  // Still inside the window: nothing.
  clock.advance(DEFAULT_REFETCH_INTERVAL_SEC - 1)
  await burst()
  expect(issuer.hits).toBe(2)

  // The window has passed: one more, and only one.
  clock.advance(1)
  await burst()
  expect(issuer.hits).toBe(3)

  // The rate limit never stood in the way of known keys.
  await mustVerify(verifier, token(rsaKey1))
  expect(issuer.hits).toBe(3)
})

test('the refetch interval is configurable', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const verifier = newVerifier(issuer, clock, { refetchIntervalSec: 5 })

  await mustVerify(verifier, token(rsaKey1))
  expect(await result(verifier, token(rsaKey2))).toBe('ErrUnknownKey')
  expect(issuer.hits).toBe(2)
  clock.advance(4)
  expect(await result(verifier, token(rsaKey2))).toBe('ErrUnknownKey')
  expect(issuer.hits).toBe(2)
  clock.advance(1)
  expect(await result(verifier, token(rsaKey2))).toBe('ErrUnknownKey')
  expect(issuer.hits).toBe(3)
})

// 200 verifications of tokens signed by a just-rotated key, all in flight at
// once, must share a single JWKS request and all succeed.
test('concurrent verifications during a rotation share one fetch', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  await mustVerify(verifier, token(rsaKey1))
  expect(issuer.hits).toBe(1)

  issuer.publish(rsaKey1, rsaKey2)
  const release = issuer.holdRequests() // keep the refetch in flight while the callers pile up
  const newToken = token(rsaKey2)

  const pending = Array.from({ length: 200 }, () => result(verifier, newToken))
  await waitFor(() => issuer.hits === 2)
  release()

  expect(new Set(await Promise.all(pending))).toEqual(new Set(['ok']))
  expect(issuer.hits).toBe(2)
})

// The same guarantee for the very first fetch, when the cache is empty.
test('concurrent first use shares one fetch', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  const release = issuer.holdRequests()

  const pending = Array.from({ length: 200 }, () => result(verifier, token(rsaKey1)))
  await waitFor(() => issuer.hits === 1)
  release()

  expect(new Set(await Promise.all(pending))).toEqual(new Set(['ok']))
  expect(issuer.hits).toBe(1)
})

describe('cache TTL', () => {
  test('default TTL', async () => {
    const issuer = await FakeIssuer.start(rsaKey1)
    const clock = new FakeClock()
    const verifier = newVerifier(issuer, clock)

    await mustVerify(verifier, longLived())
    clock.advance(DEFAULT_CACHE_TTL_SEC - 1)
    await mustVerify(verifier, longLived())
    expect(issuer.hits).toBe(1)
    clock.advance(1)
    await mustVerify(verifier, longLived())
    expect(issuer.hits).toBe(2)
  })

  test('configured TTL', async () => {
    const issuer = await FakeIssuer.start(rsaKey1)
    const clock = new FakeClock()
    const verifier = newVerifier(issuer, clock, { cacheTtlSec: 60 })

    await mustVerify(verifier, longLived())
    clock.advance(60)
    await mustVerify(verifier, longLived())
    expect(issuer.hits).toBe(2)
  })

  // Cache-Control: max-age from the issuer overrides the configured TTL,
  // clamped to [refetchIntervalSec, 24h].
  test.each<[string, number]>([
    ['max-age=120', 120],
    ['public, max-age=3600, must-revalidate', 3600],
    ['MAX-AGE=90', 90],
    ['max-age=1', DEFAULT_REFETCH_INTERVAL_SEC], // floor
    ['max-age=0', DEFAULT_REFETCH_INTERVAL_SEC], // floor
    ['max-age=31536000', MAX_CACHE_TTL_SEC], // cap
    ['max-age=99999999999999999999', MAX_CACHE_TTL_SEC], // cap
    ['no-cache', DEFAULT_CACHE_TTL_SEC], // no max-age: configured TTL
    ['max-age=soon', DEFAULT_CACHE_TTL_SEC], // unparsable: configured TTL
    ['', DEFAULT_CACHE_TTL_SEC],
  ])('Cache-Control %j gives a TTL of %d s', async (header, wantTtl) => {
    const issuer = await FakeIssuer.start(rsaKey1)
    issuer.cacheControl = header
    const clock = new FakeClock()
    const verifier = newVerifier(issuer, clock)

    await mustVerify(verifier, longLived())
    clock.advance(wantTtl - 1)
    await mustVerify(verifier, longLived())
    expect(issuer.hits).toBe(1)
    clock.advance(1)
    await mustVerify(verifier, longLived())
    expect(issuer.hits).toBe(2)
  })
})

test.each<[string, number | undefined]>([
  ['max-age=60', 60],
  [' public ,  max-age = 60 ', 60],
  ['max-age="60"', 60],
  ['s-maxage=60', undefined],
  ['max-age', undefined],
  ['max-age=', undefined],
  ['max-age=-5', undefined],
  ['max-age=1.5', undefined],
  ['max-age=1234567890', MAX_CACHE_TTL_SEC],
  ['private', undefined],
])('cacheControlMaxAge(%j) is %j', (header, want) => {
  expect(cacheControlMaxAge(header)).toBe(want)
})

describe('a failed refresh keeps the last good keys', () => {
  const failures: [string, (issuer: FakeIssuer) => void | Promise<void>][] = [
    ['HTTP 500', (f) => void (f.status = 500)],
    ['HTTP 404', (f) => void (f.status = 404)],
    ['not JSON', (f) => void (f.body = '<html>maintenance</html>')],
    ['JSON without keys', (f) => void (f.body = '{"error":"down"}')],
    ['empty key set', (f) => void (f.body = '{"keys":[]}')],
    ['no usable key', (f) => void (f.body = '{"keys":[{"kty":"oct","kid":"x","k":"AAAA"}]}')],
    ['oversized body', (f) => void (f.body = `{"keys":[],"pad":"${'a'.repeat(MAX_JWKS_BYTES)}"}`)],
    ['connection closed', (f) => f.close()],
  ]
  test.each(failures)('%s', async (_name, breakIssuer) => {
    const issuer = await FakeIssuer.start(rsaKey1)
    const clock = new FakeClock()
    const warnings: Error[] = []
    const verifier = newVerifier(issuer, clock, { onWarning: (err) => warnings.push(err) })
    const url = issuer.url

    await mustVerify(verifier, longLived())
    expect(warnings).toEqual([])

    await breakIssuer(issuer)
    clock.advance(DEFAULT_CACHE_TTL_SEC)

    // The refresh fails; the token still verifies against the last good key
    // set and the hook hears about it.
    await mustVerify(verifier, longLived())
    expect(warnings).toHaveLength(1)
    expect(warnings[0]!.message).toContain(`JWKS refresh failed: JWKS at ${url}`)

    // No retry storm: nothing is fetched again until refetchIntervalSec has passed.
    for (let i = 0; i < 20; i++) {
      await mustVerify(verifier, longLived())
    }
    expect(warnings).toHaveLength(1)
    clock.advance(DEFAULT_REFETCH_INTERVAL_SEC)
    await mustVerify(verifier, longLived())
    expect(warnings).toHaveLength(2)
  })
})

test('a refresh recovers after a failure', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const warnings: Error[] = []
  const verifier = newVerifier(issuer, clock, { onWarning: (err) => warnings.push(err) })
  await mustVerify(verifier, token(rsaKey1))

  issuer.status = 503
  clock.advance(DEFAULT_CACHE_TTL_SEC)
  await mustVerify(verifier, token(rsaKey1, setClaim('exp', clock.seconds + 60)))
  expect(warnings).toHaveLength(1)

  // The issuer comes back, having rotated in the meantime.
  issuer.status = 200
  issuer.publish(rsaKey2)
  clock.advance(DEFAULT_REFETCH_INTERVAL_SEC)
  await mustVerify(verifier, token(rsaKey2, setClaim('exp', clock.seconds + 60)))
  expect(await result(verifier, token(rsaKey1, setClaim('exp', clock.seconds + 60)))).toBe('ErrUnknownKey')
  expect(warnings).toHaveLength(1)
})

test('a failed forced refetch keeps the cache', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const warnings: Error[] = []
  const verifier = newVerifier(issuer, new FakeClock(), { onWarning: (err) => warnings.push(err) })
  await mustVerify(verifier, token(rsaKey1))

  issuer.status = 502
  expect(await result(verifier, token(rsaKey2))).toBe('ErrUnknownKey')
  expect(issuer.hits).toBe(2)
  expect(warnings).toHaveLength(1)
  // The failed lookup did not damage the cache or shorten its life.
  await mustVerify(verifier, token(rsaKey1))
  expect(issuer.hits).toBe(2)
})

test('ErrJWKSUnavailable when the first fetch fails', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  issuer.status = 500
  const warnings: Error[] = []
  const verifier = newVerifier(issuer, new FakeClock(), { onWarning: (err) => warnings.push(err) })

  // With no key set at all there is nothing to fall back on.
  const err: unknown = await verifier.verify(token(rsaKey1)).catch((e: unknown) => e)
  expect(err).toBeInstanceOf(ErrJWKSUnavailable)
  expect((err as ErrJWKSUnavailable).message).toContain('unexpected HTTP status 500')
  expect((err as ErrJWKSUnavailable).cause).toBeInstanceOf(Error)
  expect(warnings).toHaveLength(1)

  // It is not a permanent state: the next call tries again.
  issuer.status = 200
  await mustVerify(verifier, token(rsaKey1))
  expect(issuer.hits).toBe(2)
})

test('a throwing warning hook does not fail verification', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const clock = new FakeClock()
  const verifier = newVerifier(issuer, clock, {
    onWarning: () => {
      throw new Error('logger is down')
    },
  })
  await mustVerify(verifier, longLived())
  issuer.status = 500
  clock.advance(DEFAULT_CACHE_TTL_SEC)
  await mustVerify(verifier, longLived())
})

test('a malformed token never touches the network', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const verifier = newVerifier(issuer, new FakeClock())
  expect(await result(verifier, 'garbage')).toBe('ErrMalformed')
  expect(await result(verifier, unsigned({ alg: 'none' }))).toBe('ErrUnsupportedAlg')
  expect(await result(verifier, hs256WithPublicKey(rsaKey1))).toBe('ErrUnsupportedAlg')
  expect(issuer.hits).toBe(0)
})

describe('custom fetch', () => {
  test('is used instead of the global one', async () => {
    const issuer = await FakeIssuer.start(rsaKey1)
    const seen: string[] = []
    const verifier = newVerifier(issuer, new FakeClock(), {
      fetch: (input, init) => {
        seen.push(typeof input === 'string' ? input : 'not a string')
        return fetch(input, init)
      },
    })
    await mustVerify(verifier, token(rsaKey1))
    expect(seen).toEqual([issuer.url])
  })

  test('a non-Error rejection and an empty body are reported, not thrown', async () => {
    const issuer = await FakeIssuer.start(rsaKey1)
    const warnings: Error[] = []
    let respond: () => Promise<Response> = () => Promise.reject('offline') // eslint-disable-line @typescript-eslint/prefer-promise-reject-errors
    const verifier = newVerifier(issuer, new FakeClock(), {
      fetch: () => respond(),
      onWarning: (err) => warnings.push(err),
    })
    expect(await result(verifier, token(rsaKey1))).toBe('ErrJWKSUnavailable')
    expect(warnings[0]!.message).toContain('offline')

    respond = () => Promise.resolve(new Response(null, { status: 200 }))
    expect(await result(verifier, token(rsaKey1))).toBe('ErrJWKSUnavailable')
    expect(warnings[1]!.message).toContain('not a JSON object')
  })
})

test('parseJwks keeps only usable signature keys', async () => {
  const jwkWith = (key: Parameters<typeof jwk>[0], edit: (j: Record<string, unknown>) => void): Record<string, unknown> => {
    const j = jwk(key)
    edit(j)
    return j
  }
  // A private key published by mistake: only n and e may be used.
  const privateRsa = { ...rsaKey2.privateKey.export({ format: 'jwk' }), kid: 'rsa-2', use: 'sig' }
  const offCurve = jwkWith(ecKey2, (j) => {
    j.kid = 'off-curve'
    j.y = j.x
  })

  const keys = await parseJwks(
    JSON.stringify({
      keys: [
        jwk(rsaKey1),
        jwk(ecKey1),
        privateRsa,
        jwkWith(rsaKey3, (j) => (j.kid = 'rsa-1')), // duplicate kid: ignored
        jwkWith(rsaKey3, (j) => ((j.kid = 'enc'), (j.use = 'enc'))), // encryption key
        jwkWith(rsaKey3, (j) => ((j.kid = 'ps256'), (j.alg = 'PS256'))), // other algorithm
        jwkWith(rsaKey3, (j) => delete j.kid), // no kid
        jwkWith(rsaKey3, (j) => (j.kid = 7)), // kid not a string
        jwkWith(rsaKey3, (j) => ((j.kid = 'no-n'), delete j.n)), // incomplete
        jwkWith(rsaKey3, (j) => ((j.kid = 'bad-n'), (j.n = '!!!'))), // not base64url
        jwkWith(rsaKey3, (j) => ((j.kid = 'zero-n'), (j.n = b64(new Uint8Array(256))))), // all-zero modulus
        jwkWith(rsaKey3, (j) => ((j.kid = 'no-alg-use'), delete j.alg, delete j.use)),
        jwk(rsaSmall), // 1024-bit modulus
        jwk(ecP384), // wrong curve
        offCurve,
        { kty: 'oct', kid: 'hmac', k: 'c2VjcmV0' },
        { kty: 'OKP', kid: 'ed', crv: 'Ed25519', x: 'AAAA' },
        'not an object',
        null,
      ],
    }),
  )

  expect([...keys.keys()].sort()).toEqual(['ec-1', 'no-alg-use', 'rsa-1', 'rsa-2'])
  expect(keys.get('rsa-1')!.alg).toBe('RS256')
  expect(keys.get('ec-1')!.alg).toBe('ES256')
  // Keys are held as public keys even if private material was published.
  expect(keys.get('rsa-2')!.key.type).toBe('public')

  // First key wins on a duplicate kid: a token from rsaKey1 verifies, which
  // it would not if rsaKey3 had replaced it.
  const issuer = await FakeIssuer.start(rsaKey1, withKid(rsaKey3, 'rsa-1'))
  await mustVerify(newVerifier(issuer, new FakeClock()), token(rsaKey1))
})

test.each<[string, string]>([
  ['not JSON', '<html>'],
  ['array', '[]'],
  ['no keys member', '{}'],
  ['keys not array', '{"keys":{}}'],
  ['keys null', '{"keys":null}'],
  ['wrong case', `{"KEYS":[${JSON.stringify(jwk(rsaKey1))}]}`],
  ['only unusable', '{"keys":[{"kty":"oct","kid":"a"}]}'],
  ['empty document', ''],
  ['keys of wrong type', '{"keys":[1,2,3]}'],
])('parseJwks rejects a document that is %s', async (_name, body) => {
  await expect(parseJwks(body)).rejects.toThrow()
})
