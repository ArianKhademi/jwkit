// Property-based tests. Where the table-driven tests check inputs somebody
// thought of, these check rules that must hold for inputs nobody did:
//
//   1. verify() never throws anything but a JwkitError, whatever it is given.
//   2. Nothing derived from a valid token by damaging it is ever accepted.
//   3. A token is accepted only if its claims really are valid.

import fc from 'fast-check'
import { describe, expect, test } from 'vitest'

import { ERROR_NAMES, type ErrorName, type Verifier } from '../src/index.js'
import {
  AUDIENCE,
  b64,
  ecKey1,
  FakeClock,
  FakeIssuer,
  ISSUER,
  jwk,
  newVerifier,
  NOW,
  result,
  rsaKey1,
  rsaKey2,
  signRaw,
  splitToken,
  token,
  validClaims,
  type TestKey,
} from './helpers.js'

const issuer = await FakeIssuer.start(rsaKey1, ecKey1)
// One verifier for all properties: after its first fetch the unknown-kid rate
// limit keeps random kids from generating any further network traffic.
const verifier: Verifier = newVerifier(issuer, new FakeClock())

/** Errors that describe a token. The other three names can only come from the key source or the middleware. */
const TOKEN_ERRORS: readonly string[] = ERROR_NAMES.slice(0, 8)

/** Runs verify and insists the outcome is a rejection with a token error. */
async function mustReject(tok: unknown): Promise<ErrorName> {
  // result() itself fails the test if verify throws anything untyped.
  const got = await result(verifier, tok)
  expect(TOKEN_ERRORS).toContain(got)
  return got as ErrorName
}

const validTokens = [token(rsaKey1), token(ecKey1)] as const
const aValidToken = fc.constantFrom(...validTokens)
const segmentIndex = fc.constantFrom(0, 1, 2)

const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split('')
const base64urlText = fc.array(fc.constantFrom(...BASE64URL_CHARS), { maxLength: 64 }).map((chars) => chars.join(''))

describe('verify never throws anything but a typed error', () => {
  test('for random byte strings', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 512 }), async (bytes) => {
        // latin1 maps every byte to one character, so all 256 values reach the parser.
        await mustReject(Buffer.from(bytes).toString('latin1'))
        await mustReject(Buffer.from(bytes).toString('utf8'))
      }),
      { numRuns: 500 },
    )
  })

  test('for random Unicode strings', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ unit: 'binary', maxLength: 256 }), async (s) => {
        await mustReject(s)
      }),
      { numRuns: 500 },
    )
  })

  test('for values that are not strings at all', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.anything().filter((v) => typeof v !== 'string'),
        async (v) => {
          expect(await mustReject(v)).toBe('ErrMalformed')
        },
      ),
      { numRuns: 300 },
    )
  })

  test('for three random base64url segments', async () => {
    await fc.assert(
      fc.asyncProperty(base64urlText, base64urlText, base64urlText, async (h, p, s) => {
        await mustReject(`${h}.${p}.${s}`)
      }),
      { numRuns: 500 },
    )
  })

  test('for random bytes dressed up as a token', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 96 }), fc.uint8Array({ maxLength: 96 }), fc.uint8Array({ maxLength: 96 }), async (h, p, s) => {
        await mustReject(`${b64(h)}.${b64(p)}.${b64(s)}`)
      }),
      { numRuns: 500 },
    )
  })

  test('for arbitrary JSON as the header of an otherwise valid token', async () => {
    await fc.assert(
      fc.asyncProperty(fc.json(), async (headerJson) => {
        // Unsigned for this header, so it can never be accepted.
        const [, p, s] = splitToken(validTokens[0])
        await mustReject(`${b64(headerJson)}.${p}.${s}`)
      }),
      { numRuns: 500 },
    )
  })
})

describe('no damaged copy of a valid token is accepted', () => {
  test('a flipped bit in any segment', async () => {
    await fc.assert(
      fc.asyncProperty(aValidToken, segmentIndex, fc.nat(), fc.integer({ min: 0, max: 7 }), async (tok, seg, pos, bit) => {
        const parts = splitToken(tok)
        const raw = Buffer.from(parts[seg], 'base64url')
        const i = pos % raw.length
        raw[i] = raw[i]! ^ (1 << bit)
        parts[seg] = b64(raw)
        const got = await mustReject(parts.join('.'))
        if (seg === 2) {
          // Header and payload are intact, so only the signature check can
          // notice.
          expect(got).toBe('ErrBadSignature')
        } else if (seg === 1) {
          // Structure is checked before the signature: a flip that breaks
          // the payload's JSON is malformed, any other is a bad signature.
          expect(['ErrMalformed', 'ErrBadSignature']).toContain(got)
        }
      }),
      { numRuns: 1000 },
    )
  })

  test('one character replaced anywhere in the token', async () => {
    await fc.assert(
      fc.asyncProperty(aValidToken, fc.nat(), fc.constantFrom(...BASE64URL_CHARS, '.', '=', '+', '/', ' ', '\n'), async (tok, pos, ch) => {
        const i = pos % tok.length
        fc.pre(tok[i] !== ch)
        await mustReject(tok.slice(0, i) + ch + tok.slice(i + 1))
      }),
      { numRuns: 1000 },
    )
  })

  test('truncation at any length', async () => {
    await fc.assert(
      fc.asyncProperty(aValidToken, fc.nat(), async (tok, n) => {
        await mustReject(tok.slice(0, n % tok.length))
      }),
      { numRuns: 500 },
    )
  })

  test('any text appended or prepended', async () => {
    await fc.assert(
      fc.asyncProperty(aValidToken, fc.string({ minLength: 1, maxLength: 16 }), fc.boolean(), async (tok, extra, atEnd) => {
        await mustReject(atEnd ? tok + extra : extra + tok)
      }),
      { numRuns: 500 },
    )
  })

  test('segments reordered or mixed between two valid tokens', async () => {
    const rs = splitToken(validTokens[0])
    const es = splitToken(validTokens[1])
    await fc.assert(
      fc.asyncProperty(fc.tuple(segmentIndex, segmentIndex, segmentIndex), fc.tuple(fc.boolean(), fc.boolean(), fc.boolean()), async (order, fromEs) => {
        const tok = order.map((seg, i) => (fromEs[i] ? es : rs)[seg]).join('.')
        fc.pre(!validTokens.includes(tok))
        await mustReject(tok)
      }),
      { numRuns: 300 },
    )
  })

  // Header field injection, without the signing key: whatever is added to the
  // header, the signature no longer covers it.
  test('header fields injected without re-signing', async () => {
    const injected = fc.dictionary(
      fc.constantFrom('jku', 'x5u', 'jwk', 'x5c', 'crit', 'alg', 'kid', 'typ', 'b64', 'zip', 'x'),
      fc.oneof(fc.constantFrom<unknown>('none', 'HS256', 'RS256', 'rsa-1', ['exp'], jwk(rsaKey2), 'https://attacker.example/jwks.json'), fc.jsonValue()),
      { minKeys: 1 },
    )
    await fc.assert(
      fc.asyncProperty(aValidToken, injected, async (tok, extra) => {
        const [h, p, s] = splitToken(tok)
        const header = { ...(JSON.parse(Buffer.from(h, 'base64url').toString()) as object), ...extra }
        const forged = `${b64(JSON.stringify(header))}.${p}.${s}`
        fc.pre(forged !== tok)
        await mustReject(forged)
      }),
      { numRuns: 500 },
    )
  })
})

describe('header fields injected by the legitimate signer', () => {
  const keyFor = (alg: string): TestKey => (alg === 'RS256' ? rsaKey1 : ecKey1)

  // Key-location headers must be ignored, not followed and not fatal: a token
  // that really is from the issuer verifies whatever jku/x5u/jwk/x5c say.
  test('key-location headers never change the outcome', async () => {
    const hits = issuer.hits
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('RS256', 'ES256'),
        fc.dictionary(fc.constantFrom('jku', 'x5u', 'jwk', 'x5c', 'x5t', 'typ', 'cty', 'custom'), fc.jsonValue(), { minKeys: 1 }),
        async (alg, extra) => {
          const key = keyFor(alg)
          const header = { alg, kid: key.kid, ...extra }
          expect(await result(verifier, signRaw(key, JSON.stringify(header), JSON.stringify(validClaims())))).toBe('ok')
        },
      ),
      { numRuns: 300 },
    )
    // Not one of those URLs or keys caused a request anywhere.
    expect(issuer.hits).toBe(hits)
  })

  test('changing alg or kid, or adding crit, is always fatal', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom('RS256', 'ES256'),
        fc.oneof(
          fc.record({ alg: fc.oneof(fc.constantFrom('none', 'HS256', 'HS512', 'RS512', 'PS256', 'ES512', 'EdDSA', ''), fc.string(), fc.jsonValue()) }),
          fc.record({ kid: fc.oneof(fc.string(), fc.jsonValue()) }),
          fc.record({ crit: fc.jsonValue() }),
        ),
        async (alg, change) => {
          const key = keyFor(alg)
          const header = { alg, kid: key.kid, ...change }
          fc.pre(header.alg !== alg || header.kid !== key.kid || 'crit' in header)
          // An RS256 key asked to verify an ES256 token (or the reverse) is
          // still a rejection, so swapping alg between the two is covered.
          await mustReject(signRaw(key, JSON.stringify(header), JSON.stringify(validClaims())))
        },
      ),
      { numRuns: 500 },
    )
  })
})

describe('a signed token is accepted only if its claims are valid', () => {
  /** What the claims deserve, decided independently of the verifier's code. */
  function expected(p: Record<string, unknown>): ErrorName | 'ok' {
    const has = (name: string): boolean => Object.hasOwn(p, name)
    const skew = 60
    if (!has('iss') || p.iss !== ISSUER) return 'ErrBadIssuer'
    const aud = has('aud') ? p.aud : undefined
    if (!(aud === AUDIENCE || (Array.isArray(aud) && aud.includes(AUDIENCE)))) return 'ErrBadAudience'
    for (const name of ['exp', 'nbf', 'iat']) {
      if (has(name) && (typeof p[name] !== 'number' || !Number.isFinite(p[name]))) return 'ErrMalformed'
    }
    if (!has('exp')) return 'ErrMalformed'
    if (NOW >= (p.exp as number) + skew) return 'ErrExpired'
    if (has('nbf') && (p.nbf as number) > NOW + skew) return 'ErrNotYetValid'
    if (has('iat') && (p.iat as number) > NOW + skew) return 'ErrNotYetValid'
    return 'ok'
  }

  // Values chosen to land on both sides of every check, plus arbitrary JSON.
  const time = fc.oneof(
    fc.integer({ min: NOW - 200, max: NOW + 200 }),
    fc.double({ min: NOW - 100, max: NOW + 100, noNaN: true }),
    fc.constantFrom<unknown>(0, -1, 1e300, '1750000000', null, true, [], {}),
  )
  const claims = fc.record(
    {
      iss: fc.oneof(fc.constant(ISSUER), fc.constantFrom<unknown>(`${ISSUER}/`, '', null, [ISSUER], 7), fc.string()),
      aud: fc.oneof(fc.constant(AUDIENCE), fc.constantFrom<unknown>([AUDIENCE], ['x', AUDIENCE], [], ['x'], null, 7, {}), fc.string()),
      exp: time,
      nbf: time,
      iat: time,
      sub: fc.jsonValue(),
      extra: fc.jsonValue(),
    },
    { requiredKeys: [] },
  )

  test('for generated claim sets', async () => {
    const seen = new Set<string>()
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(rsaKey1, ecKey1), claims, async (key, p) => {
        // What gets signed is the JSON text, so judge what a parser will see.
        const text = JSON.stringify(p)
        const want = expected(JSON.parse(text) as Record<string, unknown>)
        const got = await result(verifier, signRaw(key, JSON.stringify({ alg: key.alg, kid: key.kid }), text))
        expect(got).toBe(want)
        seen.add(got)
      }),
      { numRuns: 2000 },
    )
    // The generator is only worth something if it reaches every outcome.
    expect([...seen].sort()).toEqual(['ErrBadAudience', 'ErrBadIssuer', 'ErrExpired', 'ErrMalformed', 'ErrNotYetValid', 'ok'])
  })

  test('for arbitrary JSON payloads', async () => {
    await fc.assert(
      fc.asyncProperty(fc.json(), async (payloadJson) => {
        const parsed: unknown = JSON.parse(payloadJson)
        const isObject = typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
        const want = isObject ? expected(parsed as Record<string, unknown>) : 'ErrMalformed'
        expect(await result(verifier, signRaw(rsaKey1, '{"alg":"RS256","kid":"rsa-1"}', payloadJson))).toBe(want)
      }),
      { numRuns: 500 },
    )
  })
})
