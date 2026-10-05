import { describe, expect, test } from 'vitest'

import {
  claimStrings,
  decodeUnverified,
  ERROR_NAMES,
  ErrBadAudience,
  ErrBadIssuer,
  ErrBadSignature,
  ErrExpired,
  ErrInsufficientScope,
  ErrJWKSUnavailable,
  ErrMalformed,
  ErrMissingToken,
  ErrNotYetValid,
  errorName,
  ErrUnknownKey,
  ErrUnsupportedAlg,
  JwkitError,
  scopes,
  Verifier,
  type ErrorName,
  type VerifierConfig,
} from '../src/index.js'
import {
  AUDIENCE,
  b64,
  ecKey1,
  ecP384,
  FakeClock,
  FakeIssuer,
  hs256WithPublicKey,
  ISSUER,
  jwk,
  newVerifier,
  NOW,
  result,
  rsaKey1,
  rsaKey2,
  rsaSmall,
  setClaim,
  setHeader,
  signature,
  signRaw,
  splitToken,
  token,
  unsigned,
  validClaims,
  withKid,
  type TestKey,
} from './helpers.js'

const HEADER = '{"alg":"RS256","kid":"rsa-1"}'
const claimsJson = (): string => JSON.stringify(validClaims())

/** Valid claims plus a claim holding n nested arrays. */
function nestedClaims(n: number): string {
  return `${claimsJson().slice(0, -1)},"deep":${'['.repeat(n)}${']'.repeat(n)}}`
}

/** The segment with one bit of its decoded bytes flipped. */
function flipBit(segment: string): string {
  const raw = Buffer.from(segment, 'base64url')
  const i = raw.length >> 1
  raw[i] = raw[i]! ^ 0x01
  return b64(raw)
}

/** The segment in the non-URL-safe alphabet, guaranteed to contain '+' or '/'. */
function stdAlphabet(segment: string): string {
  const out = segment.replaceAll('-', '+').replaceAll('_', '/')
  return out === segment ? `+${segment.slice(1)}` : out
}

/**
 * Changes only the unused trailing bits of the last character, producing a
 * different string that a lenient decoder maps to the same bytes.
 */
function nonCanonical(segment: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const last = alphabet.indexOf(segment.at(-1)!)
  const out = segment.slice(0, -1) + alphabet[last | 1]!
  if (out === segment || !Buffer.from(out, 'base64url').equals(Buffer.from(segment, 'base64url'))) {
    throw new Error('failed to build a non-canonical encoding')
  }
  return out
}

/** ASN.1 DER encoding of an r||s signature, as a TLS stack would produce. */
function derSignature(key: TestKey, signingInput: string): Buffer {
  const raw = signature(key, signingInput)
  const int = (b: Buffer): Buffer => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    const v = b[i]! & 0x80 ? Buffer.concat([Buffer.from([0]), b.subarray(i)]) : b.subarray(i)
    return Buffer.concat([Buffer.from([0x02, v.length]), v])
  }
  const body = Buffer.concat([int(raw.subarray(0, 32)), int(raw.subarray(32))])
  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}

interface Case {
  name: string
  token: string
  want?: ErrorName
  config?: Partial<VerifierConfig>
}

describe('verify', async () => {
  const issuer = await FakeIssuer.start(rsaKey1, ecKey1, rsaSmall, ecP384)

  const valid = token(rsaKey1)
  const [vh, vp, vs] = splitToken(valid)
  const validES = token(ecKey1)
  const [eh, ep] = splitToken(validES)
  const tamperedPayload = b64(claimsJson().replace('user-1', 'admin'))

  const cases: Case[] = [
    // Accepted tokens.
    { name: 'valid RS256', token: valid },
    { name: 'valid ES256', token: validES },
    { name: 'aud is an array containing the audience', token: token(rsaKey1, setClaim('aud', ['other', AUDIENCE])) },
    { name: 'aud array with non-string members', token: token(rsaKey1, setClaim('aud', [7, null, AUDIENCE])) },
    { name: 'no iat, no nbf', token: token(rsaKey1, setClaim('iat', undefined)) },
    { name: 'fractional exp', token: signRaw(rsaKey1, HEADER, `{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":1750000300.5}`) },
    { name: 'exp inside the clock skew', token: token(rsaKey1, setClaim('exp', NOW - 59)) },
    { name: 'nbf inside the clock skew', token: token(rsaKey1, setClaim('nbf', NOW + 60)) },
    { name: 'iat inside the clock skew', token: token(rsaKey1, setClaim('iat', NOW + 60)) },
    { name: 'unknown header members are ignored', token: token(rsaKey1, setHeader('x-custom', { a: 1 })) },
    { name: 'duplicate header member: the last one wins', token: signRaw(rsaKey1, '{"alg":"none","alg":"RS256","kid":"rsa-1"}', claimsJson()) },
    { name: 'whitespace around the JSON is allowed', token: signRaw(rsaKey1, ` ${HEADER}\n`, `\t${claimsJson()} `) },
    { name: 'huge exp', token: token(rsaKey1, setClaim('exp', 1e300)) },
    { name: 'claims named like Object.prototype members', token: signRaw(rsaKey1, HEADER, `{"__proto__":{"iss":"x"},"constructor":"x","iss":"${ISSUER}","aud":"${AUDIENCE}","exp":1750000300}`) },

    // Time-based claims.
    { name: 'expired', token: token(rsaKey1, setClaim('exp', NOW - 3600)), want: 'ErrExpired' },
    { name: 'expired exactly at the skew boundary', token: token(rsaKey1, setClaim('exp', NOW - 60)), want: 'ErrExpired' },
    { name: 'exp underflows to zero', token: signRaw(rsaKey1, HEADER, `{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":1e-400}`), want: 'ErrExpired' },
    { name: 'nbf in the future', token: token(rsaKey1, setClaim('nbf', NOW + 61)), want: 'ErrNotYetValid' },
    { name: 'iat in the future', token: token(rsaKey1, setClaim('iat', NOW + 3600)), want: 'ErrNotYetValid' },
    { name: 'no skew: exp equal to now', token: token(rsaKey1, setClaim('exp', NOW)), want: 'ErrExpired', config: { clockSkewSec: 0 } },
    { name: 'no skew: exp one second ahead', token: token(rsaKey1, setClaim('exp', NOW + 1)), config: { clockSkewSec: 0 } },
    { name: 'negative skew is treated as none', token: token(rsaKey1, setClaim('exp', NOW + 1)), config: { clockSkewSec: -30 } },
    { name: 'custom skew', token: token(rsaKey1, setClaim('exp', NOW - 5)), want: 'ErrExpired', config: { clockSkewSec: 5 } },
    { name: 'missing exp', token: token(rsaKey1, setClaim('exp', undefined)), want: 'ErrMalformed' },
    { name: 'exp is a string', token: token(rsaKey1, setClaim('exp', '1750000300')), want: 'ErrMalformed' },
    { name: 'exp is beyond a double', token: signRaw(rsaKey1, HEADER, `{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":1e400}`), want: 'ErrMalformed' },
    { name: 'nbf is a string', token: token(rsaKey1, setClaim('nbf', 'soon')), want: 'ErrMalformed' },
    { name: 'iat is null', token: signRaw(rsaKey1, HEADER, `{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":1750000300,"iat":null}`), want: 'ErrMalformed' },

    // Issuer and audience.
    { name: 'wrong issuer', token: token(rsaKey1, setClaim('iss', 'https://evil.example')), want: 'ErrBadIssuer' },
    { name: 'missing issuer', token: token(rsaKey1, setClaim('iss', undefined)), want: 'ErrBadIssuer' },
    { name: 'issuer is not a string', token: token(rsaKey1, setClaim('iss', [ISSUER])), want: 'ErrBadIssuer' },
    { name: 'issuer differs by a trailing slash', token: token(rsaKey1, setClaim('iss', `${ISSUER}/`)), want: 'ErrBadIssuer' },
    { name: 'wrong audience', token: token(rsaKey1, setClaim('aud', 'https://other.example')), want: 'ErrBadAudience' },
    { name: 'missing audience', token: token(rsaKey1, setClaim('aud', undefined)), want: 'ErrBadAudience' },
    { name: 'audience array without ours', token: token(rsaKey1, setClaim('aud', ['a', 'b'])), want: 'ErrBadAudience' },
    { name: 'audience is a number', token: token(rsaKey1, setClaim('aud', 42)), want: 'ErrBadAudience' },
    { name: 'claims are not read from a __proto__ member', token: signRaw(rsaKey1, HEADER, `{"__proto__":{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":1750000300}}`), want: 'ErrBadIssuer' },
    { name: 'wrong issuer wins over expiry', token: token(rsaKey1, setClaim('iss', 'x'), setClaim('exp', NOW - 3600)), want: 'ErrBadIssuer' },

    // Signature.
    { name: 'tampered payload', token: `${vh}.${tamperedPayload}.${vs}`, want: 'ErrBadSignature' },
    { name: 'tampered signature', token: `${vh}.${vp}.${flipBit(vs)}`, want: 'ErrBadSignature' },
    { name: 'signed by a different key under a published kid', token: token(withKid(rsaKey2, 'rsa-1')), want: 'ErrBadSignature' },
    { name: 'signature from another token', token: `${vh}.${b64(JSON.stringify({ iss: ISSUER, aud: AUDIENCE, exp: NOW + 900 }))}.${vs}`, want: 'ErrBadSignature' },
    { name: 'empty signature', token: `${vh}.${vp}.`, want: 'ErrBadSignature' },
    { name: 'ES256 header pointing at an RSA key', token: token(withKid(ecKey1, 'rsa-1')), want: 'ErrBadSignature' },
    { name: 'RS256 header pointing at an EC key', token: token(withKid(rsaKey1, 'ec-1')), want: 'ErrBadSignature' },
    { name: 'ES256 signature in DER form', token: `${eh}.${ep}.${b64(derSignature(ecKey1, `${eh}.${ep}`))}`, want: 'ErrBadSignature' },
    { name: 'ES256 signature with an extra byte', token: `${eh}.${ep}.${b64(Buffer.concat([Buffer.from([0]), signature(ecKey1, `${eh}.${ep}`)]))}`, want: 'ErrBadSignature' },
    { name: 'tampered ES256 payload', token: `${eh}.${tamperedPayload}.${b64(signature(ecKey1, `${eh}.${ep}`))}`, want: 'ErrBadSignature' },
    { name: 'embedded jwk header is not trusted', token: token(withKid(rsaKey2, 'rsa-1'), setHeader('jwk', jwk(rsaKey2))), want: 'ErrBadSignature' },

    // Key lookup.
    { name: 'unknown kid', token: token(rsaKey2), want: 'ErrUnknownKey' },
    { name: 'RSA key below 2048 bits is never loaded', token: token(rsaSmall), want: 'ErrUnknownKey' },
    { name: 'P-384 key is never loaded', token: token(ecP384), want: 'ErrUnknownKey' },

    // Algorithms.
    { name: 'alg none', token: unsigned({ alg: 'none', typ: 'JWT' }), want: 'ErrUnsupportedAlg' },
    { name: 'alg none with a kid', token: unsigned({ alg: 'none', kid: 'rsa-1' }), want: 'ErrUnsupportedAlg' },
    { name: 'alg None, mixed case', token: unsigned({ alg: 'None', kid: 'rsa-1' }), want: 'ErrUnsupportedAlg' },
    { name: 'HS256 keyed with the RSA public key', token: hs256WithPublicKey(rsaKey1), want: 'ErrUnsupportedAlg' },
    { name: 'RS384', token: token(rsaKey1, setHeader('alg', 'RS384')), want: 'ErrUnsupportedAlg' },
    { name: 'PS256', token: token(rsaKey1, setHeader('alg', 'PS256')), want: 'ErrUnsupportedAlg' },
    { name: 'ES384', token: token(ecKey1, setHeader('alg', 'ES384')), want: 'ErrUnsupportedAlg' },
    { name: 'alg in lower case', token: token(rsaKey1, setHeader('alg', 'rs256')), want: 'ErrUnsupportedAlg' },
    { name: 'empty alg', token: token(rsaKey1, setHeader('alg', '')), want: 'ErrUnsupportedAlg' },
    { name: 'missing alg', token: token(rsaKey1, setHeader('alg', undefined)), want: 'ErrMalformed' },
    { name: 'alg is not a string', token: token(rsaKey1, setHeader('alg', 256)), want: 'ErrMalformed' },
    { name: 'member names are case-sensitive', token: signRaw(rsaKey1, '{"ALG":"RS256","kid":"rsa-1"}', claimsJson()), want: 'ErrMalformed' },
    { name: 'alg is not read from the prototype chain', token: signRaw(rsaKey1, '{"__proto__":{"alg":"RS256","kid":"rsa-1"}}', claimsJson()), want: 'ErrMalformed' },

    // Header policy.
    { name: 'missing kid', token: token(rsaKey1, setHeader('kid', undefined)), want: 'ErrMalformed' },
    { name: 'empty kid', token: token(rsaKey1, setHeader('kid', '')), want: 'ErrMalformed' },
    { name: 'kid is not a string', token: token(rsaKey1, setHeader('kid', 1)), want: 'ErrMalformed' },
    { name: 'crit header', token: token(rsaKey1, setHeader('crit', ['exp'])), want: 'ErrMalformed' },

    // Structure.
    { name: 'empty token', token: '', want: 'ErrMalformed' },
    { name: 'one segment', token: 'abc', want: 'ErrMalformed' },
    { name: 'two segments', token: `${vh}.${vp}`, want: 'ErrMalformed' },
    { name: 'four segments', token: `${valid}.abc`, want: 'ErrMalformed' },
    { name: 'five segments, like a JWE', token: `${valid}.abc.def`, want: 'ErrMalformed' },
    { name: 'only dots', token: '..', want: 'ErrMalformed' },
    { name: 'leading space', token: ` ${valid}`, want: 'ErrMalformed' },
    { name: 'trailing newline', token: `${valid}\n`, want: 'ErrMalformed' },
    { name: 'newline inside the header segment', token: `${vh.slice(0, 10)}\n${vh.slice(10)}.${vp}.${vs}`, want: 'ErrMalformed' },
    { name: 'invalid character in the header', token: `!${vh.slice(1)}.${vp}.${vs}`, want: 'ErrMalformed' },
    { name: 'invalid character in the payload', token: `${vh}.${vp.slice(0, 5)}*${vp.slice(6)}.${vs}`, want: 'ErrMalformed' },
    { name: 'invalid character in the signature', token: `${vh}.${vp}.${vs.slice(0, 5)}~${vs.slice(6)}`, want: 'ErrMalformed' },
    { name: 'standard base64 alphabet', token: `${vh}.${vp}.${stdAlphabet(vs)}`, want: 'ErrMalformed' },
    { name: 'padded base64', token: `${vh}.${vp}.${vs}==`, want: 'ErrMalformed' },
    { name: 'impossible base64 length', token: `${vh}.${vp}.${vs}AAA`, want: 'ErrMalformed' }, // 345 characters: length mod 4 is 1
    { name: 'non-canonical trailing bits in the signature', token: `${vh}.${vp}.${nonCanonical(vs)}`, want: 'ErrMalformed' },
    { name: 'non-ASCII character in the token', token: `${vh}.${vp}é.${vs}`, want: 'ErrMalformed' },
    { name: 'header is not JSON', token: signRaw(rsaKey1, 'not json', claimsJson()), want: 'ErrMalformed' },
    { name: 'header is a JSON array', token: signRaw(rsaKey1, '["RS256"]', claimsJson()), want: 'ErrMalformed' },
    { name: 'header is JSON null', token: signRaw(rsaKey1, 'null', claimsJson()), want: 'ErrMalformed' },
    { name: 'empty header', token: `.${vp}.${vs}`, want: 'ErrMalformed' },
    { name: 'payload is not JSON', token: signRaw(rsaKey1, HEADER, '{"iss":'), want: 'ErrMalformed' },
    { name: 'payload is a JSON string', token: signRaw(rsaKey1, HEADER, '"claims"'), want: 'ErrMalformed' },
    { name: 'nested JWT: payload is a token, not claims', token: signRaw(rsaKey1, '{"alg":"RS256","kid":"rsa-1","cty":"JWT"}', valid), want: 'ErrMalformed' },
    { name: 'payload has data after the object', token: signRaw(rsaKey1, HEADER, `${claimsJson()}{}`), want: 'ErrMalformed' },
    { name: 'payload has a stray closing brace', token: signRaw(rsaKey1, HEADER, `${claimsJson()}}`), want: 'ErrMalformed' },
    { name: 'payload is not UTF-8', token: signRaw(rsaKey1, HEADER, Buffer.from([0x7b, 0x22, 0x69, 0x73, 0x73, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])), want: 'ErrMalformed' },
    { name: 'payload starts with a byte order mark', token: signRaw(rsaKey1, HEADER, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(claimsJson())])), want: 'ErrMalformed' },

    // Nesting depth. The payload object is level 1, so 63 arrays inside a
    // claim reach the limit of 64 and one more exceeds it.
    { name: 'nesting at the depth limit', token: signRaw(rsaKey1, HEADER, nestedClaims(63)) },
    { name: 'nesting over the depth limit', token: signRaw(rsaKey1, HEADER, nestedClaims(64)), want: 'ErrMalformed' },
    { name: 'header nesting over the depth limit', token: signRaw(rsaKey1, `{"alg":"RS256","kid":"rsa-1","x":${'['.repeat(64)}${']'.repeat(64)}}`, claimsJson()), want: 'ErrMalformed' },
    { name: 'brackets inside strings are not nesting', token: token(rsaKey1, setClaim('note', `${'[{'.repeat(100)}\\"${'['.repeat(100)}`)) },
    // Beyond what Go's encoding/json would parse, and within what V8 would:
    // only reachable with a raised size limit.
    { name: "nesting beyond every parser's limit", token: signRaw(rsaKey1, HEADER, nestedClaims(12000)), want: 'ErrMalformed', config: { maxTokenBytes: 1 << 16 } },

    // Size limit.
    { name: 'oversized token', token: token(rsaKey1, setClaim('pad', 'a'.repeat(9000))), want: 'ErrMalformed' },
    { name: 'oversized token allowed by a higher limit', token: token(rsaKey1, setClaim('pad', 'a'.repeat(9000))), config: { maxTokenBytes: 20000 } },
    { name: 'exactly at the limit', token: valid, config: { maxTokenBytes: valid.length } },
    { name: 'one byte over the limit', token: valid, want: 'ErrMalformed', config: { maxTokenBytes: valid.length - 1 } },
    { name: 'the limit counts bytes, not characters', token: 'é'.repeat(5000), want: 'ErrMalformed' },
  ]

  test.each(cases)('$name', async ({ token: tok, want, config }) => {
    const verifier = newVerifier(issuer, new FakeClock(), config)
    expect(await result(verifier, tok)).toBe(want ?? 'ok')
  })

  test.each([undefined, null, 42, {}, [], Symbol('token'), () => 'token', new String(valid)])(
    'a token that is not a string is malformed: %o',
    async (notAString) => {
      expect(await result(newVerifier(issuer, new FakeClock()), notAString)).toBe('ErrMalformed')
    },
  )

  test('returns the verified claims', async () => {
    const verifier = newVerifier(issuer, new FakeClock())
    const claims = await verifier.verify(
      token(
        rsaKey1,
        setClaim('aud', [AUDIENCE, 'https://other.example']),
        setClaim('nbf', NOW - 10),
        setClaim('scope', 'read:users write:users'),
        setClaim('scp', ['admin', 7]),
        setClaim('roles', ['editor']),
      ),
    )
    expect(claims).toMatchObject({ iss: ISSUER, sub: 'user-1', exp: NOW + 300, iat: NOW, nbf: NOW - 10 })
    expect(claims.aud).toEqual([AUDIENCE, 'https://other.example'])
    expect(scopes(claims)).toEqual(['read:users', 'write:users', 'admin'])
    expect(claimStrings(claims, 'roles')).toEqual(['editor'])
    expect(claimStrings(claims, 'missing')).toEqual([])
    expect(claimStrings(claims, 'exp')).toEqual([])
    // Inherited members are not claims.
    expect(claimStrings(claims, 'toString')).toEqual([])
  })
})

// Headers that name a key location must never cause a request to it.
describe('key location headers are ignored', async () => {
  const issuer = await FakeIssuer.start(rsaKey1)
  const attacker = await FakeIssuer.start(rsaKey2, withKid(rsaKey2, 'rsa-1'))

  const cases: Case[] = [
    { name: 'legitimate token carrying jku and x5u', token: token(rsaKey1, setHeader('jku', attacker.url), setHeader('x5u', attacker.url)) },
    { name: "attacker key, own kid, jku to attacker's JWKS", token: token(rsaKey2, setHeader('jku', attacker.url)), want: 'ErrUnknownKey' },
    { name: "attacker key, issuer's kid, jku to attacker's JWKS", token: token(withKid(rsaKey2, 'rsa-1'), setHeader('jku', attacker.url)), want: 'ErrBadSignature' },
    { name: "attacker key, issuer's kid, x5u to attacker", token: token(withKid(rsaKey2, 'rsa-1'), setHeader('x5u', attacker.url)), want: 'ErrBadSignature' },
  ]
  test.each(cases)('$name', async ({ token: tok, want }) => {
    expect(await result(newVerifier(issuer, new FakeClock()), tok)).toBe(want ?? 'ok')
    expect(attacker.hits).toBe(0)
  })
})

test('decodeUnverified parses without verifying', () => {
  // A token nobody could verify still decodes: that is the point, and the danger.
  const { header, payload } = decodeUnverified(unsigned({ alg: 'none' }))
  expect(header).toEqual({ alg: 'none' })
  expect(payload.iss).toBe(ISSUER)
  expect(() => decodeUnverified('not-a-token')).toThrow(ErrMalformed)
})

describe('Verifier config', () => {
  const ok: VerifierConfig = { issuer: ISSUER, audience: AUDIENCE, jwksUrl: 'https://issuer.example/jwks.json' }

  test('a valid config is accepted without any I/O', () => {
    expect(() => new Verifier(ok)).not.toThrow()
  })

  test.each<[string, Partial<Record<keyof VerifierConfig, unknown>>]>([
    ['missing issuer', { issuer: '' }],
    ['missing audience', { audience: '' }],
    ['no JWKS URL and an issuer that is not a URL', { jwksUrl: undefined, issuer: 'my-issuer' }],
    ['empty JWKS URL and an issuer that is not a URL', { jwksUrl: '', issuer: 'my-issuer' }],
    ['relative JWKS URL', { jwksUrl: '/jwks.json' }],
    ['non-HTTP JWKS URL', { jwksUrl: 'file:///etc/jwks.json' }],
    ['JWKS URL of the wrong type', { jwksUrl: 42 }],
    ['issuer of the wrong type', { issuer: 42 }],
    ['audience of the wrong type', { audience: ['a'] }],
  ])('%s is rejected', (_name, override) => {
    expect(() => new Verifier({ ...ok, ...override } as VerifierConfig)).toThrow(TypeError)
  })
})

describe('errors', () => {
  test('carry a stable code, a detail and a readable message', () => {
    const err = new ErrExpired('at 5')
    expect(err).toBeInstanceOf(JwkitError)
    expect(err).toBeInstanceOf(Error)
    expect(err.code).toBe('ErrExpired')
    expect(err.name).toBe('ErrExpired')
    expect(err.detail).toBe('at 5')
    expect(err.message).toBe('jwkit: ErrExpired: at 5')
    expect(new ErrExpired().message).toBe('jwkit: ErrExpired')
  })

  test('errorName is empty for foreign values', () => {
    expect(errorName(new ErrBadSignature())).toBe('ErrBadSignature')
    expect(errorName(new Error('ErrExpired'))).toBe('')
    expect(errorName(undefined)).toBe('')
  })

  test('ErrJWKSUnavailable exposes its cause', () => {
    const cause = new Error('connection refused')
    expect(new ErrJWKSUnavailable('fetch failed', { cause }).cause).toBe(cause)
  })

  // The names are the cross-language contract; a rename must be deliberate.
  test('every class reports the name it is exported under', () => {
    const classes = {
      ErrMalformed,
      ErrUnsupportedAlg,
      ErrUnknownKey,
      ErrBadSignature,
      ErrBadIssuer,
      ErrBadAudience,
      ErrExpired,
      ErrNotYetValid,
      ErrJWKSUnavailable,
      ErrMissingToken,
      ErrInsufficientScope,
    }
    expect(Object.keys(classes)).toEqual([...ERROR_NAMES])
    for (const [name, Class] of Object.entries(classes)) {
      expect(new Class().code).toBe(name)
    }
  })
})
