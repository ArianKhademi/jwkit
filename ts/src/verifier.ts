import { compactVerify } from 'jose'

import {
  ErrBadAudience,
  ErrBadIssuer,
  ErrBadSignature,
  ErrExpired,
  ErrMalformed,
  ErrNotYetValid,
  ErrUnsupportedAlg,
} from './errors.js'
import { KeyCache, type Alg, type VerificationKey } from './jwks.js'

export const DEFAULT_CLOCK_SKEW_SEC = 60
export const DEFAULT_CACHE_TTL_SEC = 600
export const DEFAULT_REFETCH_INTERVAL_SEC = 30
/**
 * Matches the 8 KiB header limit of common proxies: a larger bearer token
 * would not have reached the service anyway.
 */
export const DEFAULT_MAX_TOKEN_BYTES = 8192

/** The size of an ES256 signature: r and s, 32 bytes each. */
const ES256_SIGNATURE_LEN = 64

/** Configures a Verifier. issuer, audience and jwksUrl are required. */
export interface VerifierConfig {
  /** The exact value the token's iss claim must have. */
  issuer: string
  /** Must appear in the token's aud claim. */
  audience: string
  /** Where the issuer publishes its public keys. */
  jwksUrl: string
  /** Tolerance applied to exp, nbf and iat, in seconds. Default 60; 0 means none. */
  clockSkewSec?: number
  /**
   * How long a fetched key set is used before it is refreshed, unless the
   * JWKS response carries Cache-Control: max-age. Default 600.
   */
  cacheTtlSec?: number
  /**
   * Minimum time between refetches triggered by a token with an unknown kid.
   * It is the limit that stops a client spraying random kids from turning
   * this service into a load generator against the JWKS endpoint. Default 30.
   */
  refetchIntervalSec?: number
  /** Longer tokens are rejected before any parsing. Default 8192. */
  maxTokenBytes?: number
  /** Fetches the JWKS. Default: the global fetch. Every fetch is bounded by a 10 second timeout. */
  fetch?: typeof fetch
  /**
   * Called when a JWKS refresh fails and the verifier keeps serving the last
   * good key set.
   */
  onWarning?: (err: Error) => void
  /**
   * Overrides the clock (milliseconds since the epoch, like Date.now). It
   * exists for tests and for the conformance runner, which verifies fixtures
   * at a fixed instant.
   */
  now?: () => number
}

/**
 * The verified payload of a token. The registered claims jwkit has checked
 * are typed; everything else is available under its own name.
 */
export interface Claims {
  [claim: string]: unknown
  iss: string
  aud: string | string[]
  /** Always present: jwkit rejects tokens without exp. */
  exp: number
  sub?: string
  nbf?: number
  iat?: number
}

/**
 * Returns the named claim as a list of strings. It accepts the two encodings
 * identity providers use for lists: a JSON array of strings, or a single
 * space-delimited string (the OAuth 2.0 "scope" format). Any other shape
 * yields an empty list.
 */
export function claimStrings(claims: Claims, name: string): string[] {
  const value = Object.hasOwn(claims, name) ? claims[name] : undefined
  if (typeof value === 'string') {
    return value.split(/\s+/).filter((s) => s !== '')
  }
  if (Array.isArray(value)) {
    return value.filter((e): e is string => typeof e === 'string')
  }
  return []
}

/**
 * Returns the token's scopes from the "scope" claim (RFC 8693) and the "scp"
 * claim (used by Okta and Microsoft Entra ID), in that order.
 */
export function scopes(claims: Claims): string[] {
  return [...claimStrings(claims, 'scope'), ...claimStrings(claims, 'scp')]
}

/**
 * Verifies tokens for one issuer and audience. Create one per issuer and
 * share it: the key cache lives inside it.
 */
export class Verifier {
  private readonly issuer: string
  private readonly audience: string
  private readonly skewSec: number
  private readonly maxTokenBytes: number
  private readonly now: () => number
  private readonly keys: KeyCache

  /** Validates config. Performs no network I/O: the JWKS is fetched lazily by the first verify(). */
  constructor(config: VerifierConfig) {
    if (typeof config.issuer !== 'string' || config.issuer === '') {
      throw new TypeError('jwkit: config.issuer is required')
    }
    if (typeof config.audience !== 'string' || config.audience === '') {
      throw new TypeError('jwkit: config.audience is required')
    }
    checkHttpUrl(config.jwksUrl)

    this.issuer = config.issuer
    this.audience = config.audience
    this.skewSec = Math.max(0, config.clockSkewSec ?? DEFAULT_CLOCK_SKEW_SEC)
    this.maxTokenBytes = positiveOr(config.maxTokenBytes, DEFAULT_MAX_TOKEN_BYTES)
    this.now = config.now ?? Date.now
    this.keys = new KeyCache({
      jwksUrl: config.jwksUrl,
      ttlSec: positiveOr(config.cacheTtlSec, DEFAULT_CACHE_TTL_SEC),
      refetchIntervalSec: positiveOr(config.refetchIntervalSec, DEFAULT_REFETCH_INTERVAL_SEC),
      now: this.now,
      // Resolved at call time so that a fetch replaced after construction
      // (by instrumentation, for example) is the one used.
      fetch: config.fetch ?? ((input, init) => fetch(input, init)),
      onWarning: config.onWarning,
    })
  }

  /**
   * Checks token and resolves to its claims, or rejects with a JwkitError
   * naming the first check that failed. The order is fixed and identical in
   * the Go implementation, so a token that is wrong in several ways produces
   * the same error in both:
   *
   *  1. structure (ErrMalformed)
   *  2. algorithm allow-list (ErrUnsupportedAlg), then kid presence (ErrMalformed)
   *  3. key lookup (ErrUnknownKey, ErrJWKSUnavailable)
   *  4. signature (ErrBadSignature)
   *  5. iss (ErrBadIssuer), aud (ErrBadAudience)
   *  6. exp/nbf/iat types (ErrMalformed), exp (ErrExpired), nbf and iat (ErrNotYetValid)
   *
   * Claims are only examined after the signature has verified, so the error
   * type never reveals anything about an unauthenticated payload.
   *
   * The parameter is typed unknown on purpose: whatever a caller passes, the
   * result is a typed error, never a TypeError from deep inside.
   */
  async verify(token: unknown): Promise<Claims> {
    const parsed = parseToken(token, this.maxTokenBytes)
    const { alg, kid } = checkHeader(parsed.header)
    const key = await this.keys.get(kid)
    await verifySignature(alg, kid, key, parsed)
    return this.checkClaims(parsed.payload)
  }

  private checkClaims(p: Record<string, unknown>): Claims {
    const iss = own(p, 'iss')
    if (typeof iss !== 'string' || iss !== this.issuer) {
      throw new ErrBadIssuer(`iss is not ${JSON.stringify(this.issuer)}`)
    }
    if (!audiences(own(p, 'aud')).includes(this.audience)) {
      throw new ErrBadAudience(`aud does not contain ${JSON.stringify(this.audience)}`)
    }

    const exp = numericDate(p, 'exp')
    if (exp === undefined) {
      throw new ErrMalformed('token has no exp claim')
    }
    const nbf = numericDate(p, 'nbf')
    const iat = numericDate(p, 'iat')

    // Whole seconds and double arithmetic, exactly as the Go side computes
    // it, so boundary cases land on the same side in both.
    const now = Math.floor(this.now() / 1000)
    if (now >= exp + this.skewSec) {
      throw new ErrExpired(`token expired at ${isoTime(exp)}`)
    }
    if (nbf !== undefined && nbf > now + this.skewSec) {
      throw new ErrNotYetValid(`token is not valid before ${isoTime(nbf)}`)
    }
    if (iat !== undefined && iat > now + this.skewSec) {
      throw new ErrNotYetValid(`token was issued in the future, at ${isoTime(iat)}`)
    }
    return p as Claims
  }
}

/** A missing, zero or negative setting means "use the default", as in the Go Config. */
function positiveOr(value: number | undefined, fallback: number): number {
  return value !== undefined && value > 0 ? value : fallback
}

function checkHttpUrl(raw: unknown): void {
  if (typeof raw !== 'string' || raw === '') {
    throw new TypeError('jwkit: config.jwksUrl is required')
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new TypeError(`jwkit: config.jwksUrl: ${JSON.stringify(raw)} is not an absolute http(s) URL`)
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new TypeError(`jwkit: config.jwksUrl: ${JSON.stringify(raw)} is not an absolute http(s) URL`)
  }
}

/**
 * Parses a token and returns its header and payload WITHOUT checking the
 * signature or any claim. It exists for debugging tools; never make an
 * authorization decision from its result.
 */
export function decodeUnverified(token: unknown): {
  header: Record<string, unknown>
  payload: Record<string, unknown>
} {
  const { header, payload } = parseToken(token, DEFAULT_MAX_TOKEN_BYTES)
  return { header, payload }
}

/** A structurally valid compact JWS. */
interface ParsedToken {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: Buffer
  /** The token exactly as received; the signature covers its first two segments byte for byte. */
  compact: string
}

/**
 * Enforces the structure of a compact JWS carrying a JWT: exactly three
 * segments of canonical unpadded base64url, where the first two decode to
 * UTF-8 JSON objects. Every failure is ErrMalformed.
 */
function parseToken(token: unknown, maxBytes: number): ParsedToken {
  if (typeof token !== 'string') {
    throw new ErrMalformed('token is not a string')
  }
  // Size first, so that nothing below does work proportional to an
  // attacker-chosen length. The limit is in UTF-8 bytes, as in Go; a string
  // is never shorter in bytes than in UTF-16 units, so the cheap length check
  // settles most oversized inputs without measuring them.
  if (token.length > maxBytes || Buffer.byteLength(token, 'utf8') > maxBytes) {
    throw new ErrMalformed(`token is longer than the limit of ${maxBytes} bytes`)
  }
  const parts = token.split('.')
  if (parts.length !== 3) {
    throw new ErrMalformed(`expected 3 dot-separated segments, found ${parts.length}`)
  }
  const [h, p, s] = parts as [string, string, string]
  return {
    header: decodeObject(h, 'header'),
    payload: decodeObject(p, 'payload'),
    signature: decodeSegment(s, 'signature'),
    compact: token,
  }
}

const BASE64URL = /^[A-Za-z0-9_-]*$/

/** Decodes one base64url segment strictly. */
function decodeSegment(s: string, what: string): Buffer {
  // Buffer.from(…, 'base64url') skips characters outside the alphabet instead
  // of failing, so the alphabet and the length are checked here.
  if (!BASE64URL.test(s) || s.length % 4 === 1) {
    throw new ErrMalformed(`${what}: not base64url`)
  }
  const bytes = Buffer.from(s, 'base64url')
  // Re-encoding must give back the input. This rejects non-zero trailing
  // bits, so every byte string has exactly one accepted encoding and a
  // signature cannot be re-spelled into a different token that still verifies.
  if (bytes.toString('base64url') !== s) {
    throw new ErrMalformed(`${what}: not canonical base64url`)
  }
  return bytes
}

// fatal: reject invalid UTF-8 instead of substituting U+FFFD.
// ignoreBOM: keep a leading byte order mark in the output so that JSON.parse
// rejects it, as Go's decoder does, instead of having it silently stripped.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/** Decodes a base64url segment that must contain a JSON object. */
function decodeObject(segment: string, what: string): Record<string, unknown> {
  const bytes = decodeSegment(segment, what)
  let text: string
  try {
    text = utf8.decode(bytes)
  } catch {
    throw new ErrMalformed(`${what}: not valid UTF-8`)
  }
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new ErrMalformed(`${what}: not valid JSON`)
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ErrMalformed(`${what}: not a JSON object`)
  }
  return value as Record<string, unknown>
}

/**
 * Reads a member the object itself has. Plain property access would also see
 * members inherited from Object.prototype ("constructor", "toString", ...),
 * which a JSON document does not contain.
 */
function own(obj: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(obj, name) ? obj[name] : undefined
}

/** Applies the header policy and returns the algorithm and key ID. */
function checkHeader(h: Record<string, unknown>): { alg: Alg; kid: string } {
  const alg = own(h, 'alg')
  if (typeof alg !== 'string') {
    throw new ErrMalformed('header has no string "alg"')
  }
  if (alg !== 'RS256' && alg !== 'ES256') {
    throw new ErrUnsupportedAlg(`alg ${JSON.stringify(alg)} is not allowed; only RS256 and ES256 are`)
  }
  // RFC 7515 section 4.1.11: a token listing critical extensions must be
  // rejected unless every one of them is understood. jwkit implements none.
  if (Object.hasOwn(h, 'crit')) {
    throw new ErrMalformed('header has "crit" but no critical extensions are supported')
  }
  const kid = own(h, 'kid')
  if (typeof kid !== 'string' || kid === '') {
    throw new ErrMalformed('header has no "kid"')
  }
  // Headers that point at key material (jku, x5u, jwk, x5c) are deliberately
  // never read: keys come only from the configured JWKS URL.
  return { alg, kid }
}

async function verifySignature(alg: Alg, kid: string, key: VerificationKey, parsed: ParsedToken): Promise<void> {
  // The key decides the algorithm, not the token. Each cached key is bound to
  // the one algorithm its type supports, so a token cannot ask for an RSA key
  // to be used as anything other than an RS256 verification key.
  if (key.alg !== alg) {
    throw new ErrBadSignature(`token alg is ${alg} but key ${JSON.stringify(kid)} is an ${key.alg} key`)
  }
  // Enforced here rather than left to the crypto library so that the rule is
  // identical in both languages.
  if (alg === 'ES256' && parsed.signature.length !== ES256_SIGNATURE_LEN) {
    throw new ErrBadSignature(`ES256 signature is ${parsed.signature.length} bytes, want ${ES256_SIGNATURE_LEN}`)
  }
  try {
    // jwkit owns parsing and policy; the signature maths is delegated to
    // jose. The token it receives has already passed every structural check
    // above, and the key is passed explicitly, so jose never resolves one
    // from the header.
    await compactVerify(parsed.compact, key.key, { algorithms: [alg] })
  } catch {
    throw new ErrBadSignature(`signature does not verify with key ${JSON.stringify(kid)}`)
  }
}

/**
 * Normalises the aud claim, which may be one string or an array. Non-string
 * array elements cannot match an audience and are dropped.
 */
function audiences(v: unknown): string[] {
  if (typeof v === 'string') {
    return [v]
  }
  if (Array.isArray(v)) {
    return v.filter((e): e is string => typeof e === 'string')
  }
  return []
}

/**
 * Reads a NumericDate claim (seconds since the epoch, fractions allowed).
 * Returns undefined when absent. A claim that is present but not a finite
 * JSON number is ErrMalformed; JSON.parse turns a literal beyond the double
 * range, such as 1e400, into Infinity, which is caught here.
 */
function numericDate(p: Record<string, unknown>, name: string): number | undefined {
  if (!Object.hasOwn(p, name)) {
    return undefined
  }
  const v = p[name]
  if (typeof v !== 'number') {
    throw new ErrMalformed(`${name} is not a number`)
  }
  if (!Number.isFinite(v)) {
    throw new ErrMalformed(`${name} is not a finite number`)
  }
  return v
}

/** Formats a NumericDate for an error message, clamping values Date cannot represent. */
function isoTime(sec: number): string {
  const ms = Math.max(-8.64e15, Math.min(8.64e15, sec * 1000))
  return new Date(ms).toISOString()
}
