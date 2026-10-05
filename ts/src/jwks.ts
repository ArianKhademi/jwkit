import { importJWK, type CryptoKey, type JWK } from 'jose'

import { ErrJWKSUnavailable, ErrUnknownKey } from './errors.js'

/** Bounds one JWKS request. */
const FETCH_TIMEOUT_MS = 10_000
/** Caps the response body. Real key sets are a few kilobytes. */
export const MAX_JWKS_BYTES = 1 << 20
/**
 * Caps a Cache-Control max-age sent by the issuer, so that a key withdrawn
 * from the JWKS is dropped within a day at worst.
 */
export const MAX_CACHE_TTL_SEC = 24 * 60 * 60
/** The smallest RSA modulus accepted for RS256 (RFC 7518 section 3.3). */
const MIN_RSA_BITS = 2048

/**
 * The algorithm allow-list. Everything else, including "none" and the HMAC
 * family, is rejected before a key is looked up. Never letting a token choose
 * a symmetric algorithm is what defeats the RS256-to-HS256 confusion attack,
 * where the attacker signs with the public key as an HMAC secret.
 */
export type Alg = 'RS256' | 'ES256'

/**
 * A public key bound to the single algorithm it may be used with. Binding the
 * algorithm to the key, rather than trusting the alg in the token header,
 * rules out algorithm confusion by construction.
 */
export interface VerificationKey {
  alg: Alg
  key: CryptoKey
}

export interface KeyCacheOptions {
  jwksUrl: string
  ttlSec: number
  refetchIntervalSec: number
  /** Milliseconds since the epoch, like Date.now. */
  now: () => number
  fetch: typeof fetch
  onWarning?: ((err: Error) => void) | undefined
}

/**
 * Holds the issuer's current key set and decides when to refetch it.
 *
 * There are no locks because there is one thread: get() makes its lookup and
 * its decision to fetch without an await in between, so no other call can
 * interleave. The Go implementation does the same two steps under a mutex.
 */
export class KeyCache {
  private readonly opts: KeyCacheOptions
  /** null until the first successful fetch. */
  private keys: Map<string, VerificationKey> | null = null
  /** When `keys` must be refreshed, in ms. */
  private expiresAt = 0
  /** Time of the last refetch caused by an unknown kid, in ms. */
  private lastForced: number | null = null
  /**
   * The fetch in progress, if any. It never rejects: it resolves to the
   * error, or to null on success, once the cache has been updated.
   */
  private inflight: Promise<Error | null> | null = null

  constructor(opts: KeyCacheOptions) {
    this.opts = opts
  }

  /**
   * Returns the key for kid, fetching the JWKS if the cache is empty or
   * stale, or (rate limited) if kid is not in it.
   */
  async get(kid: string): Promise<VerificationKey> {
    const now = this.opts.now()
    const fresh = this.keys !== null && now < this.expiresAt
    const cached = this.keys?.get(kid)
    if (cached !== undefined && fresh) {
      return cached
    }

    let call: Promise<Error | null>
    if (this.inflight !== null) {
      // Someone is already fetching. Share their result instead of sending
      // a duplicate request.
      call = this.inflight
    } else if (!fresh) {
      // First use, or the TTL ran out.
      call = this.startFetch()
    } else if (this.lastForced === null || now - this.lastForced >= this.opts.refetchIntervalSec * 1000) {
      // Fresh cache but unknown kid: the issuer may have rotated keys since
      // the last fetch, so look once.
      this.lastForced = now
      call = this.startFetch()
    } else {
      // Unknown kid and we already looked recently. Answer from the cache so
      // a burst of made-up kids costs the issuer nothing.
      throw new ErrUnknownKey(`no key with kid ${JSON.stringify(kid)} in the JWKS`)
    }

    const fetchError = await call
    if (this.keys === null) {
      throw new ErrJWKSUnavailable(fetchError?.message, { cause: fetchError })
    }
    // Whether or not the fetch worked there is a key set to answer from: the
    // new one, or the last good one.
    const key = this.keys.get(kid)
    if (key === undefined) {
      throw new ErrUnknownKey(`no key with kid ${JSON.stringify(kid)} in the JWKS`)
    }
    return key
  }

  /** Starts a fetch and records it as the one in flight. */
  private startFetch(): Promise<Error | null> {
    const call = this.fetchKeys().then(
      ({ keys, ttlSec }) => {
        // Replace, never merge: a key the issuer has withdrawn must stop
        // verifying tokens as soon as we learn about it.
        this.keys = keys
        this.expiresAt = this.opts.now() + ttlSec * 1000
        this.inflight = null
        return null
      },
      (reason: unknown) => {
        const err = reason instanceof Error ? reason : new Error(String(reason))
        // Keep serving the last good key set, and do not retry before
        // refetchIntervalSec so an outage is not answered with a fetch on
        // every request.
        const retryAt = this.opts.now() + this.opts.refetchIntervalSec * 1000
        if (this.expiresAt < retryAt) {
          this.expiresAt = retryAt
        }
        this.inflight = null
        this.warn(new Error(`jwkit: JWKS refresh from ${this.opts.jwksUrl} failed: ${err.message}`, { cause: err }))
        return err
      },
    )
    this.inflight = call
    return call
  }

  private warn(err: Error): void {
    try {
      this.opts.onWarning?.(err)
    } catch {
      // A throwing hook must not turn into a failed verification for every
      // caller waiting on this fetch.
    }
  }

  /** Downloads and parses the JWKS; returns the keys and how long to cache them. */
  private async fetchKeys(): Promise<{ keys: Map<string, VerificationKey>; ttlSec: number }> {
    const res = await this.opts.fetch(this.opts.jwksUrl, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    })
    if (res.status !== 200) {
      await res.body?.cancel()
      throw new Error(`unexpected HTTP status ${res.status}`)
    }
    const keys = await parseJwks(await readCapped(res, MAX_JWKS_BYTES))

    let ttlSec = this.opts.ttlSec
    const maxAge = cacheControlMaxAge(res.headers.get('cache-control') ?? '')
    if (maxAge !== undefined) {
      // The issuer knows its own rotation schedule better than a default
      // does, within limits: never poll faster than refetchIntervalSec and
      // never trust a key set for more than MAX_CACHE_TTL_SEC.
      ttlSec = Math.min(Math.max(maxAge, this.opts.refetchIntervalSec), MAX_CACHE_TTL_SEC)
    }
    return { keys, ttlSec }
  }
}

/** Reads a response body, failing as soon as it exceeds cap bytes. */
async function readCapped(res: Response, cap: number): Promise<string> {
  if (res.body === null) {
    return ''
  }
  const reader = res.body.getReader() as ReadableStreamDefaultReader<Uint8Array>
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) {
      break
    }
    total += value.byteLength
    if (total > cap) {
      await reader.cancel()
      throw new Error(`response is larger than ${cap} bytes`)
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Extracts max-age, in seconds, from a Cache-Control header value. Returns
 * undefined when the directive is absent or unparsable.
 */
export function cacheControlMaxAge(header: string): number | undefined {
  for (const directive of header.split(',')) {
    const eq = directive.indexOf('=')
    if (eq < 0 || directive.slice(0, eq).trim().toLowerCase() !== 'max-age') {
      continue
    }
    const value = directive
      .slice(eq + 1)
      .trim()
      .replace(/^"+|"+$/g, '')
    if (!/^[0-9]+$/.test(value)) {
      return undefined
    }
    // More than nine digits is decades; clamp without parsing, exactly as
    // the Go implementation does to avoid integer overflow.
    return value.length > 9 ? MAX_CACHE_TTL_SEC : Number(value)
  }
  return undefined
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * Turns a JWKS document into verification keys indexed by kid.
 *
 * Keys jwkit cannot or should not use are skipped rather than failing the
 * whole set, because issuers routinely publish encryption keys and other
 * algorithms next to their signing keys. A document with no usable key at all
 * is an error, so that a broken response never replaces a good cache.
 */
export async function parseJwks(body: string): Promise<Map<string, VerificationKey>> {
  let doc: unknown
  try {
    doc = JSON.parse(body)
  } catch {
    throw new Error('JWKS is not a JSON object')
  }
  if (!isObject(doc)) {
    throw new Error('JWKS is not a JSON object')
  }
  if (!Array.isArray(doc.keys)) {
    throw new Error('JWKS has no "keys" array')
  }
  const keys = new Map<string, VerificationKey>()
  for (const entry of doc.keys as unknown[]) {
    if (!isObject(entry)) {
      continue
    }
    const imported = await importKey(entry)
    // First one wins if the issuer repeats a kid.
    if (imported !== null && !keys.has(imported.kid)) {
      keys.set(imported.kid, imported.key)
    }
  }
  if (keys.size === 0) {
    throw new Error('JWKS contains no usable RS256 or ES256 key')
  }
  return keys
}

/**
 * Converts one JWK into a verification key. Returns null if the key is not an
 * RSA (2048 bits or more) or P-256 signature-verification key with a kid.
 */
async function importKey(f: Record<string, unknown>): Promise<{ kid: string; key: VerificationKey } | null> {
  const kid = f.kid
  if (typeof kid !== 'string' || kid === '') {
    return null
  }
  if (Object.hasOwn(f, 'use') && f.use !== 'sig') {
    return null
  }

  // Copy only the public members into the JWK handed to the library. If an
  // issuer ever published a private key by mistake, its private parameters
  // are never parsed, let alone kept.
  let alg: Alg
  let publicJwk: Record<string, unknown>
  if (f.kty === 'RSA') {
    alg = 'RS256'
    publicJwk = { kty: 'RSA', n: f.n, e: f.e }
    if (rsaModulusBits(f.n) < MIN_RSA_BITS) {
      return null
    }
  } else if (f.kty === 'EC' && f.crv === 'P-256') {
    alg = 'ES256'
    publicJwk = { kty: 'EC', crv: 'P-256', x: f.x, y: f.y }
  } else {
    return null
  }
  // A JWK may pin its own algorithm; respect it by ignoring keys meant for
  // algorithms we do not implement (PS256, RS384, ...).
  if (Object.hasOwn(f, 'alg') && f.alg !== alg) {
    return null
  }

  try {
    // importJWK validates the key material, including that an EC point is
    // on the curve.
    const key = (await importJWK(publicJwk as JWK, alg)) as CryptoKey
    return { kid, key: { alg, key } }
  } catch {
    return null
  }
}

/** Bit length of a base64url-encoded big-endian modulus; 0 if it is not a string. */
function rsaModulusBits(n: unknown): number {
  if (typeof n !== 'string') {
    return 0
  }
  const bytes = Buffer.from(n, 'base64url')
  const first = bytes.findIndex((b) => b !== 0)
  if (first < 0) {
    return 0
  }
  // clz32 counts leading zeros of a 32-bit value; the top byte occupies 8 of them.
  return (bytes.length - first) * 8 - (Math.clz32(bytes.readUInt8(first)) - 24)
}
