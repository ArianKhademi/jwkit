// Test support: signing keys, a token builder, a fake clock and an in-process
// JWKS server. Tokens are signed with node:crypto directly rather than with
// jose, so the tests do not check the library against itself.

import { createHmac, generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

import { afterAll } from 'vitest'

import { JwkitError, Verifier, type ErrorName, type VerifierConfig } from '../src/index.js'

export const ISSUER = 'https://issuer.example'
export const AUDIENCE = 'https://api.example'

/** The instant every test verifies at, unless it moves the clock (seconds). */
export const NOW = 1_750_000_000

/** A key pair the fake issuer can publish and sign with. */
export interface TestKey {
  kid: string
  alg: 'RS256' | 'ES256'
  privateKey: KeyObject
  publicKey: KeyObject
}

function rsaKey(kid: string, bits: number): TestKey {
  return { kid, alg: 'RS256', ...generateKeyPairSync('rsa', { modulusLength: bits }) }
}

function ecKey(kid: string, curve: string): TestKey {
  return { kid, alg: 'ES256', ...generateKeyPairSync('ec', { namedCurve: curve }) }
}

// Generated once per test file; RSA generation is too slow to repeat per test.
export const rsaKey1 = rsaKey('rsa-1', 2048)
export const rsaKey2 = rsaKey('rsa-2', 2048)
export const rsaKey3 = rsaKey('rsa-3', 2048)
export const rsaSmall = rsaKey('rsa-small', 1024)
export const ecKey1 = ecKey('ec-1', 'P-256')
export const ecKey2 = ecKey('ec-2', 'P-256')
export const ecP384 = ecKey('ec-p384', 'P-384')

/** The same key pair published under another kid. */
export function withKid(key: TestKey, kid: string): TestKey {
  return { ...key, kid }
}

export function b64(data: string | Uint8Array): string {
  return Buffer.from(data).toString('base64url')
}

/** The public JWK for the key. */
export function jwk(key: TestKey): Record<string, unknown> {
  const exported = key.publicKey.export({ format: 'jwk' })
  return key.alg === 'RS256'
    ? { ...exported, kid: key.kid, use: 'sig', alg: 'RS256' }
    : { ...exported, kid: key.kid, use: 'sig' }
}

/** Signs the JWS signing input with the key's own algorithm. */
export function signature(key: TestKey, signingInput: string): Buffer {
  return key.alg === 'RS256'
    ? sign('sha256', Buffer.from(signingInput), key.privateKey)
    : sign('sha256', Buffer.from(signingInput), { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
}

/**
 * Builds a token from literal header and payload text, for tests that need
 * JSON the encoder would never produce.
 */
export function signRaw(key: TestKey, header: string | Uint8Array, payload: string | Uint8Array): string {
  const input = `${b64(header)}.${b64(payload)}`
  return `${input}.${b64(signature(key, input))}`
}

type Json = Record<string, unknown>

/** The payload of a token that is valid at NOW. */
export function validClaims(): Json {
  return { iss: ISSUER, aud: AUDIENCE, sub: 'user-1', iat: NOW, exp: NOW + 300 }
}

export type Edit = (header: Json, payload: Json) => void

/** Signs a valid token after letting the edits change its header and payload. */
export function token(key: TestKey, ...edits: Edit[]): string {
  const header: Json = { alg: key.alg, kid: key.kid, typ: 'JWT' }
  const payload = validClaims()
  for (const edit of edits) {
    edit(header, payload)
  }
  return signRaw(key, JSON.stringify(header), JSON.stringify(payload))
}

function setMember(target: Json, name: string, value: unknown): void {
  if (value === undefined) {
    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
    delete target[name]
  } else {
    target[name] = value
  }
}

/** Edits for token(). Passing undefined deletes the member. */
export function setClaim(name: string, value: unknown): Edit {
  return (_h, p) => {
    setMember(p, name, value)
  }
}

export function setHeader(name: string, value: unknown): Edit {
  return (h) => {
    setMember(h, name, value)
  }
}

/** An "alg: none" token: valid claims, empty signature. */
export function unsigned(header: Json): string {
  return `${b64(JSON.stringify(header))}.${b64(JSON.stringify(validClaims()))}.`
}

/**
 * Mounts the classic algorithm-confusion attack: an HS256 token whose HMAC
 * secret is the issuer's RSA public key in PEM form, which the attacker knows
 * because it is public.
 */
export function hs256WithPublicKey(key: TestKey): string {
  const secret = key.publicKey.export({ type: 'spki', format: 'pem' })
  const input = `${b64(JSON.stringify({ alg: 'HS256', kid: key.kid, typ: 'JWT' }))}.${b64(JSON.stringify(validClaims()))}`
  return `${input}.${b64(createHmac('sha256', secret).update(input).digest())}`
}

export function splitToken(tok: string): [string, string, string] {
  const parts = tok.split('.')
  if (parts.length !== 3) {
    throw new Error(`test token has ${parts.length} segments`)
  }
  return parts as [string, string, string]
}

/** A manually advanced clock, in the shape VerifierConfig.now expects. */
export class FakeClock {
  private ms = NOW * 1000
  readonly now = (): number => this.ms
  /** Seconds since the epoch. */
  get seconds(): number {
    return Math.floor(this.ms / 1000)
  }
  advance(seconds: number): void {
    this.ms += seconds * 1000
  }
}

/**
 * An in-process JWKS endpoint whose key set, status code and caching headers
 * can be changed mid-test, and which counts requests.
 */
export class FakeIssuer {
  body = ''
  status = 200
  cacheControl = ''
  hits = 0
  /** If set, requests wait for it before answering. */
  private hold: Promise<void> | null = null
  private readonly server: Server

  private constructor(server: Server) {
    this.server = server
  }

  static async start(...keys: TestKey[]): Promise<FakeIssuer> {
    const server = createServer((_req, res) => {
      issuer.hits++
      const { body, status, cacheControl, hold } = issuer
      void (hold ?? Promise.resolve()).then(() => {
        if (cacheControl !== '') {
          res.setHeader('Cache-Control', cacheControl)
        }
        res.setHeader('Content-Type', 'application/json')
        res.writeHead(status)
        res.end(body)
      })
    })
    const issuer = new FakeIssuer(server)
    issuer.publish(...keys)
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    afterAll(() => issuer.close())
    return issuer
  }

  get url(): string {
    const { port } = this.server.address() as AddressInfo
    return `http://127.0.0.1:${port}/.well-known/jwks.json`
  }

  /** Replaces the key set the endpoint serves, as a rotation would. */
  publish(...keys: TestKey[]): void {
    this.body = JSON.stringify({ keys: keys.map(jwk) })
  }

  /** Makes every request wait until the returned function is called. */
  holdRequests(): () => void {
    let release!: () => void
    this.hold = new Promise<void>((resolve) => {
      release = resolve
    })
    return () => {
      this.hold = null
      release()
    }
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      this.server.closeAllConnections()
      this.server.close(() => {
        resolve()
      })
    })
  }
}

/** A verifier pointed at the fake issuer and clock. */
export function newVerifier(issuer: FakeIssuer, clock: FakeClock, overrides: Partial<VerifierConfig> = {}): Verifier {
  return new Verifier({ issuer: ISSUER, audience: AUDIENCE, jwksUrl: issuer.url, now: clock.now, ...overrides })
}

/** Resolves to "ok" or the name of the JwkitError; anything else fails the test. */
export async function result(verifier: Verifier, tok: unknown): Promise<ErrorName | 'ok'> {
  try {
    await verifier.verify(tok)
    return 'ok'
  } catch (err) {
    if (!(err instanceof JwkitError)) {
      throw new Error(`verify threw something that is not a JwkitError: ${String(err)}`, { cause: err })
    }
    return err.code
  }
}

/** Polls until cond holds, failing after a generous deadline. */
export async function waitFor(cond: () => boolean): Promise<void> {
  const deadline = Date.now() + 5000
  while (!cond()) {
    if (Date.now() > deadline) {
      throw new Error('condition not reached in time')
    }
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
}
