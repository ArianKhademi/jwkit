import type { Request, RequestHandler, Response } from 'express'

import { ErrInsufficientScope, ErrMissingToken, errorName, JwkitError } from './errors.js'
import { claimStrings, scopes, type Claims, type Verifier } from './verifier.js'

declare global {
  // Express exposes Request for augmentation only through this namespace.
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** The claims jwkitExpress verified for this request. */
      auth?: Claims
    }
  }
}

/** Finds the token on a request. Returns undefined or "" when the request carries none. */
export type TokenExtractor = (req: Request) => string | undefined

/**
 * Customises jwkitExpress. With no options every route is protected and the
 * token is read from the Authorization header.
 */
export interface MiddlewareOptions {
  /** All must be present in the token's scope or scp claim. */
  requiredScopes?: string[]
  /** All must be present in the claim named by rolesClaim. */
  requiredRoles?: string[]
  /** The claim that lists roles, as a JSON array or a space-delimited string. Default "roles". */
  rolesClaim?: string
  /** Overrides where the token is read from. Default bearerToken. */
  tokenExtractor?: TokenExtractor
  /**
   * Request paths that bypass authentication entirely. An entry matches the
   * path exactly, or as a prefix if it ends in "*" ("/public/*"). Paths are
   * matched against the full request path, not the path relative to where
   * the middleware is mounted.
   */
  skipPaths?: string[]
}

/**
 * Extracts the token from "Authorization: Bearer <token>". The scheme is
 * matched case-insensitively, as RFC 9110 requires.
 */
export function bearerToken(req: Request): string | undefined {
  const header = req.headers.authorization ?? ''
  const space = header.indexOf(' ')
  if (space < 0 || header.slice(0, space).toLowerCase() !== 'bearer') {
    return undefined
  }
  return header.slice(space + 1).replace(/^ +| +$/g, '')
}

/**
 * Returns an extractor that reads the token from the named cookie. It parses
 * the Cookie header itself, so no cookie-parsing middleware is needed.
 */
export function cookieToken(name: string): TokenExtractor {
  return (req) => {
    for (const pair of (req.headers.cookie ?? '').split(';')) {
      const eq = pair.indexOf('=')
      if (eq >= 0 && pair.slice(0, eq).trim() === name) {
        return pair
          .slice(eq + 1)
          .trim()
          .replace(/^"|"$/g, '')
      }
    }
    return undefined
  }
}

/**
 * Returns an extractor that reads the token from the named header, verbatim
 * (for gateways that forward it as, say, X-Auth-Token).
 */
export function headerToken(name: string): TokenExtractor {
  return (req) => req.get(name)
}

/**
 * Returns Express middleware that authenticates requests with verifier.
 *
 * On success the verified claims are stored on `req.auth` and the next
 * handler runs. On failure the response is a JSON body
 * `{"error": "<error name>"}` and:
 *
 *  - 401 and a `WWW-Authenticate: Bearer` challenge for a missing or invalid token
 *  - 403 when the token is valid but lacks a required scope or role
 *  - 503 when the issuer's keys cannot be fetched, since that is not the
 *    client's fault and the same token may succeed on retry
 */
export function jwkitExpress(verifier: Verifier, opts: MiddlewareOptions = {}): RequestHandler {
  const extract = opts.tokenExtractor ?? bearerToken
  const rolesClaim = opts.rolesClaim ?? 'roles'
  const requiredScopes = opts.requiredScopes ?? []
  const requiredRoles = opts.requiredRoles ?? []
  const skipPaths = opts.skipPaths ?? []

  return (req, res, next) => {
    if (skipped(skipPaths, requestPath(req))) {
      next()
      return
    }
    const token = extract(req)
    if (token === undefined || token === '') {
      reject(res, new ErrMissingToken(), requiredScopes)
      return
    }
    verifier.verify(token).then(
      (claims) => {
        if (!containsAll(scopes(claims), requiredScopes) || !containsAll(claimStrings(claims, rolesClaim), requiredRoles)) {
          reject(res, new ErrInsufficientScope(), requiredScopes)
          return
        }
        req.auth = claims
        next()
      },
      (err: unknown) => {
        if (err instanceof JwkitError) {
          reject(res, err, requiredScopes)
        } else {
          // Not a verification outcome: let the application's error handler see it.
          next(err)
        }
      },
    )
  }
}

/** The full request path, without the query string, wherever the middleware is mounted. */
function requestPath(req: Request): string {
  const url = req.originalUrl
  const query = url.indexOf('?')
  return query < 0 ? url : url.slice(0, query)
}

function skipped(patterns: string[], path: string): boolean {
  return patterns.some((p) => (p.endsWith('*') ? path.startsWith(p.slice(0, -1)) : p === path))
}

function containsAll(have: string[], want: string[]): boolean {
  return want.every((w) => have.includes(w))
}

/**
 * Sends the status, challenge and body for err. Only the error's stable name
 * is sent to the client; the detail may describe the token or the key set and
 * stays in the server's hands.
 */
function reject(res: Response, err: JwkitError, requiredScopes: string[]): void {
  const name = errorName(err)
  let status = 401
  // Challenge formats follow RFC 6750 section 3.
  let challenge = `Bearer error="invalid_token", error_description="${name}"`
  if (name === 'ErrMissingToken') {
    // No credentials at all: RFC 6750 says to send no error code.
    challenge = 'Bearer'
  } else if (name === 'ErrInsufficientScope') {
    status = 403
    challenge = `Bearer error="insufficient_scope", error_description="${name}"`
    if (requiredScopes.length > 0) {
      challenge += `, scope="${requiredScopes.join(' ')}"`
    }
  } else if (name === 'ErrJWKSUnavailable') {
    status = 503
    challenge = ''
  }
  if (challenge !== '') {
    res.set('WWW-Authenticate', challenge)
  }
  res.status(status).json({ error: name })
}
